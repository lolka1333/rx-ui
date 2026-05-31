use crate::{
    AppState,
    auth::{AuthUser, create_token, hash_password, verify_password},
    error::{AppError, AppResult},
    models::{ChangeCredentialsRequest, LoginRequest, LoginResponse, UserView},
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use std::sync::OnceLock;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/credentials", post(change_credentials))
}

/// Pre-computed argon2 hash of an unrelated random string. Used as a stand-in
/// when the requested username doesn't exist, so the login handler still
/// spends roughly the same wall-clock time running argon2 either way. Without
/// this, the missing-user branch returns ~instantly while the existing-user
/// branch takes ~100ms — a trivially observable enumeration oracle.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        hash_password("timing-equalizer-not-a-real-password")
            .expect("argon2 hashes a constant string at startup")
    })
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    let row = sqlx::query!(
        "SELECT id, username, password_hash, is_admin, token_version FROM users WHERE username = ?",
        req.username
    )
    .fetch_optional(&state.db)
    .await?;

    // Always run argon2::verify_password — against the real hash if the user
    // exists, otherwise against a constant dummy hash. This equalises the
    // response time so an attacker can't distinguish "no such user" from
    // "wrong password" by wall-clock observation.
    let hash = row
        .as_ref()
        .map_or_else(|| dummy_hash(), |r| r.password_hash.as_str());
    let password_ok = verify_password(&req.password, hash);

    let Some(row) = row.filter(|_| password_ok) else {
        return Err(AppError::Unauthorized);
    };

    let is_admin = row.is_admin != 0;
    let token = create_token(
        &state.jwt,
        &row.id,
        &row.username,
        is_admin,
        row.token_version,
    )?;

    Ok(Json(LoginResponse {
        token,
        user: UserView {
            id: row.id,
            username: row.username,
            is_admin,
        },
    }))
}

/// Change the calling user's username and/or password.
///
/// Even with a valid bearer token we re-check `current_password` — a
/// session token can outlive the operator's awareness of it (a shared
/// browser left logged in, a leaked storage dump), so a credential
/// change must be gated on knowledge of the *current* password, not
/// just on possession of the token.
///
/// On success we bump `users.token_version`, which the auth extractor
/// compares on every request — that invalidates the just-used token
/// (and any other live sessions for this user) and forces a re-login
/// with the new credentials. The handler returns 204 with no body;
/// the frontend wipes its stored token and routes the user back to
/// the login screen.
async fn change_credentials(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<ChangeCredentialsRequest>,
) -> AppResult<StatusCode> {
    let new_username = req
        .new_username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let new_password = req.new_password.as_deref().filter(|s| !s.is_empty());
    if new_username.is_none() && new_password.is_none() {
        return Err(AppError::BadRequest(
            "must change at least one of: new_username, new_password".to_owned(),
        ));
    }

    // Fetch the live hash — the JWT only carries the user id, not the
    // password, so we round-trip to the DB on every credential change.
    let user_id = &user.0.sub;
    let row = sqlx::query!("SELECT password_hash FROM users WHERE id = ?", user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !verify_password(&req.current_password, &row.password_hash) {
        // 401 (not 400) — distinguishes "wrong current password" from
        // "malformed request body" so the UI can show a focused error
        // on the password field instead of a generic banner.
        return Err(AppError::Unauthorized);
    }

    // Build the updates. We do them in one transaction so a successful
    // username change can't accidentally leave a stale token version if
    // the second statement fails — either both land or neither does.
    let mut tx = state.db.begin().await?;
    if let Some(uname) = new_username {
        sqlx::query!("UPDATE users SET username = ? WHERE id = ?", uname, user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(d) if d.is_unique_violation() => {
                    AppError::Conflict(format!("username '{uname}' is already taken"))
                }
                e => e.into(),
            })?;
    }
    if let Some(pw) = new_password {
        let hash = hash_password(pw)?;
        sqlx::query!(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            hash,
            user_id
        )
        .execute(&mut *tx)
        .await?;
    }
    // Always bump token_version on success: the credential surface
    // just changed, so any token issued before this point should stop
    // working — including the one in the current request.
    sqlx::query!(
        "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
        user_id
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}
