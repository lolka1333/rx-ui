use crate::{
    error::{AppError, AppResult},
    models::Claims,
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    extract::{FromRequestParts, State},
    http::request::Parts,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};

#[derive(Clone)]
pub struct JwtKeys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl JwtKeys {
    pub fn from_secret(secret: &str) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
        }
    }
}

pub fn hash_password(plain: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("argon2 hash: {e}")))
}

pub fn verify_password(plain: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok()
}

/// 24-hour TTL — short enough that a stolen token expires on its own within
/// a day, long enough to avoid forcing a re-login mid-session. For "revoke
/// right now" (after password change, logout-everywhere, etc.) bump
/// `users.token_version`; the extractor compares it on every request.
const JWT_TTL_HOURS: i64 = 24;

pub fn create_token(
    keys: &JwtKeys,
    user_id: &str,
    username: &str,
    is_admin: bool,
    token_version: i64,
) -> AppResult<String> {
    let now = Utc::now();
    let exp = now + Duration::hours(JWT_TTL_HOURS);
    // i64 → u64 fails only when the timestamp is negative (system clock
    // pre-1970 — practically impossible on a real deployment). Bail loudly
    // instead of silently issuing exp=0 / iat=0; either would make the
    // token instantly read as expired against the current wall clock.
    let iat = u64::try_from(now.timestamp())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("system clock is before unix epoch")))?;
    let exp_ts = u64::try_from(exp.timestamp()).map_err(|_| {
        AppError::Internal(anyhow::anyhow!("token expiry timestamp out of u64 range"))
    })?;
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        is_admin,
        tv: token_version,
        exp: exp_ts,
        iat,
    };
    let token = encode(&Header::default(), &claims, &keys.encoding)?;
    Ok(token)
}

/// Axum extractor — pulls `Authorization: Bearer <token>` and decodes.
pub struct AuthUser(pub Claims);

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    crate::AppState: axum::extract::FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let State(app_state) = State::<crate::AppState>::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Internal(anyhow::anyhow!("missing app state")))?;

        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;

        let data = decode::<Claims>(token, &app_state.jwt.decoding, &Validation::default())
            .map_err(|_| AppError::Unauthorized)?;

        // Revocation check: compare the token's `tv` against the live DB
        // value. If they don't match (or the user no longer exists) the
        // token is rejected — this is what makes "log out everywhere" /
        // "force-rotate after password change" work without an in-memory
        // blocklist. One small DB read per request, which is cheap given
        // sqlite + the WAL cache.
        let current_tv: Option<i64> = sqlx::query_scalar!(
            "SELECT token_version FROM users WHERE id = ?",
            data.claims.sub
        )
        .fetch_optional(&app_state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("token_version lookup: {e}")))?;
        match current_tv {
            Some(tv) if tv == data.claims.tv => Ok(Self(data.claims)),
            _ => Err(AppError::Unauthorized),
        }
    }
}
