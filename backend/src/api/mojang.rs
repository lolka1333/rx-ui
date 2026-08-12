//! Minecraft profile lookup for the XMC finalmask.
//!
//! XMC presents a real account during its fake login, and the profile it
//! presents carries Mojang's signature over the skin data. Nothing verifies
//! that signature for the tunnel to work — but nothing stops an observer from
//! verifying it either, and an invented profile is exactly the anomaly the
//! mask exists to avoid. So the values have to come from Mojang.
//!
//! Two calls, both public and unauthenticated:
//!   * `api.mojang.com/users/profiles/minecraft/{name}` → the account UUID;
//!   * `sessionserver.mojang.com/session/minecraft/profile/{uuid}?unsigned=false`
//!     → the properties, including the signed `textures` blob.
//!
//! This is the panel's only outbound call to a third party, and it is made on
//! the operator's explicit action (pressing the button in the XMC form), never
//! in the background. It leaks the fact that this address looked up a username
//! — worth knowing before using it from the server itself.

use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
};
use axum::{Json, Router, extract::Query, routing::get};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub fn routes() -> Router<AppState> {
    Router::new().route("/profile", get(profile))
}

#[derive(Debug, Deserialize)]
pub struct ProfileQuery {
    pub username: String,
}

/// Exactly the four fields an `XmcProfile` needs, ready to drop into the form.
#[derive(Debug, Serialize)]
pub struct ResolvedProfile {
    /// Mojang's spelling, which may differ in case from what was typed.
    pub username: String,
    pub uuid: String,
    pub textures_value: String,
    pub textures_signature: String,
}

#[derive(Deserialize)]
struct MojangAccount {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct SessionProfile {
    name: String,
    properties: Vec<SessionProperty>,
}

#[derive(Deserialize)]
struct SessionProperty {
    name: String,
    value: String,
    #[serde(default)]
    signature: Option<String>,
}

async fn profile(
    _user: AuthUser,
    Query(q): Query<ProfileQuery>,
) -> AppResult<Json<ResolvedProfile>> {
    let username = q.username.trim();
    // Same shape xray enforces later; catching it here saves a pointless
    // round trip to Mojang for something that could never be accepted.
    if !(3..=16).contains(&username.len())
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(AppError::BadRequest(
            "Minecraft username must be 3-16 characters of A-Z, a-z, 0-9 or _".to_owned(),
        ));
    }

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("build http client: {e}")))?;

    let account: MojangAccount = {
        let url = format!("https://api.mojang.com/users/profiles/minecraft/{username}");
        let resp = http.get(&url).send().await.map_err(|e| {
            AppError::BadRequest(format!(
                "could not reach Mojang to resolve the username: {e}"
            ))
        })?;
        // 404 / 204 is Mojang's "no such account" — a user error, not a fault.
        if resp.status() == reqwest::StatusCode::NOT_FOUND
            || resp.status() == reqwest::StatusCode::NO_CONTENT
        {
            return Err(AppError::BadRequest(format!(
                "no Minecraft account named '{username}'"
            )));
        }
        if !resp.status().is_success() {
            return Err(AppError::BadRequest(format!(
                "Mojang answered {} while resolving the username",
                resp.status()
            )));
        }
        resp.json().await.map_err(|e| {
            AppError::Internal(anyhow::anyhow!("unexpected answer from Mojang: {e}"))
        })?
    };

    let profile: SessionProfile = {
        // `unsigned=false` is what makes the response carry `signature`
        // alongside the textures; without it the blob is unsigned and the
        // disguise is only skin-deep.
        let url = format!(
            "https://sessionserver.mojang.com/session/minecraft/profile/{}?unsigned=false",
            account.id
        );
        let resp = http.get(&url).send().await.map_err(|e| {
            AppError::BadRequest(format!("could not reach Mojang for the profile: {e}"))
        })?;
        if !resp.status().is_success() {
            return Err(AppError::BadRequest(format!(
                "Mojang answered {} while fetching the profile",
                resp.status()
            )));
        }
        resp.json().await.map_err(|e| {
            AppError::Internal(anyhow::anyhow!("unexpected profile from Mojang: {e}"))
        })?
    };

    let textures = profile
        .properties
        .into_iter()
        .find(|p| p.name == "textures")
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "'{}' has no textures property to copy",
                profile.name
            ))
        })?;
    let signature = textures
        .signature
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::BadRequest(
                "Mojang returned the textures unsigned — the profile cannot be used".to_owned(),
            )
        })?;

    Ok(Json(ResolvedProfile {
        username: account.name,
        uuid: hyphenate(&account.id)?,
        textures_value: textures.value,
        textures_signature: signature,
    }))
}

/// Mojang returns the UUID unhyphenated; xray's conf parser wants the
/// canonical form.
fn hyphenate(compact: &str) -> AppResult<String> {
    if compact.len() != 32 || !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::Internal(anyhow::anyhow!(
            "Mojang returned a UUID that isn't 32 hex digits: {compact}"
        )));
    }
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &compact[0..8],
        &compact[8..12],
        &compact[12..16],
        &compact[16..20],
        &compact[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyphenates_a_compact_uuid() {
        assert_eq!(
            hyphenate("069a79f444e94726a5befca90e38aaf5").unwrap(),
            "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        );
    }

    #[test]
    fn rejects_a_uuid_that_is_not_hex() {
        assert!(hyphenate("069a79f444e94726a5befca90e38aazz").is_err());
        assert!(hyphenate("tooshort").is_err());
    }
}
