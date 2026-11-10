//! Server-managed key material: the Reality x25519 pair, the VLESS Encryption
//! pair and the `WireGuard` device pair. One rule on every path — a blank
//! private key means "unchanged", and any key that arrives has its public half
//! re-derived from it, so a stored pair always matches. Create completes what
//! the body left out; the rotate endpoints mint fresh ones.

use super::{
    reapply_inbound_to_xray,
    store::{read_row, row_to_inbound},
};
use crate::{
    AppState,
    auth::AuthUser,
    error::{AppError, AppResult},
    models::Inbound,
    protocols::{
        ProtocolConfig,
        vless::{VlessEncryptionAuth, VlessEncryptionMode, VlessXorMode},
    },
    security::SecurityConfig,
    xray::keygen,
};
use axum::{
    Json,
    extract::{Path, State},
};

/// Server-side completion of operator-supplied layers. Most of the time
/// the operator sends a structurally complete payload; these key fields are
/// finalised here so the stored material is always self-consistent:
///   * Reality x25519 keypair — the public half is re-derived from the
///     (body-carried) private the frontend sent, or a fresh pair is
///     generated if none was supplied. The public always matches the
///     private, so a hand-crafted request can't paste a mismatched pair.
///   * VLESS Encryption keypair — calling `xray vlessenc` for the
///     chosen auth (X25519 vs ML-KEM-768). Skipped when mode=None.
///
/// Mutates the typed configs in place so the resulting JSON blobs
/// carry the completed values. Returns Err if the keygen subprocess
/// fails (the operator sees the underlying message).
pub(super) async fn complete_server_managed_fields(
    state: &AppState,
    protocol: &mut ProtocolConfig,
    security: &mut SecurityConfig,
) -> AppResult<()> {
    if let SecurityConfig::Reality(r) = security {
        // Reality x25519 keypair. The frontend pre-generates one (body-carried,
        // like VLESS Encryption) so the operator sees the public key right on
        // the create form; keep that private half but always re-derive the
        // public from it, so a hand-crafted request can't ship a mismatched
        // pair. With no private supplied (older API clients), generate fresh.
        if r.private_key.is_empty() {
            let kp = keygen::generate_reality_keypair();
            r.private_key = kp.private_key;
            r.public_key = kp.public_key;
        } else {
            r.public_key = keygen::derive_reality_public_key(&r.private_key)
                .map_err(|e| AppError::BadRequest(format!("reality private_key: {e}")))?;
        }
        if r.short_ids.is_empty() {
            r.short_ids = vec![keygen::generate_short_id()];
        }
        if r.fingerprint.is_empty() {
            "chrome".clone_into(&mut r.fingerprint);
        }
    }

    // WireGuard's device keypair, the same rule as Reality's: keep whatever
    // private half arrived, always re-derive the public one from it so a
    // hand-crafted request cannot ship a mismatched pair — every client config
    // this inbound hands out carries that public key, and a wrong one is a
    // tunnel that completes no handshake and says nothing about why.
    if let ProtocolConfig::Wireguard(wg) = &mut *protocol {
        crate::protocols::wireguard::parse_subnet(&wg.subnet)
            .map_err(|e| AppError::BadRequest(format!("wireguard subnet: {e}")))?;
        if wg.secret_key.trim().is_empty() {
            let kp = keygen::generate_wireguard_keypair();
            wg.secret_key = kp.private_key;
            wg.public_key = kp.public_key;
        } else {
            wg.public_key = keygen::derive_wireguard_public_key(&wg.secret_key)
                .map_err(|e| AppError::BadRequest(format!("wireguard private key: {e}")))?;
        }
        return Ok(());
    }

    // VLESS-specific encryption key derivation. Hysteria 2 carries no
    // protocol-level encryption (everything is on the QUIC/TLS layer),
    // so the whole block is skipped for non-VLESS protocols.
    let ProtocolConfig::Vless(v) = protocol else {
        return Ok(());
    };
    if v.encryption_mode == VlessEncryptionMode::Mlkem768x25519Plus {
        let auth = v.encryption_auth.unwrap_or(VlessEncryptionAuth::Mlkem768);
        v.encryption_auth = Some(auth);
        v.encryption_xor_mode
            .get_or_insert_with(VlessXorMode::default);
        v.encryption_seconds_from.get_or_insert(600);
        // Respect frontend-provided keys (pre-generated through
        // `POST /api/keygen/vless-encryption` so the operator can see
        // them in the form before saving). Only fall back to a server-
        // side `xray vlessenc` call when the frontend didn't supply
        // anything — keeps backward compat with API clients that don't
        // know about the standalone keygen endpoint.
        let need_gen = v
            .encryption_server_key
            .as_ref()
            .is_none_or(String::is_empty)
            || v.encryption_client_key
                .as_ref()
                .is_none_or(String::is_empty);
        if need_gen {
            let kp = keygen::generate_vless_encryption_keypair(&state.xray.binary, auth)
                .await
                .map_err(AppError::Internal)?;
            v.encryption_server_key = Some(kp.server_key);
            v.encryption_client_key = Some(kp.client_key);
        }
    }

    Ok(())
}

/// Settle a `WireGuard` inbound's device keypair for an update, doing for this
/// path what `complete_server_managed_fields` does on create — which never runs
/// here.
///
/// Two cases, and both matter because the public half is what every client
/// config already handed out names as the server:
///   * blank incoming `secret_key` → keep the stored pair. Covers the API
///     caller who patches one field of the protocol block, and any future UI
///     that stops showing the key. Wiping it would leave the inbound
///     unbuildable, the same trap Reality's keypair has below.
///   * a real incoming key → an intentional rotation, and the public half is
///     RE-DERIVED from it. The form's public-key field is read-only, so a
///     pasted private key arrives next to the previous public one; storing that
///     pair would build a device on the new key while telling every client to
///     expect the old one — a tunnel whose handshake fails with nothing said
///     anywhere. The same derivation refuses a key that is not a key.
pub(super) fn settle_wireguard_keys(
    incoming: &ProtocolConfig,
    stored: &ProtocolConfig,
) -> AppResult<ProtocolConfig> {
    let ProtocolConfig::Wireguard(new) = incoming else {
        return Ok(incoming.clone());
    };
    let stored_key = match stored {
        ProtocolConfig::Wireguard(old) => old.secret_key.trim(),
        _ => "",
    };
    let mut merged = new.clone();
    if merged.secret_key.trim().is_empty() {
        if stored_key.is_empty() {
            // Nothing on either side: this is an inbound BECOMING WireGuard.
            // Generate the device pair here, the way `create` does — the form
            // only pre-fills one when its WireGuard tab is actually opened, and
            // the operator who just flips the protocol select would otherwise
            // store an inbound that can never be enabled (a blank key fails
            // every later build) with nothing on screen to say so.
            merged.secret_key = keygen::generate_wireguard_keypair().private_key;
        } else {
            stored_key.clone_into(&mut merged.secret_key);
        }
    }
    merged.public_key = keygen::derive_wireguard_public_key(&merged.secret_key)
        .map_err(|e| AppError::BadRequest(format!("wireguard private key: {e}")))?;
    Ok(ProtocolConfig::Wireguard(merged))
}

/// DB half of [`settle_wireguard_keys`]: reads the stored protocol only for a
/// `WireGuard` body, which is the only one that has a keypair to settle.
pub(super) async fn settle_wireguard_keys_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
    incoming: &ProtocolConfig,
) -> AppResult<ProtocolConfig> {
    if !matches!(incoming, ProtocolConfig::Wireguard(_)) {
        return Ok(incoming.clone());
    }
    let stored = sqlx::query!("SELECT protocol_config FROM inbounds WHERE id = ?", id)
        .fetch_optional(&mut **tx)
        .await?
        .and_then(|row| serde_json::from_str::<ProtocolConfig>(&row.protocol_config).ok());
    settle_wireguard_keys(incoming, stored.as_ref().unwrap_or(incoming))
}

/// Pure Reality keypair-preserve merge (no DB). Returns `incoming` unchanged
/// unless it is Reality with a blank `private_key` layered over a `stored`
/// Reality keypair, in which case the stored private/public keypair is lifted
/// across. Shared by `preserve_reality_keypair_tx` (write path, reads the
/// stored config inside the tx) and the `update` pre-commit validation (which
/// merges against the already re-read `before.security`) so both build the
/// exact same security.
pub(super) fn preserve_reality_keypair(
    incoming: &SecurityConfig,
    stored: &SecurityConfig,
) -> SecurityConfig {
    let (SecurityConfig::Reality(new), SecurityConfig::Reality(old)) = (incoming, stored) else {
        return incoming.clone();
    };
    if !new.private_key.is_empty() || old.private_key.is_empty() {
        return incoming.clone();
    }
    let mut merged = new.clone();
    merged.private_key.clone_from(&old.private_key);
    merged.public_key.clone_from(&old.public_key);
    SecurityConfig::Reality(merged)
}

/// Preserve the server-managed Reality x25519 keypair across an inbound
/// update. The frontend can't read the private key, so it always submits
/// it (and the derived public key) blank; without this, editing any other
/// field of a Reality inbound overwrites the stored keypair with empty
/// strings and breaks the inbound. Returns the incoming security unchanged
/// for every case except "Reality with a blank private key layered over a
/// stored Reality keypair", where it lifts the existing keypair across.
pub(super) async fn preserve_reality_keypair_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
    incoming: &SecurityConfig,
) -> AppResult<SecurityConfig> {
    // Fast path: only a Reality PATCH with a blank private key needs the DB read.
    let SecurityConfig::Reality(new) = incoming else {
        return Ok(incoming.clone());
    };
    if !new.private_key.is_empty() {
        return Ok(incoming.clone());
    }
    let Some(row) = sqlx::query!("SELECT security_config FROM inbounds WHERE id = ?", id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(incoming.clone());
    };
    let Ok(stored) = serde_json::from_str::<SecurityConfig>(&row.security_config) else {
        return Ok(incoming.clone());
    };
    Ok(preserve_reality_keypair(incoming, &stored))
}

/// Generate a fresh Reality x25519 keypair for this inbound. Only legal
/// when the inbound's security layer is Reality; for anything else the
/// call returns 400. After the rotation every previously-issued share
/// link is invalid (the `pbk=` baked into the URL no longer matches the
/// server), so the UI surfaces a confirm dialog.
pub(super) async fn rotate_reality_keypair(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Inbound>> {
    let mut inbound = row_to_inbound(read_row(&state, &id).await?)?;
    let SecurityConfig::Reality(ref mut reality) = inbound.security else {
        return Err(AppError::BadRequest(
            "inbound is not configured for Reality — nothing to rotate".to_owned(),
        ));
    };

    let kp = keygen::generate_reality_keypair();
    reality.private_key = kp.private_key;
    reality.public_key = kp.public_key;

    let j = serde_json::to_string(&inbound.security)?;
    sqlx::query!(
        "UPDATE inbounds SET security_config = ?, updated_at = datetime('now') WHERE id = ?",
        j,
        id
    )
    .execute(&state.db)
    .await?;

    let after = row_to_inbound(read_row(&state, &id).await?)?;
    if after.enabled {
        reapply_inbound_to_xray(&state, &after, "reality key rotated").await?;
    }

    Ok(Json(after))
}

/// Generate a fresh VLESS-encryption keypair. Auth defaults to ML-KEM-
/// 768 when the inbound isn't yet configured for PQ; calling this
/// endpoint also flips mode to `mlkem768x25519plus` if it was None
/// (operator's signal that they want it enabled). Same share-link
/// invalidation caveat as `rotate_reality_keypair`.
pub(super) async fn regenerate_vless_encryption_keypair(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Inbound>> {
    let mut inbound = row_to_inbound(read_row(&state, &id).await?)?;
    // This endpoint is VLESS-specific (regenerates VLESS-encryption keys).
    // For non-VLESS inbounds reject with a clear 4xx rather than panic.
    let ProtocolConfig::Vless(ref mut vless) = inbound.protocol else {
        return Err(AppError::BadRequest(
            "this endpoint only applies to VLESS inbounds".to_owned(),
        ));
    };

    let auth = vless
        .encryption_auth
        .unwrap_or(VlessEncryptionAuth::Mlkem768);
    let kp = keygen::generate_vless_encryption_keypair(&state.xray.binary, auth)
        .await
        .map_err(AppError::Internal)?;

    vless.encryption_mode = VlessEncryptionMode::Mlkem768x25519Plus;
    vless.encryption_auth = Some(auth);
    vless
        .encryption_xor_mode
        .get_or_insert_with(VlessXorMode::default);
    vless.encryption_seconds_from.get_or_insert(600);
    vless.encryption_server_key = Some(kp.server_key);
    vless.encryption_client_key = Some(kp.client_key);

    let j = serde_json::to_string(&inbound.protocol)?;
    sqlx::query!(
        "UPDATE inbounds SET protocol_config = ?, updated_at = datetime('now') WHERE id = ?",
        j,
        id
    )
    .execute(&state.db)
    .await?;

    let after = row_to_inbound(read_row(&state, &id).await?)?;
    if after.enabled {
        reapply_inbound_to_xray(&state, &after, "vless-encryption regenerated").await?;
    }
    Ok(Json(after))
}

#[cfg(test)]
mod tests {
    //! The carry-forward rules the update path relies on: a blank key keeps the
    //! stored pair, a real one gets its own public half, a protocol switch
    //! mints one.
    use super::*;
    use crate::protocols::vless::VlessProtocol;
    use crate::protocols::wireguard::WireguardProtocol;
    use crate::security::NoneSecurity;
    use crate::security::reality::RealitySecurity;

    /// A PATCH that leaves the device key blank means "unchanged", the way a
    /// Reality PATCH does — wiping it would leave every client config naming a
    /// public key the server no longer holds.
    #[test]
    fn a_blank_wireguard_key_keeps_the_stored_pair() {
        let stored = ProtocolConfig::Wireguard(WireguardProtocol {
            secret_key: "gI6EdUSYvn8ugXOt8QQD6Yc+JyiZxIhp3GInSWRfWGE=".to_owned(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_owned(),
            ..WireguardProtocol::default()
        });
        let incoming = ProtocolConfig::Wireguard(WireguardProtocol {
            subnet: "10.9.0.0/24".to_owned(),
            ..WireguardProtocol::default()
        });
        let ProtocolConfig::Wireguard(merged) = settle_wireguard_keys(&incoming, &stored).unwrap()
        else {
            panic!("merge changed the protocol");
        };
        assert_eq!(
            merged.secret_key,
            "gI6EdUSYvn8ugXOt8QQD6Yc+JyiZxIhp3GInSWRfWGE="
        );
        // Derived, not copied: a pair stored crooked by an older path is
        // straightened the next time the inbound is saved.
        assert_eq!(
            merged.public_key,
            keygen::derive_wireguard_public_key("gI6EdUSYvn8ugXOt8QQD6Yc+JyiZxIhp3GInSWRfWGE=")
                .unwrap()
        );
        // The rest of the PATCH still lands.
        assert_eq!(merged.subnet, "10.9.0.0/24");
    }

    /// A key the operator actually typed is a rotation, and the public half has
    /// to be re-derived from it. The form's public-key field is read-only, so a
    /// pasted private key arrives beside the PREVIOUS public one — storing that
    /// pair would run the device on the new key while every client config still
    /// names the old one, and the handshake would fail with nothing logged.
    #[test]
    fn an_explicit_wireguard_key_is_paired_with_its_own_public_half() {
        let stored = ProtocolConfig::Wireguard(WireguardProtocol {
            secret_key: "gI6EdUSYvn8ugXOt8QQD6Yc+JyiZxIhp3GInSWRfWGE=".to_owned(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_owned(),
            ..WireguardProtocol::default()
        });
        let rotated = "yPz3Yq0mQ5tHhP2xLZ9nR4cVwK7sJd8bFgN6uT1aX0E=";
        let incoming = ProtocolConfig::Wireguard(WireguardProtocol {
            secret_key: rotated.to_owned(),
            // Exactly what the form submits: the key that belonged to the
            // pair before the operator pasted a new private half.
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_owned(),
            ..WireguardProtocol::default()
        });
        let ProtocolConfig::Wireguard(merged) = settle_wireguard_keys(&incoming, &stored).unwrap()
        else {
            panic!("merge changed the protocol");
        };
        assert_eq!(merged.secret_key, rotated);
        assert_eq!(
            merged.public_key,
            keygen::derive_wireguard_public_key(rotated).unwrap(),
            "public key was not re-derived from the rotated private key"
        );
        assert_ne!(
            merged.public_key,
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        );
    }

    /// An inbound BECOMING `WireGuard` arrives with both halves blank — the form
    /// only pre-fills a pair when its tab is opened, and the operator who just
    /// flips the protocol select never opens it. Storing that blank would leave
    /// an inbound that can never be enabled, so the pair is generated here the
    /// way `create` generates it.
    #[test]
    fn switching_a_protocol_to_wireguard_mints_a_device_pair() {
        let stored = ProtocolConfig::Vless(VlessProtocol::default());
        let incoming = ProtocolConfig::Wireguard(WireguardProtocol {
            secret_key: String::new(),
            public_key: String::new(),
            ..WireguardProtocol::default()
        });
        let ProtocolConfig::Wireguard(merged) = settle_wireguard_keys(&incoming, &stored).unwrap()
        else {
            panic!("merge changed the protocol");
        };
        assert!(!merged.secret_key.is_empty(), "no private key was minted");
        assert_eq!(
            merged.public_key,
            keygen::derive_wireguard_public_key(&merged.secret_key).unwrap()
        );
    }

    /// A private key that is not a key is refused rather than stored: every
    /// client config would otherwise name a public key derived from nothing.
    #[test]
    fn a_wireguard_key_that_is_not_a_key_is_refused_on_update() {
        let stored = ProtocolConfig::Wireguard(WireguardProtocol {
            secret_key: "gI6EdUSYvn8ugXOt8QQD6Yc+JyiZxIhp3GInSWRfWGE=".to_owned(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_owned(),
            ..WireguardProtocol::default()
        });
        let incoming = ProtocolConfig::Wireguard(WireguardProtocol {
            secret_key: "definitely-not-a-key".to_owned(),
            ..WireguardProtocol::default()
        });
        assert!(settle_wireguard_keys(&incoming, &stored).is_err());
    }

    // === preserve_reality_keypair (update pre-commit build must see the same
    // security the write path persists) ======================================
    #[test]
    fn preserve_reality_keypair_lifts_stored_key_over_blank_patch() {
        // A Reality PATCH submits a blank private_key; the stored keypair must
        // carry forward so the update pre-commit build sees a valid key rather
        // than falsely 400ing with "x25519 key must decode to 32 bytes, got 0".
        let stored = SecurityConfig::Reality(RealitySecurity {
            private_key: "storedPrivateKey".into(),
            public_key: "storedPublicKey".into(),
            dest: "old.example.com:443".into(),
            server_names: vec!["old.example.com".into()],
            ..RealitySecurity::default()
        });
        // Operator edits only `dest`/`server_names`; the frontend blanks the key.
        let incoming = SecurityConfig::Reality(RealitySecurity {
            private_key: String::new(),
            public_key: String::new(),
            dest: "new.example.com:443".into(),
            server_names: vec!["new.example.com".into()],
            ..RealitySecurity::default()
        });
        let SecurityConfig::Reality(merged) = preserve_reality_keypair(&incoming, &stored) else {
            panic!("expected a Reality security");
        };
        assert_eq!(merged.private_key, "storedPrivateKey");
        assert_eq!(merged.public_key, "storedPublicKey");
        assert_eq!(
            merged.dest, "new.example.com:443",
            "the actual edit is kept"
        );
    }

    #[test]
    fn preserve_reality_keypair_passthrough_cases() {
        // Explicit rotate (non-blank incoming key) is left untouched.
        let stored = SecurityConfig::Reality(RealitySecurity {
            private_key: "storedKey".into(),
            ..RealitySecurity::default()
        });
        let rotate = SecurityConfig::Reality(RealitySecurity {
            private_key: "freshKey".into(),
            ..RealitySecurity::default()
        });
        let SecurityConfig::Reality(r) = preserve_reality_keypair(&rotate, &stored) else {
            panic!("expected Reality");
        };
        assert_eq!(r.private_key, "freshKey");

        // Switching TO Reality (blank key) over a non-Reality stored config has
        // no keypair to lift — it stays blank, so the pre-commit build correctly
        // rejects it (this is the fix working, not a regression).
        let stored_none = SecurityConfig::None(NoneSecurity {});
        let blank = SecurityConfig::Reality(RealitySecurity {
            private_key: String::new(),
            ..RealitySecurity::default()
        });
        let SecurityConfig::Reality(r2) = preserve_reality_keypair(&blank, &stored_none) else {
            panic!("expected Reality");
        };
        assert!(r2.private_key.is_empty());
    }
}
