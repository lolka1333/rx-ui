//! The `inbounds` table: decoding a row into an `Inbound`, the reads sibling
//! modules hydrate through, and the PATCH write. `Row` is the one shape every
//! SELECT decodes into; the column list is repeated per query because
//! `query_as!` checks a literal against the schema at compile time.

use super::{
    keys::{preserve_reality_keypair_tx, settle_wireguard_keys_tx},
    validate::validate_inbound_tag,
};
use crate::{
    AppState,
    error::{AppError, AppResult},
    models::{Inbound, InboundUpdate},
    protocols::ProtocolConfig,
};

/// One `inbounds` row, still JSON-encoded. `row_to_inbound` is the only
/// intended consumer; `tag` is public because the reconciler logs by it.
#[derive(sqlx::FromRow)]
pub struct Row {
    id: String,
    pub tag: String,
    enabled: i64,
    listen: String,
    port: i64,
    protocol_config: String,
    transport_config: String,
    security_config: String,
    sniffing_config: String,
    finalmask_config: String,
    sockopt_config: String,
    created_at: String,
    updated_at: String,
}

/// Every enabled inbound, as raw rows. Shared with the boot reconciler so the
/// column list lives in one place.
pub async fn load_enabled_inbound_rows(db: &crate::db::DbPool) -> AppResult<Vec<Row>> {
    // `query_as!`, like `read_row` below: the macro checks the column list and
    // the types against the schema at compile time. The runtime form would
    // turn a renamed column into a 500 at boot instead of a build error.
    Ok(sqlx::query_as!(
        Row,
        r#"SELECT id, tag, enabled, listen, port,
                  protocol_config, transport_config, security_config, sniffing_config,
                  finalmask_config, sockopt_config, created_at, updated_at
           FROM inbounds WHERE enabled = 1"#
    )
    .fetch_all(db)
    .await?)
}

/// Decode one DB row into the public `Inbound`. Each JSON column maps
/// directly into the corresponding tagged-enum field via `serde_json`.
/// A malformed blob in any layer is surfaced as a 500 — the JSON is
/// always written by this same code, so a parse failure means DB
/// corruption or an aborted backfill, not user error.
pub fn row_to_inbound(r: Row) -> AppResult<Inbound> {
    let protocol = serde_json::from_str(&r.protocol_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("protocol_config JSON: {e}")))?;
    let transport = serde_json::from_str(&r.transport_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("transport_config JSON: {e}")))?;
    let security = serde_json::from_str(&r.security_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("security_config JSON: {e}")))?;
    let sniffing = serde_json::from_str(&r.sniffing_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("sniffing_config JSON: {e}")))?;
    // Legacy single-item Noise blobs fold into the current `items[]` shape
    // automatically on deserialize (see `NoiseParams` / `NoiseParamsRepr`).
    let finalmask = serde_json::from_str(&r.finalmask_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("finalmask_config JSON: {e}")))?;
    let sockopt = serde_json::from_str(&r.sockopt_config)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("sockopt_config JSON: {e}")))?;
    Ok(Inbound {
        id: r.id,
        tag: r.tag,
        enabled: r.enabled != 0,
        listen: r.listen,
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        port: r.port as u16,
        protocol,
        transport,
        security,
        sniffing,
        finalmask,
        sockopt,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

/// Every inbound, newest first — the order the Inbounds page lists them in.
pub(super) async fn list_inbounds(db: &crate::db::DbPool) -> AppResult<Vec<Inbound>> {
    let rows = sqlx::query_as!(
        Row,
        r#"SELECT id, tag, enabled, listen, port,
                  protocol_config, transport_config, security_config, sniffing_config,
                  finalmask_config, sockopt_config, created_at, updated_at
           FROM inbounds
           ORDER BY created_at DESC"#
    )
    .fetch_all(db)
    .await?;
    rows.into_iter().map(row_to_inbound).collect()
}

pub(super) async fn read_row(state: &AppState, id: &str) -> AppResult<Row> {
    sqlx::query_as!(
        Row,
        r#"SELECT id, tag, enabled, listen, port,
                  protocol_config, transport_config, security_config, sniffing_config,
                  finalmask_config, sockopt_config, created_at, updated_at
           FROM inbounds WHERE id = ?"#,
        id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

/// One inbound, fully decoded — for sibling modules (`api::clients` needs the
/// typed view to build share links and push a rebuilt handler after a client
/// write). A missing id is a 404.
pub async fn fetch_inbound(state: &AppState, id: &str) -> AppResult<Inbound> {
    row_to_inbound(read_row(state, id).await?)
}

/// Batched sibling of `fetch_inbound`: every inbound whose id is in `ids`,
/// in one `WHERE id IN (…)` SELECT, keyed by id. The subscription bundle and
/// the client write path need many at once and would otherwise pay a round
/// trip per row.
///
/// A row that fails to hydrate is an ERROR, not an omission: the map is keyed
/// by id, and a caller reads a missing key as "this inbound is gone" — so
/// dropping a corrupt row would surface DB corruption as a plausible-looking
/// 404 somewhere else entirely.
pub async fn fetch_inbounds_batch(
    state: &AppState,
    ids: &[String],
) -> AppResult<std::collections::HashMap<String, Inbound>> {
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT id, tag, enabled, listen, port, \
         protocol_config, transport_config, security_config, sniffing_config, \
         finalmask_config, sockopt_config, created_at, updated_at FROM inbounds WHERE id IN (",
    );
    let mut sep = qb.separated(", ");
    for id in ids {
        sep.push_bind(id);
    }
    qb.push(")");
    let rows = qb.build_query_as::<Row>().fetch_all(&state.db).await?;
    let mut out = std::collections::HashMap::with_capacity(rows.len());
    for r in rows {
        out.insert(r.id.clone(), row_to_inbound(r)?);
    }
    Ok(out)
}

/// Port-uniqueness guard. xray's HandlerService.AddInbound does NOT
/// reliably reject duplicate port bindings — on Windows in particular
/// two inbounds can coexist in xray's config while only one actually
/// receives traffic (silent SO_REUSEADDR-style override). A clean 409
/// from the panel is much better than a phantom inbound.
pub(super) async fn ensure_port_free<'e, E>(
    conn: E,
    port: u16,
    exclude_id: Option<&str>,
) -> AppResult<()>
where
    E: sqlx::SqliteExecutor<'e>,
{
    let p = i64::from(port);
    let tag: Option<String> = match exclude_id {
        Some(id) => {
            sqlx::query_scalar("SELECT tag FROM inbounds WHERE port = ? AND id != ?")
                .bind(p)
                .bind(id)
                .fetch_optional(conn)
                .await?
        }
        None => {
            sqlx::query_scalar("SELECT tag FROM inbounds WHERE port = ?")
                .bind(p)
                .fetch_optional(conn)
                .await?
        }
    };
    if let Some(tag) = tag {
        return Err(AppError::Conflict(format!(
            "port {port} is already used by inbound '{tag}'"
        )));
    }
    Ok(())
}

/// Apply the PATCH body to the DB inside one tx. Each non-`None` field
/// becomes its own sub-UPDATE so the unique-violation on `tag` can be
/// surfaced specifically (a combined dynamic UPDATE would lose that
/// error context). Port writes go through `ensure_port_free` so the
/// same port can't be silently double-bound by two inbounds.
pub(super) async fn write_inbound_update_tx(
    state: &AppState,
    id: &str,
    body: &InboundUpdate,
) -> AppResult<()> {
    let mut tx = crate::db::begin_write(&state.db).await?;
    if let Some(tag) = &body.tag {
        validate_inbound_tag(tag)?;
        // Current tag, captured before the rename so the persisted per-inbound
        // traffic total can follow it. `inbound_traffic` is keyed by tag (xray
        // counts per tag), so without the migration below the total would orphan
        // under the old tag and a later inbound reusing it would inherit these
        // bytes — the exact ghost-total misattribution this feature removes.
        let old_tag: Option<String> = sqlx::query_scalar!(
            r#"SELECT tag AS "tag!: String" FROM inbounds WHERE id = ?"#,
            id
        )
        .fetch_optional(&mut *tx)
        .await?;

        sqlx::query!(
            "UPDATE inbounds SET tag = ?, updated_at = datetime('now') WHERE id = ?",
            tag,
            id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                AppError::Conflict(format!("inbound with tag '{tag}' already exists"))
            }
            e => e.into(),
        })?;

        if let Some(old_tag) = old_tag
            && old_tag != *tag
        {
            // Drop any stale row already under the new tag (left by a previously
            // deleted inbound) before moving the old total onto it, so the
            // UPDATE can't collide with the `inbound_traffic` primary key.
            sqlx::query!("DELETE FROM inbound_traffic WHERE tag = ?", tag)
                .execute(&mut *tx)
                .await?;
            sqlx::query!(
                "UPDATE inbound_traffic SET tag = ? WHERE tag = ?",
                tag,
                old_tag
            )
            .execute(&mut *tx)
            .await?;
        }
    }
    if let Some(enabled) = body.enabled {
        let v = i64::from(enabled);
        sqlx::query!(
            "UPDATE inbounds SET enabled = ?, updated_at = datetime('now') WHERE id = ?",
            v,
            id
        )
        .execute(&mut *tx)
        .await?;
    }
    if let Some(listen) = &body.listen {
        sqlx::query!(
            "UPDATE inbounds SET listen = ?, updated_at = datetime('now') WHERE id = ?",
            listen,
            id
        )
        .execute(&mut *tx)
        .await?;
    }
    if let Some(port) = body.port {
        let p = i64::from(port);
        ensure_port_free(&mut *tx, port, Some(id)).await?;
        sqlx::query!(
            "UPDATE inbounds SET port = ?, updated_at = datetime('now') WHERE id = ?",
            p,
            id
        )
        .execute(&mut *tx)
        .await?;
    }
    // Layer JSON blobs are persisted in a helper purely to keep this
    // function under the line limit — see `write_inbound_layers_tx`.
    write_inbound_layers_tx(&mut tx, id, body).await?;
    tx.commit().await.map_err(AppError::from)
}

/// Persist the six JSON-blob layer columns of an inbound PATCH (protocol,
/// transport, security, sniffing, finalmask, sockopt). Split out of
/// `write_inbound_update_tx` only to keep it under the line limit — each
/// arm stays explicit because `sqlx::query!` insists on a literal column
/// name, so they can't be collapsed into a loop.
async fn write_inbound_layers_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
    body: &InboundUpdate,
) -> AppResult<()> {
    if let Some(protocol) = &body.protocol {
        // Same treatment Reality's keypair gets below, for the same reason:
        // a blank key in the body means "unchanged", never "wipe it". Only a
        // WireGuard body with a blank key pays for the extra read.
        let protocol = settle_wireguard_keys_tx(tx, id, protocol).await?;
        let j = serde_json::to_string(&protocol)?;
        sqlx::query!(
            "UPDATE inbounds SET protocol_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
        // An inbound that just became WireGuard keeps the clients it had, and
        // they carry none of what a peer needs. Issue it now, in this same
        // transaction: the alternative is a row that looks fine until someone
        // enables it and takes every other peer on the inbound down with it.
        if matches!(protocol, ProtocolConfig::Wireguard(_)) {
            let tag = sqlx::query_scalar!(
                r#"SELECT tag AS "tag!: String" FROM inbounds WHERE id = ?"#,
                id
            )
            .fetch_one(&mut **tx)
            .await?;
            crate::api::clients::backfill_wireguard_peers(tx, id, &tag, &protocol).await?;
        }
    }
    if let Some(transport) = &body.transport {
        let j = serde_json::to_string(transport)?;
        sqlx::query!(
            "UPDATE inbounds SET transport_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(security) = &body.security {
        // Reality's x25519 keypair is server-managed — the frontend never
        // holds the private key, so it submits it blank on every update.
        // Writing that blank straight through wipes the stored keypair and
        // leaves the inbound unbuildable ("x25519 key must decode to 32
        // bytes, got 0"). Carry the existing keypair forward when the
        // incoming private key is empty; an explicit rotate uses its own
        // endpoint and arrives with a real key.
        let security = preserve_reality_keypair_tx(tx, id, security).await?;
        let j = serde_json::to_string(&security)?;
        sqlx::query!(
            "UPDATE inbounds SET security_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(sniffing) = &body.sniffing {
        let j = serde_json::to_string(sniffing)?;
        sqlx::query!(
            "UPDATE inbounds SET sniffing_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(finalmask) = &body.finalmask {
        let j = serde_json::to_string(finalmask)?;
        sqlx::query!(
            "UPDATE inbounds SET finalmask_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(sockopt) = &body.sockopt {
        let j = serde_json::to_string(sockopt)?;
        sqlx::query!(
            "UPDATE inbounds SET sockopt_config = ?, updated_at = datetime('now') WHERE id = ?",
            j,
            id
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
