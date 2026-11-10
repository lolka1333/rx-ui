//! One write path for a client.
//!
//! A client — a *user* here — is every row that shares an email, one row per
//! inbound the user is attached to. Nearly everything about it is the user's,
//! not the row's: the uuid and the Hysteria secret it connects with, flow and
//! reverse tag, note, traffic limit and expiry, whether it is on, and the
//! subscription token. A row owns only its id, its inbound and, on a
//! `WireGuard` inbound, its peer.
//!
//! Every endpoint that changes a user — create on an inbound, bulk-assign, the
//! per-row PATCH, a traffic reset — says what the user should look like
//! afterwards (a [`UserWrite`]) and hands it here. This module makes the rows
//! say exactly that in one transaction, then tells xray about the rows that
//! actually changed. Keeping the per-user fields in step used to be each
//! endpoint's own job, and each did it a little differently: one re-enabled a
//! user whose limit was raised and another did not, one pushed a disabled user
//! back into xray, one created a new attachment switched on for a user who had
//! been switched off.

use super::{Row, row_to_client, wireguard_peer_for};
use crate::{
    AppState,
    db::DbPool,
    error::{AppError, AppResult},
    models::{Client, ClientBulkRemoved, ClientBulkXrayFailure, Inbound},
};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// What a user is, apart from where it is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserFields {
    pub uuid: String,
    /// Hysteria 2 secret. `None` ≡ authenticate by `uuid` (see
    /// `Client::effective_hysteria_auth`).
    pub auth: Option<String>,
    pub flow: Option<String>,
    pub reverse_tag: Option<String>,
    pub note: Option<String>,
    pub traffic_limit_bytes: Option<i64>,
    /// Stored UTC `YYYY-MM-DD HH:MM:SS`, already normalised.
    pub expires_at: Option<String>,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
}

impl UserFields {
    /// A user nobody has configured yet: a fresh uuid, on, nothing set.
    pub fn new_user() -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            auth: None,
            flow: None,
            reverse_tag: None,
            note: None,
            traffic_limit_bytes: None,
            expires_at: None,
            enabled: true,
            disabled_reason: None,
        }
    }
}

/// A user as stored.
pub struct StoredUser {
    pub fields: UserFields,
    /// Oldest first.
    pub rows: Vec<Client>,
    /// Whether one of its rows sits on a Hysteria 2 inbound.
    pub on_hysteria: bool,
}

impl StoredUser {
    pub fn inbound_ids(&self) -> Vec<String> {
        self.rows.iter().map(|r| r.inbound_id.clone()).collect()
    }

    pub fn has_inbound(&self, inbound_id: &str) -> bool {
        self.rows.iter().any(|r| r.inbound_id == inbound_id)
    }
}

async fn rows_of(conn: &mut sqlx::SqliteConnection, email: &str) -> AppResult<Vec<Client>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, inbound_id, email, uuid, auth, flow, reverse_tag, enabled, note, \
         traffic_limit_bytes, disabled_reason, expires_at, sub_token, wg_private_key, \
         wg_public_key, wg_address, wg_preshared_key, created_at, updated_at \
         FROM clients WHERE email = ? ORDER BY created_at ASC, id ASC",
    )
    .bind(email)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(row_to_client).collect())
}

/// Load the user an email names, or `None` when it has no rows.
///
/// The fields are read off the oldest row. Every write keeps the rows equal, so
/// for a user written by this module any row would do; rows written before it
/// may disagree, and the oldest one is the pick the subscription token was
/// unified on (migration 0054), so a user is always read the same way.
pub async fn load_user(db: &DbPool, email: &str) -> AppResult<Option<StoredUser>> {
    let mut conn = db.acquire().await?;
    let rows = rows_of(&mut conn, email).await?;
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let fields = UserFields {
        uuid: first.uuid.clone(),
        auth: first.auth.clone().filter(|s| !s.is_empty()),
        flow: first.flow.clone(),
        reverse_tag: first.reverse_tag.clone(),
        note: first.note.clone(),
        traffic_limit_bytes: first.traffic_limit_bytes,
        expires_at: first.expires_at.clone(),
        enabled: first.enabled,
        disabled_reason: first.disabled_reason.clone(),
    };
    // `json_valid` first: `json_extract` RAISES on malformed JSON rather than
    // returning NULL, and the column's default is ''.
    let on_hysteria: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM clients c JOIN inbounds i ON i.id = c.inbound_id \
         WHERE c.email = ? AND CASE WHEN json_valid(i.protocol_config) \
               THEN json_extract(i.protocol_config, '$.kind') END = 'hysteria2' \
         LIMIT 1",
    )
    .bind(email)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(Some(StoredUser {
        fields,
        rows,
        on_hysteria: on_hysteria.is_some(),
    }))
}

/// The Hysteria 2 secret a write should leave the user with.
///
/// The caller's value wins, then the user's own. Short of both, a secret is
/// minted only for a user with no Hysteria history: one that already has a
/// Hysteria attachment without a secret connects with its uuid, and stamping a
/// fresh secret on it would change the credential under every link it has.
pub fn resolve_auth(
    caller: Option<&str>,
    stored: Option<&StoredUser>,
    targets_hysteria: bool,
) -> Option<String> {
    if let Some(auth) = caller.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(auth.to_owned());
    }
    if let Some(user) = stored
        && (user.fields.auth.is_some() || user.on_hysteria)
    {
        return user.fields.auth.clone();
    }
    targets_hysteria.then(|| Uuid::new_v4().to_string())
}

/// What a user should look like after a write.
pub struct UserWrite {
    /// The email the rows carry afterwards.
    pub email: String,
    /// The email they carry now, when the write renames the user.
    pub rename_from: Option<String>,
    pub fields: UserFields,
    /// Exactly the inbounds the user ends up attached to.
    pub inbounds: HashMap<String, Inbound>,
}

/// What a write did to the rows: each surviving row before and after (no
/// `before` for a new attachment), and the rows it removed.
pub struct Committed {
    pub kept: Vec<(Option<Client>, Client)>,
    pub removed: Vec<Client>,
}

/// A user switched off by the poller comes back on once the reason has gone:
/// the limit was raised or cleared past what it has used, or the expiry was
/// cleared or moved into the future. A manual switch-off stays off.
fn recheck(mut fields: UserFields, used: i64) -> UserFields {
    let back_on = match fields.disabled_reason.as_deref() {
        Some("quota") => fields.traffic_limit_bytes.is_none_or(|cap| used < cap),
        Some("expired") => {
            let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
            fields
                .expires_at
                .as_deref()
                .is_none_or(|exp| exp > now.as_str())
        }
        _ => false,
    };
    if back_on && !fields.enabled {
        fields.enabled = true;
        fields.disabled_reason = None;
    }
    fields
}

/// Put the user's fields — and, on a rename, its new email — on an existing row.
async fn rewrite_row(
    tx: &mut sqlx::SqliteConnection,
    id: &str,
    email: &str,
    f: &UserFields,
    token: &str,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE clients SET email = ?, uuid = ?, auth = ?, flow = ?, reverse_tag = ?, note = ?, \
         traffic_limit_bytes = ?, expires_at = ?, enabled = ?, disabled_reason = ?, \
         sub_token = ?, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(email)
    .bind(&f.uuid)
    .bind(&f.auth)
    .bind(&f.flow)
    .bind(&f.reverse_tag)
    .bind(&f.note)
    .bind(f.traffic_limit_bytes)
    .bind(&f.expires_at)
    .bind(i64::from(f.enabled))
    .bind(&f.disabled_reason)
    .bind(token)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// Attach the user to one more inbound.
///
/// The new row starts at the user's current usage: xray counts per email, so
/// every row describes the same traffic, and a row that started at 0 would take
/// that history with it if the older ones were deleted later.
async fn insert_row(
    tx: &mut sqlx::SqliteConnection,
    inbound: &Inbound,
    email: &str,
    f: &UserFields,
    token: &str,
) -> AppResult<()> {
    // Per attachment, not per user: each `WireGuard` inbound hands out addresses
    // from its own subnet, and the address is the peer there.
    let wg = wireguard_peer_for(&mut *tx, &inbound.id, &inbound.tag, &inbound.protocol).await?;
    sqlx::query(
        "INSERT INTO clients (id, inbound_id, email, uuid, auth, flow, reverse_tag, enabled, \
         note, traffic_limit_bytes, disabled_reason, expires_at, sub_token, wg_private_key, \
         wg_public_key, wg_address, wg_preshared_key, uplink_total, downlink_total) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                 COALESCE((SELECT MAX(uplink_total) FROM clients WHERE email = ?), 0), \
                 COALESCE((SELECT MAX(downlink_total) FROM clients WHERE email = ?), 0))",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&inbound.id)
    .bind(email)
    .bind(&f.uuid)
    .bind(&f.auth)
    .bind(&f.flow)
    .bind(&f.reverse_tag)
    .bind(i64::from(f.enabled))
    .bind(&f.note)
    .bind(f.traffic_limit_bytes)
    .bind(&f.disabled_reason)
    .bind(&f.expires_at)
    .bind(token)
    .bind(&wg.private_key)
    .bind(&wg.public_key)
    .bind(&wg.address)
    .bind(&wg.preshared_key)
    .bind(email)
    .bind(email)
    .execute(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict(format!(
            "client '{email}' already exists in inbound {}",
            inbound.tag
        )),
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => AppError::NotFound,
        e => e.into(),
    })?;
    Ok(())
}

/// Make the rows say what `w` says, in one transaction.
///
/// Rows are written before any is deleted: a user moved off all its inbounds
/// onto new ones must still have a row when the old ones go, or the trigger
/// that retires subscription aliases with their user (migration 0054) would
/// take its old URLs with it.
pub async fn commit_user(db: &DbPool, w: &UserWrite) -> AppResult<Committed> {
    if w.inbounds.is_empty() {
        return Err(AppError::BadRequest(
            "a client has to stay attached to at least one inbound".to_owned(),
        ));
    }
    let from = w.rename_from.as_deref().unwrap_or(&w.email);
    // Reads the rows before writing them — see `begin_write`. The UI's group
    // toggle sends one PATCH per row at the same moment; on a deferred begin
    // most of them failed with "database is locked".
    let mut tx = crate::db::begin_write(db).await?;
    let before = rows_of(&mut tx, from).await?;
    if w.rename_from.is_some() && !rows_of(&mut tx, &w.email).await?.is_empty() {
        return Err(AppError::Conflict(format!(
            "a client with email '{}' already exists",
            w.email
        )));
    }

    let token = crate::api::subscription::token_for_email_on(&mut tx, from).await?;
    let used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(uplink_total + downlink_total), 0) FROM clients WHERE email = ?",
    )
    .bind(from)
    .fetch_one(&mut *tx)
    .await?;
    let f = recheck(w.fields.clone(), used);

    let before_by_inbound: HashMap<&str, &Client> =
        before.iter().map(|r| (r.inbound_id.as_str(), r)).collect();

    for row in before
        .iter()
        .filter(|r| w.inbounds.contains_key(&r.inbound_id))
    {
        rewrite_row(&mut tx, &row.id, &w.email, &f, &token).await?;
    }
    // Sorted so a multi-inbound create allocates in a stable order.
    let mut new_inbounds: Vec<&Inbound> = w
        .inbounds
        .values()
        .filter(|i| !before_by_inbound.contains_key(i.id.as_str()))
        .collect();
    new_inbounds.sort_by(|a, b| a.id.cmp(&b.id));
    for inbound in new_inbounds {
        insert_row(&mut tx, inbound, &w.email, &f, &token).await?;
    }

    if w.rename_from.is_some() {
        sqlx::query("UPDATE sub_token_aliases SET email = ? WHERE email = ?")
            .bind(&w.email)
            .bind(from)
            .execute(&mut *tx)
            .await?;
    }

    let mut removed = Vec::new();
    for row in &before {
        if w.inbounds.contains_key(&row.inbound_id) {
            continue;
        }
        sqlx::query("DELETE FROM clients WHERE id = ?")
            .bind(&row.id)
            .execute(&mut *tx)
            .await?;
        removed.push(row.clone());
    }

    let after = rows_of(&mut tx, &w.email).await?;
    tx.commit().await?;

    let kept = after
        .into_iter()
        .map(|a| {
            (
                before_by_inbound
                    .get(a.inbound_id.as_str())
                    .map(|b| (*b).clone()),
                a,
            )
        })
        .collect();
    Ok(Committed { kept, removed })
}

/// Whether xray has to be told about a change from `before` to `after`: the
/// account xray holds is built from exactly these — the email it keys users
/// on, the credentials, flow and reverse tag (both live in the VLESS account),
/// and a `WireGuard` peer's key and address. Note, limit and expiry never reach
/// xray.
fn xray_sees_change(before: &Client, after: &Client) -> bool {
    before.email != after.email
        || before.uuid != after.uuid
        || before.auth != after.auth
        || before.flow != after.flow
        || before.reverse_tag != after.reverse_tag
        || before.wg_public_key != after.wg_public_key
        || before.wg_preshared_key != after.wg_preshared_key
        || before.wg_address != after.wg_address
}

/// Bring one row's entry in xray in line with the DB: present, with the
/// current account, while the row and its inbound are both on; absent
/// otherwise. An unchanged live row is left alone — removing and re-adding it
/// would only disturb the user. `Err` carries what went wrong for the caller to
/// report; the DB is already right either way.
pub async fn sync_row(
    state: &AppState,
    inbound: &Inbound,
    before: Option<&Client>,
    after: Option<&Client>,
) -> Result<(), String> {
    if !inbound.enabled {
        return Ok(());
    }
    let was_live = before.is_some_and(|b| b.enabled);
    let live = after.is_some_and(|a| a.enabled);
    let changed = match (before, after) {
        (Some(b), Some(a)) => xray_sees_change(b, a),
        _ => true,
    };
    if was_live
        && (!live || changed)
        && let Some(b) = before
    {
        // A missing user is not an error here: the goal is its absence.
        let _ = state.xray_client.remove_user(&inbound.tag, &b.email).await;
    }
    if live
        && (!was_live || changed)
        && let Some(a) = after
    {
        let user = inbound
            .protocol
            .as_protocol()
            .build_user(a)
            .map_err(|e| format!("build_user failed: {e}"))?;
        state
            .xray_client
            .add_user(&inbound.tag, user)
            .await
            .map_err(|e| format!("AddUser failed: {e}"))?;
    }
    Ok(())
}

/// What [`apply_user`] reports back.
pub struct Applied {
    pub created: Vec<Client>,
    pub updated: Vec<Client>,
    pub removed: Vec<ClientBulkRemoved>,
    pub xray_failures: Vec<ClientBulkXrayFailure>,
}

/// Write the user, then sync xray for every row the write touched.
///
/// xray failures are collected rather than raised: the DB is the source of
/// truth and already committed, so the caller decides how loudly to say that
/// the running core lags behind it.
pub async fn apply_user(state: &AppState, w: &UserWrite) -> AppResult<Applied> {
    let committed = commit_user(&state.db, w).await?;

    let removed_ids: Vec<String> = committed
        .removed
        .iter()
        .map(|r| r.inbound_id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let removed_inbounds = crate::api::inbounds::fetch_inbounds_batch(state, &removed_ids).await?;

    let mut xray_failures = Vec::new();
    let mut fail = |inbound: &Inbound, message: String| {
        tracing::warn!(
            "client write: xray sync on {} failed: {message}",
            inbound.tag
        );
        xray_failures.push(ClientBulkXrayFailure {
            inbound_id: inbound.id.clone(),
            inbound_tag: inbound.tag.clone(),
            message,
        });
    };
    for row in &committed.removed {
        // An inbound deleted meanwhile has no handler left to clean up.
        if let Some(inbound) = removed_inbounds.get(&row.inbound_id)
            && let Err(e) = sync_row(state, inbound, Some(row), None).await
        {
            fail(inbound, e);
        }
    }
    let (mut created, mut updated) = (Vec::new(), Vec::new());
    for (before, after) in committed.kept {
        if let Some(inbound) = w.inbounds.get(&after.inbound_id)
            && let Err(e) = sync_row(state, inbound, before.as_ref(), Some(&after)).await
        {
            fail(inbound, e);
        }
        if before.is_some() {
            updated.push(after);
        } else {
            created.push(after);
        }
    }
    let removed = committed
        .removed
        .into_iter()
        .map(|r| ClientBulkRemoved {
            id: r.id,
            inbound_id: r.inbound_id,
        })
        .collect();
    Ok(Applied {
        created,
        updated,
        removed,
        xray_failures,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Client, StoredUser, UserFields, UserWrite, commit_user, recheck, resolve_auth,
        xray_sees_change,
    };
    use crate::db::DbPool;
    use crate::models::Inbound;
    use crate::protocols::ProtocolConfig;
    use std::collections::HashMap;

    async fn pool() -> DbPool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");
        pool
    }

    fn inbound(id: &str, protocol: ProtocolConfig) -> Inbound {
        Inbound {
            id: id.to_owned(),
            tag: id.to_owned(),
            enabled: true,
            listen: "0.0.0.0".into(),
            port: 1000,
            protocol,
            transport: crate::transports::TransportConfig::Tcp(
                crate::transports::tcp::TcpTransport::default(),
            ),
            security: crate::security::SecurityConfig::None(
                crate::security::NoneSecurity::default(),
            ),
            sniffing: crate::models::Sniffing::default(),
            finalmask: crate::transports::finalmask::FinalMask::None,
            sockopt: crate::transports::sockopt::SocketOpt::default(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn vless(id: &str) -> Inbound {
        inbound(
            id,
            ProtocolConfig::Vless(crate::protocols::vless::VlessProtocol::default()),
        )
    }

    async fn add_inbounds(pool: &DbPool, ids: &[&str]) {
        for (n, id) in ids.iter().enumerate() {
            sqlx::query(
                "INSERT INTO inbounds (id, tag, port, protocol_config) VALUES (?, ?, ?, ?)",
            )
            .bind(id)
            .bind(id)
            .bind(2000 + i64::try_from(n).unwrap())
            .bind(r#"{"kind":"vless"}"#)
            .execute(pool)
            .await
            .unwrap();
        }
    }

    fn on(ids: &[&str]) -> HashMap<String, Inbound> {
        ids.iter().map(|id| ((*id).to_owned(), vless(id))).collect()
    }

    fn write(email: &str, fields: &UserFields, ids: &[&str]) -> UserWrite {
        UserWrite {
            email: email.to_owned(),
            rename_from: None,
            fields: fields.clone(),
            inbounds: on(ids),
        }
    }

    async fn rows(pool: &DbPool, email: &str) -> Vec<Client> {
        let mut conn = pool.acquire().await.unwrap();
        super::rows_of(&mut conn, email).await.unwrap()
    }

    fn fields() -> UserFields {
        UserFields {
            note: Some("n".into()),
            traffic_limit_bytes: Some(1000),
            flow: Some("xtls-rprx-vision".into()),
            ..UserFields::new_user()
        }
    }

    /// Every per-user value, as one row carries it.
    fn shared(c: &Client) -> impl PartialEq + std::fmt::Debug {
        (
            c.uuid.clone(),
            c.auth.clone(),
            c.flow.clone(),
            c.reverse_tag.clone(),
            c.note.clone(),
            c.traffic_limit_bytes,
            c.expires_at.clone(),
            c.enabled,
            c.disabled_reason.clone(),
            c.sub_token.clone(),
        )
    }

    #[tokio::test]
    async fn every_row_of_a_user_carries_the_same_fields() {
        let pool = pool().await;
        add_inbounds(&pool, &["A", "B", "C"]).await;
        let f = fields();
        commit_user(&pool, &write("alice", &f, &["A", "B"]))
            .await
            .unwrap();
        commit_user(&pool, &write("alice", &f, &["A", "B", "C"]))
            .await
            .unwrap();
        let rs = rows(&pool, "alice").await;
        assert_eq!(rs.len(), 3);
        assert!(rs.iter().all(|r| shared(r) == shared(&rs[0])), "{rs:#?}");
        assert_eq!(rs[0].uuid, f.uuid);
    }

    #[tokio::test]
    async fn a_new_attachment_inherits_a_switched_off_user() {
        let pool = pool().await;
        add_inbounds(&pool, &["A", "B"]).await;
        let off = UserFields {
            enabled: false,
            disabled_reason: Some("manual".into()),
            ..fields()
        };
        commit_user(&pool, &write("bob", &off, &["A"]))
            .await
            .unwrap();
        let done = commit_user(&pool, &write("bob", &off, &["A", "B"]))
            .await
            .unwrap();
        let new = done
            .kept
            .iter()
            .find(|(b, _)| b.is_none())
            .expect("a new row")
            .1
            .clone();
        assert!(
            !new.enabled,
            "switched off by hand means off on the new inbound too"
        );
        assert_eq!(new.disabled_reason.as_deref(), Some("manual"));
    }

    #[tokio::test]
    async fn moving_a_user_to_new_inbounds_keeps_its_token_and_its_old_urls() {
        let pool = pool().await;
        add_inbounds(&pool, &["A", "B"]).await;
        let f = fields();
        commit_user(&pool, &write("carol", &f, &["A"]))
            .await
            .unwrap();
        let token = rows(&pool, "carol").await[0].sub_token.clone();
        sqlx::query("INSERT INTO sub_token_aliases (token, email) VALUES ('old', 'carol')")
            .execute(&pool)
            .await
            .unwrap();
        let done = commit_user(&pool, &write("carol", &f, &["B"]))
            .await
            .unwrap();
        assert_eq!(done.removed.len(), 1);
        let rs = rows(&pool, "carol").await;
        assert_eq!((rs.len(), rs[0].inbound_id.as_str()), (1, "B"));
        assert_eq!(rs[0].sub_token, token, "a full swap must keep the URL");
        assert_eq!(
            crate::api::subscription::owner_of_token(&pool, "old")
                .await
                .unwrap()
                .as_deref(),
            Some("carol"),
            "the swap deletes the old row last, so its retired URL survives"
        );
    }

    #[tokio::test]
    async fn a_new_attachment_starts_at_the_users_usage() {
        let pool = pool().await;
        add_inbounds(&pool, &["A", "B"]).await;
        let f = fields();
        commit_user(&pool, &write("dave", &f, &["A"]))
            .await
            .unwrap();
        sqlx::query(
            "UPDATE clients SET uplink_total = 300, downlink_total = 200 WHERE email = 'dave'",
        )
        .execute(&pool)
        .await
        .unwrap();
        commit_user(&pool, &write("dave", &f, &["A", "B"]))
            .await
            .unwrap();
        let totals: Vec<(i64, i64)> =
            sqlx::query_as("SELECT uplink_total, downlink_total FROM clients WHERE email = 'dave'")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(totals, [(300, 200), (300, 200)]);
    }

    #[tokio::test]
    async fn raising_the_limit_brings_a_quota_stopped_user_back() {
        let pool = pool().await;
        add_inbounds(&pool, &["A"]).await;
        let stopped = UserFields {
            enabled: false,
            disabled_reason: Some("quota".into()),
            traffic_limit_bytes: Some(1000),
            ..fields()
        };
        commit_user(&pool, &write("erin", &stopped, &["A"]))
            .await
            .unwrap();
        sqlx::query("UPDATE clients SET uplink_total = 1500 WHERE email = 'erin'")
            .execute(&pool)
            .await
            .unwrap();
        // Still over: stays off.
        commit_user(&pool, &write("erin", &stopped, &["A"]))
            .await
            .unwrap();
        assert!(!rows(&pool, "erin").await[0].enabled);
        // Limit raised past the usage: back on.
        let raised = UserFields {
            traffic_limit_bytes: Some(5000),
            ..stopped.clone()
        };
        commit_user(&pool, &write("erin", &raised, &["A"]))
            .await
            .unwrap();
        let r = &rows(&pool, "erin").await[0];
        assert!(r.enabled);
        assert_eq!(r.disabled_reason, None);
    }

    #[test]
    fn only_the_reasons_the_poller_sets_lift_by_themselves() {
        let expired = UserFields {
            enabled: false,
            disabled_reason: Some("expired".into()),
            expires_at: Some("2001-01-01 00:00:00".into()),
            ..fields()
        };
        assert!(!recheck(expired.clone(), 0).enabled, "still in the past");
        let extended = UserFields {
            expires_at: Some("2999-01-01 00:00:00".into()),
            ..expired.clone()
        };
        assert!(recheck(extended, 0).enabled);
        let manual = UserFields {
            disabled_reason: Some("manual".into()),
            traffic_limit_bytes: None,
            expires_at: None,
            ..expired
        };
        assert!(
            !recheck(manual, 0).enabled,
            "a manual switch-off is the operator's to undo"
        );
    }

    #[tokio::test]
    async fn a_rename_moves_the_whole_user_and_refuses_a_taken_email() {
        let pool = pool().await;
        add_inbounds(&pool, &["A", "B"]).await;
        let f = fields();
        commit_user(&pool, &write("fay", &f, &["A", "B"]))
            .await
            .unwrap();
        commit_user(&pool, &write("gus", &f, &["A"])).await.unwrap();
        let token = rows(&pool, "fay").await[0].sub_token.clone();
        sqlx::query("INSERT INTO sub_token_aliases (token, email) VALUES ('fay-old', 'fay')")
            .execute(&pool)
            .await
            .unwrap();

        let onto_gus = UserWrite {
            rename_from: Some("fay".into()),
            ..write("gus", &f, &["A", "B"])
        };
        assert!(matches!(
            commit_user(&pool, &onto_gus).await,
            Err(crate::error::AppError::Conflict(_))
        ));

        let renamed = UserWrite {
            rename_from: Some("fay".into()),
            ..write("hal", &f, &["A", "B"])
        };
        commit_user(&pool, &renamed).await.unwrap();
        assert!(rows(&pool, "fay").await.is_empty());
        let rs = rows(&pool, "hal").await;
        assert_eq!(rs.len(), 2);
        assert!(
            rs.iter().all(|r| r.sub_token == token),
            "a rename keeps the URL"
        );
        let owner = |t: &'static str| {
            let pool = pool.clone();
            async move {
                crate::api::subscription::owner_of_token(&pool, t)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(owner("fay-old").await.as_deref(), Some("hal"));
    }

    /// The Hysteria secret is the user's, so it lives on every row — VLESS ones
    /// included, where the wire ignores it. Dropping the last Hysteria
    /// attachment must not drop the secret: re-adding Hysteria later has to
    /// hand the user the credential its links already carry.
    #[tokio::test]
    async fn the_hysteria_secret_outlives_the_last_hysteria_attachment() {
        let pool = pool().await;
        add_inbounds(&pool, &["V"]).await;
        sqlx::query(
            "INSERT INTO inbounds (id, tag, port, protocol_config) VALUES ('H', 'H', 3000, ?)",
        )
        .bind(r#"{"kind":"hysteria2"}"#)
        .execute(&pool)
        .await
        .unwrap();
        let hysteria = || {
            inbound(
                "H",
                ProtocolConfig::Hysteria2(crate::protocols::hysteria::HysteriaProtocol {}),
            )
        };
        let both: HashMap<String, Inbound> =
            [("V".to_owned(), vless("V")), ("H".to_owned(), hysteria())].into();

        let secret = resolve_auth(None, None, true).expect("a new user on Hysteria gets a secret");
        let f = UserFields {
            auth: Some(secret.clone()),
            ..fields()
        };
        commit_user(
            &pool,
            &UserWrite {
                inbounds: both.clone(),
                ..write("jo", &f, &[])
            },
        )
        .await
        .unwrap();
        assert!(
            rows(&pool, "jo")
                .await
                .iter()
                .all(|r| r.auth.as_deref() == Some(secret.as_str()))
        );

        // Off Hysteria: the VLESS row keeps the secret...
        commit_user(&pool, &write("jo", &f, &["V"])).await.unwrap();
        let stored = super::load_user(&pool, "jo").await.unwrap().unwrap();
        assert!(!stored.on_hysteria);
        // ...and going back on hands the same one out again.
        assert_eq!(
            resolve_auth(None, Some(&stored), true).as_deref(),
            Some(secret.as_str())
        );
    }

    /// `json_extract` RAISES on malformed JSON, and `protocol_config` defaults
    /// to ''. Reading a user attached to such an inbound must not fail.
    #[tokio::test]
    async fn a_user_on_an_inbound_with_a_broken_config_still_loads() {
        let pool = pool().await;
        add_inbounds(&pool, &["A"]).await;
        sqlx::query(
            "INSERT INTO inbounds (id, tag, port, protocol_config) VALUES ('X', 'X', 3001, '')",
        )
        .execute(&pool)
        .await
        .unwrap();
        commit_user(&pool, &write("kim", &fields(), &["A", "X"]))
            .await
            .unwrap();
        let stored = super::load_user(&pool, "kim")
            .await
            .unwrap()
            .expect("loads");
        assert_eq!(stored.rows.len(), 2);
        assert!(!stored.on_hysteria);
    }

    #[tokio::test]
    async fn a_user_cannot_be_left_without_an_inbound() {
        let pool = pool().await;
        assert!(matches!(
            commit_user(&pool, &write("ivy", &fields(), &[])).await,
            Err(crate::error::AppError::BadRequest(_))
        ));
    }

    fn stored(auth: Option<&str>, on_hysteria: bool) -> StoredUser {
        StoredUser {
            fields: UserFields {
                auth: auth.map(str::to_owned),
                ..UserFields::new_user()
            },
            rows: Vec::new(),
            on_hysteria,
        }
    }

    #[test]
    fn a_hysteria_secret_is_minted_only_for_a_user_without_one() {
        // The caller's word first, then the user's own secret.
        assert_eq!(
            resolve_auth(Some(" mine "), Some(&stored(Some("s"), true)), true).as_deref(),
            Some("mine")
        );
        assert_eq!(
            resolve_auth(None, Some(&stored(Some("s"), true)), true).as_deref(),
            Some("s")
        );
        // A user already on Hysteria without a secret connects with its uuid:
        // minting one now would change the credential under its links.
        assert_eq!(resolve_auth(None, Some(&stored(None, true)), true), None);
        // A VLESS-only user going onto Hysteria, or a new one, gets a secret.
        assert!(resolve_auth(None, Some(&stored(None, false)), true).is_some());
        assert!(resolve_auth(None, None, true).is_some());
        assert_eq!(resolve_auth(None, None, false), None);
    }

    #[test]
    fn xray_hears_only_about_what_it_holds() {
        let base = Client {
            id: "1".into(),
            inbound_id: "A".into(),
            email: "e".into(),
            uuid: "u".into(),
            auth: None,
            flow: None,
            reverse_tag: None,
            enabled: true,
            note: None,
            traffic_limit_bytes: None,
            disabled_reason: None,
            expires_at: None,
            sub_token: "t".into(),
            wg_private_key: None,
            wg_public_key: None,
            wg_address: None,
            wg_preshared_key: None,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let quiet = Client {
            note: Some("n".into()),
            traffic_limit_bytes: Some(1),
            expires_at: Some("2999-01-01 00:00:00".into()),
            updated_at: "later".into(),
            ..base.clone()
        };
        assert!(!xray_sees_change(&base, &quiet));
        for loud in [
            Client {
                uuid: "u2".into(),
                ..base.clone()
            },
            Client {
                email: "e2".into(),
                ..base.clone()
            },
            Client {
                flow: Some("xtls-rprx-vision".into()),
                ..base.clone()
            },
            Client {
                reverse_tag: Some("r".into()),
                ..base.clone()
            },
            Client {
                wg_public_key: Some("k".into()),
                ..base.clone()
            },
        ] {
            assert!(xray_sees_change(&base, &loud), "{loud:?}");
        }
    }
}
