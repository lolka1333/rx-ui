//! The single `panel_settings` row (`id = 1`): the whole-row read the GET and
//! a few sibling modules share, the snapshot a save takes before it writes,
//! the one UPDATE it issues, and the narrow reads boot needs before there is a
//! router to serve them.

use super::{listener::PanelTls, validate::NormalizedPanel};
use crate::{
    error::AppResult,
    models::{PanelSettings, PanelSettingsUpdate, RoutingRule},
};

/// Load the whole `panel_settings` row into `PanelSettings`. Shared by the GET
/// handler and callers that need one stored value — e.g. the outbound
/// connectivity test reading `xray_test_url`. Kept as the single whole-row
/// SELECT (rather than a second narrow single-column query) so no extra sqlx
/// offline-cache entry is needed — a real constraint in this repo, where
/// regenerating that cache is fragile.
pub async fn load_panel_settings(db: &crate::db::DbPool) -> AppResult<PanelSettings> {
    let row = sqlx::query!(
        "SELECT panel_port, panel_base_path,
                sub_enabled, sub_host_override, sub_link_host,
                sub_update_interval_hours,
                sub_brand_name, sub_service_url, sub_port,
                xray_freedom_strategy, xray_routing_strategy, xray_test_url,
                xray_freedom_allow_private, xray_freedom_block_delay,
                xray_block_bittorrent, xray_blocked_ips, xray_blocked_domains,
                xray_direct_ips, xray_direct_domains,
                xray_dns_servers, xray_dns_hosts, xray_dns_query_strategy,
                xray_dns_client_ip, xray_dns_tag, xray_dns_disable_cache,
                xray_dns_disable_fallback, xray_dns_disable_fallback_if_match,
                xray_dns_parallel_query, xray_dns_use_system_hosts,
                xray_dns_serve_stale, xray_dns_serve_expired_ttl,
                xray_ipv4_domains, xray_custom_rules, xray_rule_order,
                panel_tls_enabled, panel_tls_cert, panel_tls_key,
                sub_tls_mode, sub_cert_pem, sub_key_pem
            FROM panel_settings WHERE id = 1"
    )
    .fetch_one(db)
    .await?;
    // JSON-array / JSON-object columns; a parse failure (hand-edited DB)
    // degrades to an empty value rather than a 500.
    let list = |s: &str| serde_json::from_str::<Vec<String>>(s).unwrap_or_default();
    let xray_custom_rules =
        serde_json::from_str::<Vec<RoutingRule>>(&row.xray_custom_rules).unwrap_or_default();
    Ok(PanelSettings {
        panel_port: i32::try_from(row.panel_port).unwrap_or_else(|_| i32::from(DEFAULT_PANEL_PORT)),
        panel_base_path: row.panel_base_path,
        sub_enabled: row.sub_enabled != 0,
        sub_host_override: row.sub_host_override,
        sub_link_host: row.sub_link_host,
        sub_update_interval_hours: i32::try_from(row.sub_update_interval_hours).unwrap_or(12),
        sub_brand_name: row.sub_brand_name,
        sub_service_url: row.sub_service_url,
        sub_port: i32::try_from(row.sub_port).unwrap_or(0),
        xray_freedom_strategy: row.xray_freedom_strategy,
        xray_routing_strategy: row.xray_routing_strategy,
        xray_freedom_allow_private: list(&row.xray_freedom_allow_private),
        xray_freedom_block_delay: row.xray_freedom_block_delay,
        xray_test_url: row.xray_test_url,
        xray_block_bittorrent: row.xray_block_bittorrent != 0,
        xray_blocked_ips: list(&row.xray_blocked_ips),
        xray_blocked_domains: list(&row.xray_blocked_domains),
        xray_direct_ips: list(&row.xray_direct_ips),
        xray_direct_domains: list(&row.xray_direct_domains),
        xray_ipv4_domains: list(&row.xray_ipv4_domains),
        // Same rule as every other JSON column here: unreadable content reads
        // as empty rather than failing the whole settings page.
        xray_dns_servers: serde_json::from_str(&row.xray_dns_servers).unwrap_or_default(),
        xray_dns_hosts: serde_json::from_str(&row.xray_dns_hosts).unwrap_or_default(),
        xray_dns_query_strategy: row.xray_dns_query_strategy,
        xray_dns_client_ip: row.xray_dns_client_ip,
        xray_dns_tag: row.xray_dns_tag,
        xray_dns_disable_cache: row.xray_dns_disable_cache != 0,
        xray_dns_disable_fallback: row.xray_dns_disable_fallback != 0,
        xray_dns_disable_fallback_if_match: row.xray_dns_disable_fallback_if_match != 0,
        xray_dns_parallel_query: row.xray_dns_parallel_query != 0,
        xray_dns_use_system_hosts: row.xray_dns_use_system_hosts != 0,
        xray_dns_serve_stale: row.xray_dns_serve_stale != 0,
        xray_dns_serve_expired_ttl: u32::try_from(row.xray_dns_serve_expired_ttl).unwrap_or(0),
        xray_custom_rules,
        xray_rule_order: list(&row.xray_rule_order),
        panel_tls_enabled: row.panel_tls_enabled != 0,
        panel_tls_cert: row.panel_tls_cert,
        // Never echo the private key back to the client — only whether one is set.
        panel_tls_key_set: !row.panel_tls_key.trim().is_empty(),
        sub_tls_mode: row.sub_tls_mode,
        sub_cert_pem: row.sub_cert_pem,
        sub_key_set: !row.sub_key_pem.trim().is_empty(),
    })
}

/// Everything `update_panel`'s helpers need to know about the row as it stands
/// BEFORE the write. Read once, so every helper judges the same snapshot:
/// separate SELECTs could disagree about what "stored" meant under a
/// concurrent write.
pub(super) struct StoredPanel {
    pub(super) custom_rules: String,
    pub(super) rule_order: String,
    pub(super) blocked_ips: String,
    pub(super) blocked_domains: String,
    pub(super) direct_ips: String,
    pub(super) direct_domains: String,
    pub(super) ipv4_domains: String,
    pub(super) block_bittorrent: i64,
    pub(super) panel_tls_key: String,
    pub(super) sub_tls_mode: String,
    pub(super) sub_cert_pem: String,
    pub(super) sub_key_pem: String,
}

pub(super) async fn read_stored_panel(db: &crate::db::DbPool) -> AppResult<StoredPanel> {
    let r = sqlx::query!(
        r#"SELECT xray_custom_rules    AS "custom_rules!: String",
                  xray_rule_order      AS "rule_order!: String",
                  xray_blocked_ips     AS "blocked_ips!: String",
                  xray_blocked_domains AS "blocked_domains!: String",
                  xray_direct_ips      AS "direct_ips!: String",
                  xray_direct_domains  AS "direct_domains!: String",
                  xray_ipv4_domains    AS "ipv4_domains!: String",
                  xray_block_bittorrent,
                  panel_tls_key        AS "panel_tls_key!: String",
                  sub_tls_mode         AS "sub_tls_mode!: String",
                  sub_cert_pem         AS "sub_cert_pem!: String",
                  sub_key_pem          AS "sub_key_pem!: String"
             FROM panel_settings WHERE id = 1"#
    )
    .fetch_one(db)
    .await?;
    Ok(StoredPanel {
        custom_rules: r.custom_rules,
        rule_order: r.rule_order,
        blocked_ips: r.blocked_ips,
        blocked_domains: r.blocked_domains,
        direct_ips: r.direct_ips,
        direct_domains: r.direct_domains,
        ipv4_domains: r.ipv4_domains,
        block_bittorrent: r.xray_block_bittorrent,
        panel_tls_key: r.panel_tls_key,
        sub_tls_mode: r.sub_tls_mode,
        sub_cert_pem: r.sub_cert_pem,
        sub_key_pem: r.sub_key_pem,
    })
}

/// The parts of a settings write that don't come from `NormalizedPanel`:
/// already-serialised routing JSON and the two resolved certificate pairs.
/// Grouped into a struct because the alternative is nine positional
/// parameters, most of them `String`.
pub(super) struct PanelWrite<'a> {
    pub(super) custom_rules_json: &'a str,
    pub(super) rule_order_json: &'a str,
    /// `(enabled, cert, key)` for the panel listener.
    pub(super) tls: (i64, &'a str, &'a str),
    /// `(mode, cert, key)` for the subscription listener.
    pub(super) sub_tls: (&'a str, &'a str, &'a str),
}

/// Persist the whole `panel_settings` row. Split out of `update_panel` so the
/// handler stays about ordering — validate, write, apply — instead of being
/// mostly one thirty-column UPDATE.
pub(super) async fn write_panel_row(
    db: &crate::db::DbPool,
    body: &PanelSettingsUpdate,
    panel: &NormalizedPanel,
    w: PanelWrite<'_>,
) -> AppResult<()> {
    let sub_enabled_i = i64::from(body.sub_enabled);
    let xray_bittorrent_i = i64::from(panel.routing.block_bittorrent);
    sqlx::query!(
        "UPDATE panel_settings
            SET panel_port = ?,
                panel_base_path = ?,
                sub_enabled = ?,
                sub_host_override = ?,
                sub_link_host = ?,
                sub_update_interval_hours = ?,
                sub_brand_name = ?,
                sub_service_url = ?,
                sub_port = ?,
                xray_freedom_strategy = ?,
                xray_routing_strategy = ?,
                xray_freedom_allow_private = ?,
                xray_freedom_block_delay = ?,
                xray_test_url = ?,
                xray_block_bittorrent = ?,
                xray_blocked_ips = ?,
                xray_blocked_domains = ?,
                xray_direct_ips = ?,
                xray_direct_domains = ?,
                xray_dns_servers = ?,
                xray_dns_hosts = ?,
                xray_dns_query_strategy = ?,
                xray_dns_client_ip = ?,
                xray_dns_tag = ?,
                xray_dns_disable_cache = ?,
                xray_dns_disable_fallback = ?,
                xray_dns_disable_fallback_if_match = ?,
                xray_dns_parallel_query = ?,
                xray_dns_use_system_hosts = ?,
                xray_dns_serve_stale = ?,
                xray_dns_serve_expired_ttl = ?,
                xray_ipv4_domains = ?,
                xray_custom_rules = ?,
                xray_rule_order = ?,
                panel_tls_enabled = ?,
                panel_tls_cert = ?,
                panel_tls_key = ?,
                sub_tls_mode = ?,
                sub_cert_pem = ?,
                sub_key_pem = ?,
                updated_at = datetime('now')
            WHERE id = 1",
        body.panel_port,
        panel.base_path,
        sub_enabled_i,
        panel.sub_host,
        panel.sub_link_host,
        body.sub_update_interval_hours,
        panel.sub_brand,
        panel.sub_service_url,
        body.sub_port,
        panel.engine.freedom_strategy,
        panel.engine.routing_strategy,
        panel.engine.allow_private,
        panel.engine.block_delay,
        panel.engine.test_url,
        xray_bittorrent_i,
        panel.routing.blocked_ips,
        panel.routing.blocked_domains,
        panel.routing.direct_ips,
        panel.routing.direct_domains,
        panel.dns.servers,
        panel.dns.hosts,
        panel.dns.query_strategy,
        panel.dns.client_ip,
        panel.dns.tag,
        panel.dns.flags.disable_cache,
        panel.dns.flags.disable_fallback,
        panel.dns.flags.disable_fallback_if_match,
        panel.dns.flags.parallel_query,
        panel.dns.flags.use_system_hosts,
        panel.dns.flags.serve_stale,
        panel.dns.serve_expired_ttl,
        panel.routing.ipv4_domains,
        w.custom_rules_json,
        w.rule_order_json,
        w.tls.0,
        w.tls.1,
        w.tls.2,
        w.sub_tls.0,
        w.sub_tls.1,
        w.sub_tls.2,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Boot/runtime read of operator-provided panel TLS. Returns `Some` only when
/// HTTPS is enabled AND both PEM blobs are present; otherwise `None` (serve
/// plain HTTP). Validity of the pair is checked when the listener binds.
pub(super) async fn load_tls_for_boot(db: &crate::db::DbPool) -> Option<PanelTls> {
    let row = sqlx::query!(
        r#"SELECT panel_tls_enabled,
                  panel_tls_cert AS "panel_tls_cert!: String",
                  panel_tls_key AS "panel_tls_key!: String"
            FROM panel_settings WHERE id = 1"#
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;
    if row.panel_tls_enabled == 0
        || row.panel_tls_cert.trim().is_empty()
        || row.panel_tls_key.trim().is_empty()
    {
        return None;
    }
    Some(PanelTls {
        cert_pem: row.panel_tls_cert,
        key_pem: row.panel_tls_key,
    })
}

/// TLS for the dedicated subscription listener, honouring `sub_tls_mode`:
/// `off` → `None` (plain HTTP, TLS terminated by an upstream CDN/tunnel);
/// `custom` → the separate sub cert/key (`None` if either half is missing);
/// `inherit` (or anything unexpected) → the panel's own cert.
pub(super) async fn load_sub_tls_for_boot(db: &crate::db::DbPool) -> Option<PanelTls> {
    let row = sqlx::query!(
        r#"SELECT sub_tls_mode AS "sub_tls_mode!: String",
                  sub_cert_pem AS "sub_cert_pem!: String",
                  sub_key_pem  AS "sub_key_pem!: String"
            FROM panel_settings WHERE id = 1"#
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;
    match row.sub_tls_mode.trim() {
        "off" => None,
        "custom" => {
            if row.sub_cert_pem.trim().is_empty() || row.sub_key_pem.trim().is_empty() {
                return None;
            }
            Some(PanelTls {
                cert_pem: row.sub_cert_pem,
                key_pem: row.sub_key_pem,
            })
        }
        _ => load_tls_for_boot(db).await,
    }
}

/// The port migration 0019 seeds the settings row with. Boot treats a stored
/// value equal to this as "the operator never chose one" — see `main`.
pub const DEFAULT_PANEL_PORT: u16 = 8080;

/// Boot-time read. Returns the canonical `(panel_port, base_path,
/// sub_port)` for the initial listeners + router mount. Falls back to
/// env-var defaults on any DB error so a broken settings row can't
/// lock the operator out — they can at least bring the panel up on
/// the default port and fix it through the UI. `sub_port` is an i32
/// (not u16) so caller can detect / log the out-of-range case.
pub async fn load_for_boot(db: &crate::db::DbPool) -> (Option<u16>, String, i32) {
    let row = sqlx::query!(
        "SELECT panel_port, panel_base_path, sub_port FROM panel_settings WHERE id = 1"
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    match row {
        Some(r) => {
            // `None` here means "no settings row at all", which is a different
            // thing from "the row holds 8080" — the caller decides what to do
            // with the latter.
            let port = u16::try_from(r.panel_port).ok();
            let sub_port = i32::try_from(r.sub_port).unwrap_or(0);
            (port, r.panel_base_path, sub_port)
        }
        None => (None, String::new(), 0),
    }
}
