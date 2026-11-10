//! Runtime panel settings: the listener (port, URL prefix, TLS), subscription
//! delivery, and the xray engine, routing and DNS knobs.
//!
//! * `store` — the `panel_settings` row: the whole-row read, the one UPDATE a
//!   save issues, and the narrow reads boot needs.
//! * `validate` — the panel, subscription and engine fields, and the two TLS
//!   pairs.
//! * `routing` — the basic match lists and the operator's custom rules.
//! * `dns` — the core's own resolver section.
//! * `listener` — rebinding the panel and subscription listeners in place.
//!
//! A save validates everything first, writes the row once, hot-applies routing
//! (`xray::reload::hot_apply_routing`) when it changed, and rebinds the
//! listeners last. DNS and the engine settings reach xray only through the
//! config file, so they take effect on the next restart.

mod dns;
mod listener;
mod routing;
mod store;
mod validate;

pub use listener::{spawn_main_listener, spawn_sub_listener};
pub use store::{DEFAULT_PANEL_PORT, load_for_boot, load_panel_settings};
pub use validate::validate_optional_http_url;

use self::{
    listener::apply_listener_changes,
    routing::{StoredRules, XrayRouting, valid_rule_targets, validate_custom_routing},
    store::{PanelWrite, StoredPanel, read_stored_panel, write_panel_row},
    validate::{resolve_panel_tls, resolve_sub_tls, validate_panel_update},
};
use crate::{
    AppState,
    auth::AuthUser,
    error::AppResult,
    models::{PanelSettings, PanelSettingsUpdate},
};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use std::{sync::atomic::Ordering, time::Duration};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/panel", get(get_panel).put(update_panel))
        .route("/panel/restart", post(restart_panel))
}

async fn get_panel(
    _user: AuthUser,
    State(state): State<AppState>,
) -> AppResult<Json<PanelSettings>> {
    Ok(Json(load_panel_settings(&state.db).await?))
}

async fn update_panel(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<PanelSettingsUpdate>,
) -> AppResult<Json<serde_json::Value>> {
    let panel = validate_panel_update(&body)?;
    // The row as it stands, read once and shared by every helper below.
    let stored = read_stored_panel(&state.db).await?;
    // Validate custom rules + order up front, so a bad rule aborts before any
    // DB write. Valid targets = the reserved built-ins ∪ the tags of currently-
    // enabled custom outbounds (a rule may route to an operator's relay).
    let valid_targets = valid_rule_targets(&state.db).await?;
    let stored_rules = StoredRules::from_row(&stored);
    let (custom_rules_json, rule_order_json) =
        validate_custom_routing(&body, &valid_targets, &stored_rules)?;

    // Panel HTTPS: validate + resolve the cert/key (an empty incoming key keeps
    // the stored one) before persisting — a bad pair fails here as a clean 400
    // the operator sees in the form, not as a failed restart later.
    let (tls_enabled_i, tls_cert, tls_key) = resolve_panel_tls(&stored, &body).await?;
    // Subscription TLS is independent of the panel's: validate the mode + (for
    // `custom`) the separate cert/key pair, keeping the stored key when the
    // incoming one is blank — same convention as the panel cert above.
    let (sub_tls_mode, sub_cert, sub_key, sub_tls_changed) =
        resolve_sub_tls(&stored, &body).await?;

    // Snapshot routing-relevant fields BEFORE the UPDATE, so we only hot-apply
    // routing when it actually changed. An unrelated save (brand / TLS / sub
    // port) must not touch the live router or risk a recovery restart.
    let routing_changed = routing_fields_changed(
        &stored,
        &panel.routing,
        &custom_rules_json,
        &rule_order_json,
    );

    write_panel_row(
        &state.db,
        &body,
        &panel,
        PanelWrite {
            custom_rules_json: &custom_rules_json,
            rule_order_json: &rule_order_json,
            tls: (tls_enabled_i, &tls_cert, &tls_key),
            sub_tls: (&sub_tls_mode, &sub_cert, &sub_key),
        },
    )
    .await?;

    // Hot-apply the just-persisted routing rules (no restart) — only when they
    // actually changed; see docs on hot_apply_routing. Done BEFORE the listener
    // rebind: the UPDATE has already committed and routing doesn't depend on
    // listener state, so a rebind failure must not strand the rule change (the
    // change-gate would see no delta on the operator's retry).
    // Re-push when a previous attempt left the router out of step, even if this
    // save changes nothing routing-related: without it the operator's retry is
    // silently a no-op.
    let routing_changed = routing_changed || state.routing_out_of_sync.load(Ordering::Relaxed);
    let routing = if routing_changed {
        Some(crate::xray::reload::hot_apply_routing(&state).await)
    } else {
        None
    };

    apply_listener_changes(
        &state,
        &body,
        panel.new_port,
        &panel.base_path,
        sub_tls_changed,
    )
    .await?;
    // When this save didn't push, the router can still be stale from an earlier
    // one that failed in a way not worth retrying — report that rather than let
    // the save read as clean.
    let lingering = state.routing_stale.read().await.clone();
    Ok(Json(routing_body(routing, lingering)))
}

/// Report what happened to the live router. The row is committed either way, so
/// this is never an error status — but it must not read as "done" when the
/// running xray never took the rules, which is all the UI has to go on.
fn routing_body(
    routing: Option<crate::xray::reload::RoutingApply>,
    lingering: Option<String>,
) -> serde_json::Value {
    // Nothing pushed this time: still say so if a previous attempt left the
    // router behind the DB. Silence here is what makes a stale router look like
    // a clean save on every subsequent edit.
    let Some(applied) = routing else {
        return lingering.map_or_else(
            || serde_json::json!({}),
            |detail| serde_json::json!({ "routing_live": false, "routing_detail": detail }),
        );
    };
    applied.detail().map_or_else(
        // Live — but say whether it cost a restart, so the UI can't tell an
        // operator "no restart needed" right after their tunnels dropped.
        || {
            serde_json::json!({
                "routing_live": true,
                "routing_restarted": applied.dropped_connections(),
            })
        },
        |detail| serde_json::json!({ "routing_live": false, "routing_detail": detail }),
    )
}

/// Whether a settings update touches anything the router cares about (rules,
/// order, block/ipv4 lists, bittorrent), compared against the currently-stored
/// values. Lets the caller skip the live-router push on unrelated saves.
fn routing_fields_changed(
    stored: &StoredPanel,
    routing: &XrayRouting,
    custom_rules_json: &str,
    rule_order_json: &str,
) -> bool {
    stored.custom_rules != custom_rules_json
        || stored.rule_order != rule_order_json
        || stored.blocked_ips != routing.blocked_ips
        || stored.blocked_domains != routing.blocked_domains
        // Without these two a saved direct list would sit in the database and
        // change nothing until the next restart: this flag is what triggers the
        // hot re-apply of the whole rule set.
        || stored.direct_ips != routing.direct_ips
        || stored.direct_domains != routing.direct_domains
        || stored.ipv4_domains != routing.ipv4_domains
        || (stored.block_bittorrent != 0) != routing.block_bittorrent
}

/// Restart the panel process. TLS binds at startup, so flipping HTTPS on/off (or
/// swapping the cert) is applied by exiting and letting the supervisor respawn —
/// `restart: unless-stopped` under Docker, a unit under systemd. With no
/// supervisor the process simply stops and must be started again by hand. Exits
/// after a short beat so the 202 response reaches the UI first.
async fn restart_panel(_user: AuthUser) -> StatusCode {
    tracing::warn!("panel restart requested via API — exiting so the supervisor respawns");
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        std::process::exit(0);
    });
    StatusCode::ACCEPTED
}
