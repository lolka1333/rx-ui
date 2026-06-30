pub mod auth;
pub mod clients;
pub mod dashboard;
pub mod inbounds;
pub mod keygen;
pub mod logs;
pub mod outbounds;
pub mod settings;
pub mod subscription;
pub mod xray;

use crate::{AppState, static_assets};
use axum::{Router, routing::get};

pub fn router(state: AppState) -> Router {
    Router::new()
        // Explicit mount-root route: serves the SPA at `/` (root mode) and at
        // the prefix root after nest-strip (`/secret/`), which axum's `nest`
        // won't route to the fallback on its own.
        .route("/", get(static_assets::serve_index_root))
        .route("/api/health", get(|| async { "ok" }))
        .nest("/api/auth", auth::routes())
        .nest("/api/dashboard", dashboard::routes())
        .nest("/api/inbounds", inbounds::routes())
        .nest("/api/keygen", keygen::routes())
        // Two parallel mounts for clients — same DB rows, two URL styles:
        //   * `/api/inbounds/{inbound_id}/clients` — nested, inbound is
        //     context. Used by the inbound-modal Clients tab where the
        //     operator is already focused on one inbound.
        //   * `/api/clients` — global, inbound_id passed in query or body.
        //     Used by the top-level Clients page for cross-inbound list,
        //     filter, and bulk operations.
        .nest("/api/inbounds/{inbound_id}/clients", clients::routes())
        .nest("/api/clients", clients::routes_global())
        .nest("/api/logs", logs::routes())
        .nest("/api/outbounds", outbounds::routes())
        .nest("/api/settings", settings::routes())
        // Public subscription URL — no `/api/` prefix because client
        // apps (v2rayN, Hiddify, sing-box, NekoBox) pull from a bare
        // URL with no JWT in scope. Token is the credential.
        .nest("/sub", subscription::routes())
        .nest("/api/xray", xray::routes())
        // Frontend SPA fallback — catches everything not claimed by an `/api/*`
        // nest above. Added BEFORE `.with_state` so it can extract `State` to
        // read the mount prefix and stamp the right `<base href>` into the
        // served index.html. In dev mode the embedded assets directory may be
        // empty (Vite serves the live frontend on :5173 directly), so hitting /
        // on :8080 in dev returns a "frontend assets not embedded" 500 — that's
        // intentional, browse via the Vite dev server.
        .fallback(static_assets::serve)
        .with_state(state)
}
