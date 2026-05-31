mod api;
mod auth;
mod db;
mod error;
mod host;
mod logs;
mod models;
// Trait-based protocol / transport / security modules. The orchestrator
// (`xray::orchestrator`) composes one of each per inbound; the Inbound
// row carries one tagged-enum per layer as JSON-blob columns.
mod protocols;
mod security;
mod static_assets;
mod traffic;
mod transports;
mod xray;

use crate::{
    auth::JwtKeys,
    db::DbPool,
    host::HostMonitor,
    logs::LogBuffer,
    xray::{XrayClient, XrayController, grpc},
};
use axum::extract::FromRef;
use std::{
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};
use tokio::sync::{RwLock, oneshot};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub jwt: JwtKeys,
    pub xray: XrayController,
    pub xray_client: XrayClient,
    pub host: HostMonitor,
    pub logs: LogBuffer,
    pub traffic: traffic::TrafficStore,
    /// URL prefix the panel currently serves under. Read by the
    /// `prefix_strip_middleware` on every request; updated atomically
    /// when the operator saves new settings, so a path change takes
    /// effect on the very next request (no restart needed).
    pub base_path: Arc<RwLock<String>>,
    /// Port the currently-active TCP listener is bound to. Used by
    /// the settings handler to decide whether a port change needs a
    /// listener re-bind, and surfaced for logging.
    pub current_port: Arc<AtomicU16>,
    /// `oneshot::Sender` that signals the current listener task to
    /// gracefully shut down. Replaced (and the old handle dropped /
    /// scheduled for shutdown) when a new listener takes over.
    pub listener_shutdown: Arc<RwLock<Option<oneshot::Sender<()>>>>,
    /// Port of the optional sub-only listener (`0` = not running).
    /// Mirrors `current_port` semantics — the settings handler reads
    /// this to decide between spawn / shutdown / rebind on each PUT.
    pub current_sub_port: Arc<AtomicU16>,
    /// Shutdown handle for the sub-only listener task. `None` when
    /// `current_sub_port == 0`; populated after a successful spawn.
    pub sub_listener_shutdown: Arc<RwLock<Option<oneshot::Sender<()>>>>,
}

impl FromRef<AppState> for DbPool {
    fn from_ref(s: &AppState) -> Self {
        s.db.clone()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    // Compose two tracing layers: the standard stdout fmt + our in-memory
    // ring buffer so `/api/logs` can serve recent entries to the panel UI.
    let log_buffer = LogBuffer::new();
    // If RUST_LOG is set but unparseable, surface that on stderr — tracing
    // isn't initialised yet so we can't `tracing::warn!`. Without this, a
    // typo in RUST_LOG silently falls back to "info" and the operator never
    // sees why their filter didn't take effect.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|e| {
        if std::env::var_os("RUST_LOG").is_some() {
            eprintln!("RUST_LOG is set but failed to parse ({e}); falling back to 'info'");
        }
        EnvFilter::new("info")
    });
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().compact())
        .with(logs::BufferLayer {
            buffer: log_buffer.clone(),
        })
        .init();

    // Default: SQLite file next to the working directory. On a Linux server
    // this means `<cwd>/data/panel.db` — no hand-tweaked absolute paths, the
    // same binary works on Windows and Linux.
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://data/panel.db".to_string());
    // Resolve the JWT signing secret. Tries (in order): env var,
    // persisted `data/jwt_secret` file, or generates a fresh one and
    // writes it there. The "zero-config first run" path lets an
    // operator double-click the .exe and have it just work — same
    // pattern as Caddy / Gitea / n8n use.
    let jwt_secret = resolve_or_generate_jwt_secret(std::path::Path::new("data"))?;
    // xray + geofiles + config live next to the panel by default. Auto-install
    // on first run drops them into ./data/xray/. Override with env vars to use
    // a system-wide xray (e.g. /usr/local/bin/xray managed by systemd).
    let (xray_binary, xray_config) = resolve_xray_paths();
    let host = std::env::var("PANEL_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    // The env var still wins for bootstrap purposes (first ever start,
    // before any DB row exists) but on second-and-later starts the DB
    // value loaded just below takes priority. This keeps the existing
    // env-driven workflow working while giving operators a UI to flip
    // the port without editing files on disk.
    let env_port: u16 = std::env::var("PANEL_PORT")
        .ok()
        .and_then(|s| u16::from_str(&s).ok())
        .unwrap_or(8080);

    let db = db::init_pool(&database_url).await?;
    bootstrap_admin(&db).await?;

    // Read DB-stored runtime settings (panel port + URL prefix +
    // optional sub-port). Falls back to env-derived port and empty
    // prefix if the row is missing or malformed —
    // see `settings::load_for_boot`.
    let (db_port, base_path, db_sub_port) = api::settings::load_for_boot(&db).await;
    let port = if db_port == 8080 { env_port } else { db_port };

    let state = AppState {
        db,
        jwt: JwtKeys::from_secret(&jwt_secret),
        xray: XrayController::new(xray_binary, xray_config, log_buffer.clone()),
        xray_client: XrayClient::new(grpc::DEFAULT_ENDPOINT),
        host: HostMonitor::spawn(),
        logs: log_buffer,
        traffic: traffic::TrafficStore::new(),
        base_path: Arc::new(RwLock::new(base_path.clone())),
        current_port: Arc::new(AtomicU16::new(port)),
        listener_shutdown: Arc::new(RwLock::new(None)),
        current_sub_port: Arc::new(AtomicU16::new(0)),
        sub_listener_shutdown: Arc::new(RwLock::new(None)),
    };

    // Attach to a running xray, or lay down the bootstrap config and start
    // one. Failure here is logged but does not abort the panel — login still
    // works and the operator can diagnose via `/api/logs` and `/api/xray/*`.
    if let Err(e) = xray::reload::bootstrap(&state).await {
        tracing::warn!("xray bootstrap skipped: {e}");
    }

    // Start the per-user traffic + online poll. Runs every 5 s,
    // populates `state.traffic` from xray's StatsService. The REST
    // handler reads the latest snapshot under a short read lock.
    traffic::spawn_traffic_poller(
        state.xray_client.clone(),
        state.traffic.clone(),
        state.db.clone(),
    );

    // Reconcile in-memory xray state with the panel DB. xray's
    // HandlerService stores inbounds in memory only — every cold start
    // (panel boot, xray crash + supervisor restart) needs us to push the
    // enabled rows back in. We run this in a tokio task so a slow gRPC dial
    // doesn't delay the HTTP listener coming up.
    let reconcile_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = reconcile_inbounds_with_xray(&reconcile_state).await {
            tracing::error!("xray reconciliation failed: {e}");
        }
    });

    // Build the router once. URL prefix is applied dynamically via the
    // `prefix_strip_middleware` reading `state.base_path` on every
    // request — that way an operator changing the prefix takes effect
    // on the next request without rebuilding the router. Port changes
    // do still need a fresh `TcpListener`; for that we spawn a new
    // listener task and let the old one finish in-flight requests
    // before shutting down (see `spawn_listener` + the settings
    // handler's port-swap path).
    let app = build_router(state.clone()).await;

    // Bind initial listener and stash its shutdown channel so the
    // settings handler can later swap it for a new one.
    let initial_tx = api::settings::spawn_listener(&host, port, app).await?;
    *state.listener_shutdown.write().await = Some(initial_tx);
    let display_path = if base_path.is_empty() {
        "/"
    } else {
        base_path.as_str()
    };
    tracing::info!("backend listening on http://{host}:{port}{display_path}");

    // Optional sub-only listener — bound only when the operator has
    // configured a non-zero sub_port. Bind failures (port in use,
    // permission denied) are logged but don't kill the whole panel —
    // the main listener still works and the operator can fix the port
    // from the UI.
    if let Ok(sub_port) = u16::try_from(db_sub_port)
        && sub_port != 0
    {
        match api::settings::spawn_listener(&host, sub_port, build_sub_router(state.clone())).await
        {
            Ok(tx) => {
                *state.sub_listener_shutdown.write().await = Some(tx);
                state.current_sub_port.store(sub_port, Ordering::Relaxed);
                tracing::info!("subscription listener on http://{host}:{sub_port}/sub/<token>");
            }
            Err(e) => {
                tracing::warn!("failed to bind subscription listener on port {sub_port}: {e}");
            }
        }
    }

    // Main thread blocks on ctrl-c. The HTTP listener lives in a
    // separate task spawned by `spawn_listener`, which lets the
    // settings handler swap listener tasks at runtime without ever
    // touching this main future.
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");
    // Take the shutdown sender out of the lock in a separate statement
    // — holding the `RwLockWriteGuard` across the `tx.send(())` would
    // pin the lock across a `.await`-free but still significant
    // `Drop`, which clippy flags as a potential dead-lock surface
    // (`significant_drop_in_scrutinee`). The take-then-send pattern
    // releases the lock the moment we have ownership of the sender.
    let shutdown_tx = state.listener_shutdown.write().await.take();
    if let Some(tx) = shutdown_tx {
        let _ = tx.send(());
    }
    let sub_shutdown_tx = state.sub_listener_shutdown.write().await.take();
    if let Some(tx) = sub_shutdown_tx {
        let _ = tx.send(());
    }
    Ok(())
}

/// Resolve the xray binary + bootstrap-config paths. Defaults to the
/// auto-install location under `data/xray/`; `XRAY_BINARY` / `XRAY_CONFIG`
/// override for a system-managed xray (e.g. `/usr/local/bin/xray`).
fn resolve_xray_paths() -> (PathBuf, PathBuf) {
    let install_dir = xray::installer::default_install_dir(std::path::Path::new("data"));
    let xray_binary = PathBuf::from(std::env::var("XRAY_BINARY").unwrap_or_else(|_| {
        install_dir
            .join(xray::installer::binary_name())
            .to_string_lossy()
            .into_owned()
    }));
    let xray_config = PathBuf::from(std::env::var("XRAY_CONFIG").unwrap_or_else(|_| {
        install_dir
            .join("config.json")
            .to_string_lossy()
            .into_owned()
    }));
    (xray_binary, xray_config)
}

/// Build the public-facing axum router with the URL prefix mounted
/// statically.
///
/// Called once at boot, and again from the settings handler
/// on every path / port change — we never modify a running router
/// instance, we build a fresh one and hand it to a new TCP listener
/// task. The static-nest approach gives axum the well-trodden routing
/// path it knows how to match against; dynamic URI rewriting in a
/// layer behaved oddly with the SPA fallback in axum 0.8.
pub async fn build_router(state: AppState) -> axum::Router {
    let inner = api::router(state.clone());
    let base_path = state.base_path.read().await.clone();
    let routed = if base_path.is_empty() {
        inner
    } else {
        axum::Router::new().nest(&base_path, inner)
    };
    let mut app = routed.layer(TraceLayer::new_for_http());
    if cfg!(debug_assertions) {
        app = app.layer(CorsLayer::permissive());
    }
    app
}

/// Build a stripped-down router for the optional sub-only listener.
///
/// Same `/sub/{token}` handler the main port serves, plus the SPA
/// static fallback (so a browser visit to `:sub-port/sub/X` lands on
/// the React landing page) — but no `/api/*` routes, so the admin
/// surface stays off this listener. URL prefix is intentionally
/// ignored: the sub-port exists exactly to give the public endpoint a
/// stable, predictable address.
pub fn build_sub_router(state: AppState) -> axum::Router {
    let app = axum::Router::new()
        .nest("/sub", api::subscription::routes())
        .with_state(state)
        .fallback_service(static_assets::router())
        .layer(TraceLayer::new_for_http());
    if cfg!(debug_assertions) {
        app.layer(CorsLayer::permissive())
    } else {
        app
    }
}

/// Resolution order:
///   1. `JWT_SECRET` env var — honour explicit operator config. Bail
///      with a clear message if it's set but too short.
///   2. `<data>/jwt_secret` file — re-use across restarts so sessions
///      survive panel reboots. Already-issued JWTs stay valid.
///   3. Generate fresh 32 bytes (64 hex chars) via OS-RNG, write to
///      `<data>/jwt_secret`, log a one-time notice. On Unix the file
///      gets mode 0600.
///
/// The "zero-config first run" lets the binary Just Work after a
/// single download — same UX as Caddy/Gitea/n8n. Operators
/// who care can still pre-set `JWT_SECRET` env or pre-write the file
/// (e.g. for clustered/secrets-managed deployments).
///
/// To rotate the secret: delete the file and restart. All existing
/// session tokens are immediately invalidated (next API call → 401 →
/// frontend logs out gracefully).
fn resolve_or_generate_jwt_secret(data_dir: &std::path::Path) -> anyhow::Result<String> {
    use rand::RngCore as _;
    use std::fmt::Write as _;

    const MIN_LEN: usize = 32;

    if let Ok(env_val) = std::env::var("JWT_SECRET") {
        if env_val.len() < MIN_LEN {
            anyhow::bail!(
                "JWT_SECRET env var is too short ({} chars, need {}+). \
                 Either set a longer value, or UNSET it to let the panel \
                 auto-generate one into {}/jwt_secret.",
                env_val.len(),
                MIN_LEN,
                data_dir.display()
            );
        }
        return Ok(env_val);
    }

    let secret_file = data_dir.join("jwt_secret");
    if secret_file.exists() {
        let s = std::fs::read_to_string(&secret_file)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", secret_file.display()))?
            .trim()
            .to_owned();
        if s.len() >= MIN_LEN {
            return Ok(s);
        }
        tracing::warn!(
            "{} exists but is too short ({} chars) — regenerating",
            secret_file.display(),
            s.len()
        );
    }

    // Fresh generation. 32 bytes from OS-RNG → 64 hex chars (256 bits
    // of entropy, well above HS256's 128-bit security target). Writing
    // into a pre-sized `String` via `write!` avoids the 32 transient
    // `String` allocations a `.map(format!).collect()` would produce.
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        let _ = write!(hex, "{b:02x}");
    }

    if let Some(parent) = secret_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(&secret_file, &hex)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", secret_file.display()))?;
    // chmod 600 on Unix; Windows ACL is left at the default
    // (typically inherits from parent dir, which is fine for a
    // single-user self-hosted panel).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&secret_file, perms)
            .map_err(|e| anyhow::anyhow!("chmod {}: {e}", secret_file.display()))?;
    }

    tracing::warn!(
        "Generated fresh JWT_SECRET (saved to {}). \
         Sessions will persist across panel restarts. \
         Delete the file to rotate (invalidates all live tokens).",
        secret_file.display()
    );
    Ok(hex)
}

/// Push every `enabled=1` inbound from the panel DB into the running xray
/// via `HandlerService.AddInbound`. xray keeps handler state in memory, so
/// this must run after every xray (re)start; otherwise the panel and xray
/// would silently disagree about what's listening.
///
/// Failures on individual inbounds are logged but don't abort the loop —
/// one broken row (e.g. corrupt JSON in `protocol_config`) shouldn't stop
/// the other inbounds from coming up. The operator sees the error in
/// `/api/logs` and can fix or delete the bad row.
async fn reconcile_inbounds_with_xray(state: &AppState) -> anyhow::Result<()> {
    let rows = sqlx::query!(
        r#"SELECT id, tag, enabled, listen, port,
                  protocol_config, transport_config, security_config, sniffing_config,
                  finalmask_config, sockopt_config, created_at, updated_at
           FROM inbounds WHERE enabled = 1"#
    )
    .fetch_all(&state.db)
    .await?;

    let total = rows.len();
    let mut pushed = 0usize;
    for r in rows {
        // Parse the five typed blobs. Any failure is a per-row skip
        // with a warning so a single corrupt row can't block the rest.
        let Some(inb) = hydrate_inbound_row(ReconcileRow {
            id: &r.id,
            tag: &r.tag,
            enabled: r.enabled,
            listen: r.listen.clone(),
            port: r.port,
            protocol_config: &r.protocol_config,
            transport_config: &r.transport_config,
            security_config: &r.security_config,
            sniffing_config: &r.sniffing_config,
            finalmask_config: &r.finalmask_config,
            sockopt_config: &r.sockopt_config,
            created_at: r.created_at.clone(),
            updated_at: r.updated_at.clone(),
        }) else {
            continue;
        };
        // Pull enabled clients in a separate per-inbound query — keeps
        // the reconciliation join-free and lets a client-query failure
        // skip just one inbound instead of poisoning the whole reload.
        let clients = match crate::api::inbounds::load_enabled_clients(&state.db, &inb.id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("inbound tag={} client query failed, skipping: {e}", r.tag);
                continue;
            }
        };
        let handler = match xray::orchestrator::inbound_to_handler_config(&inb, &clients) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("inbound tag={} proto build failed, skipping: {e}", r.tag);
                continue;
            }
        };
        // Idempotency: when the panel restarts but xray is already
        // running (we attached to it via `XrayController::attach_or_start`),
        // the previous panel session's inbounds are still in xray's
        // in-memory handler map. A naive AddInbound would 409 with
        // "existing tag found"; remove-first guarantees we converge
        // xray's state to the current DB regardless of what was there
        // before. The remove is best-effort — a fresh xray instance has
        // nothing to remove.
        let _ = state.xray_client.remove_inbound(&r.tag).await;
        match state.xray_client.add_inbound(handler).await {
            Ok(()) => pushed += 1,
            Err(e) => tracing::warn!("inbound tag={} AddInbound failed: {e}", r.tag),
        }
    }

    tracing::info!("xray reconciliation: pushed {pushed}/{total} enabled inbounds");
    Ok(())
}

/// Per-row arguments mirror of the `SELECT … FROM inbounds` shape used
/// by `reconcile_inbounds_with_xray`. Keeps the helper's signature
/// independent of the anonymous record type `sqlx::query`! generates.
struct ReconcileRow<'a> {
    id: &'a str,
    tag: &'a str,
    enabled: i64,
    listen: String,
    port: i64,
    protocol_config: &'a str,
    transport_config: &'a str,
    security_config: &'a str,
    sniffing_config: &'a str,
    finalmask_config: &'a str,
    sockopt_config: &'a str,
    created_at: String,
    updated_at: String,
}

/// Parse one DB row into a typed `Inbound`. A failed JSON deserialise
/// returns `None`; the caller logs and skips that row so a single
/// corrupt blob (e.g. partially-written column from a crash) can't
/// stall the whole reconciliation.
fn hydrate_inbound_row(r: ReconcileRow<'_>) -> Option<crate::models::Inbound> {
    fn parse_json<T: serde::de::DeserializeOwned>(tag: &str, col: &str, raw: &str) -> Option<T> {
        match serde_json::from_str(raw) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("inbound tag={tag} bad {col}, skipping: {e}");
                None
            }
        }
    }
    let protocol = parse_json(r.tag, "protocol_config", r.protocol_config)?;
    let transport = parse_json(r.tag, "transport_config", r.transport_config)?;
    let security = parse_json(r.tag, "security_config", r.security_config)?;
    let sniffing = parse_json(r.tag, "sniffing_config", r.sniffing_config)?;
    let finalmask = parse_json(r.tag, "finalmask_config", r.finalmask_config)?;
    let sockopt = parse_json(r.tag, "sockopt_config", r.sockopt_config)?;
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let port = r.port as u16;
    Some(crate::models::Inbound {
        id: r.id.to_owned(),
        tag: r.tag.to_owned(),
        enabled: r.enabled != 0,
        listen: r.listen,
        port,
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

async fn bootstrap_admin(db: &DbPool) -> anyhow::Result<()> {
    let count = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await?;
    if count == 0 {
        let id = uuid::Uuid::new_v4().to_string();
        // Treat an empty or whitespace-only `ADMIN_INITIAL_PASSWORD` the same
        // as unset — otherwise a misconfigured `.env` (`ADMIN_INITIAL_PASSWORD=`
        // or `ADMIN_INITIAL_PASSWORD="   "`) silently creates an admin with a
        // blank/whitespace password that argon2 happily hashes but no one can
        // type at the login form.
        let env_password = std::env::var("ADMIN_INITIAL_PASSWORD")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let password = env_password.as_deref().unwrap_or("admin");
        let hash = crate::auth::hash_password(password)?;
        sqlx::query!(
            "INSERT INTO users (id, username, password_hash, is_admin) VALUES (?, 'admin', ?, 1)",
            id,
            hash
        )
        .execute(db)
        .await?;
        if env_password.is_some() {
            tracing::warn!(
                "created admin user 'admin' with password from ADMIN_INITIAL_PASSWORD — change it via the panel"
            );
        } else {
            tracing::warn!(
                "created default admin user (username='admin', password='admin') — change it immediately via the panel"
            );
        }
    }
    Ok(())
}
