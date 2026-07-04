use anyhow::Context;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::str::FromStr;
use std::time::Duration;

pub type DbPool = SqlitePool;

/// Open the `SQLite` pool, creating the file (and its parent directory) if
/// missing, then run embedded migrations. Works identically on Windows and
/// Linux — no manual `sqlx database create`, no `?mode=rwc` URL hack.
pub async fn init_pool(database_url: &str) -> anyhow::Result<DbPool> {
    let opts = SqliteConnectOptions::from_str(database_url)
        .with_context(|| format!("invalid DATABASE_URL: {database_url}"))?
        .create_if_missing(true)
        .foreign_keys(true)
        // WAL lets the 5s traffic-poller commit run without blocking the
        // dashboard / auth / subscription reads (writer and readers stop
        // serialising); busy_timeout makes a contended write wait instead of
        // failing instantly with SQLITE_BUSY; synchronous=NORMAL is the safe WAL
        // pairing (fsync at checkpoint, not on every commit). This is what keeps
        // the panel responsive as the client count climbs.
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        // Cap each connection's page cache at ~1 MB (SQLite defaults to ~2 MB).
        // The working set is small — indexed lookups on clients/inbounds — so a
        // smaller cache barely moves query latency but halves the per-connection
        // memory the pool holds across all its connections.
        .pragma("cache_size", "-1024");

    // sqlite won't auto-create the directory, only the file.
    let path = opts.get_filename().to_path_buf();
    if path.as_os_str() != ":memory:"
        && let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create db dir {}", parent.display()))?;
    }

    // 5 minutes. The nursery `duration_suboptimal_units` lint wants a coarser
    // unit here, but stable `Duration` has no `from_mins` to give it.
    #[allow(clippy::duration_suboptimal_units)]
    let idle_timeout = Duration::from_secs(300);
    let pool = SqlitePoolOptions::new()
        // Keep the ceiling high enough for concurrent reads: the public
        // subscription / stats endpoints can be hit by many clients at once and
        // WAL runs those reads in parallel, so starving the pool would cap
        // throughput as the client count climbs. Per-connection memory is
        // trimmed via the smaller `cache_size` above (not by shrinking the
        // pool), and `idle_timeout` lets connections opened during a burst close
        // again so the pool shrinks back while the panel is quiet.
        .max_connections(8)
        .idle_timeout(idle_timeout)
        .connect_with(opts)
        .await
        .context("failed to open database")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("failed to run migrations")?;

    tracing::info!("database ready: {}", path.display());
    Ok(pool)
}
