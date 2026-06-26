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
        .busy_timeout(Duration::from_secs(5));

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

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
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
