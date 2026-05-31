-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT NOT NULL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Settings (key-value store for panel config)
CREATE TABLE IF NOT EXISTS settings (
    key TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Inbounds: stored independently from xray's config.json, panel rewrites the file on apply
CREATE TABLE IF NOT EXISTS inbounds (
    id TEXT NOT NULL PRIMARY KEY,
    tag TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    protocol TEXT NOT NULL,
    listen TEXT NOT NULL DEFAULT '0.0.0.0',
    port INTEGER NOT NULL,
    -- Full inbound JSON (settings, streamSettings, sniffing)
    config_json TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_inbounds_tag ON inbounds(tag);
CREATE INDEX IF NOT EXISTS idx_inbounds_enabled ON inbounds(enabled);

-- Clients for VLESS inbounds (one inbound can have multiple clients)
CREATE TABLE IF NOT EXISTS clients (
    id TEXT NOT NULL PRIMARY KEY,
    inbound_id TEXT NOT NULL,
    email TEXT NOT NULL,
    uuid TEXT NOT NULL,
    flow TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    traffic_limit_bytes INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE,
    UNIQUE (inbound_id, email)
);

CREATE INDEX IF NOT EXISTS idx_clients_inbound ON clients(inbound_id);

-- Traffic stats snapshots (collected from xray stats API)
CREATE TABLE IF NOT EXISTS traffic_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_at TEXT NOT NULL DEFAULT (datetime('now')),
    scope TEXT NOT NULL, -- 'inbound:<tag>' or 'user:<email>' or 'outbound:<tag>'
    uplink_bytes INTEGER NOT NULL DEFAULT 0,
    downlink_bytes INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_traffic_scope_time ON traffic_snapshots(scope, snapshot_at);
