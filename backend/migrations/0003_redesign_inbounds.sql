-- Redesign of `inbounds` table for the gRPC-based pipeline.
--
-- Previous schema (0001_init.sql) stored the entire xray inbound as a single
-- `config_json` blob and applied changes by regenerating the on-disk
-- config.json and restarting xray. The gRPC pipeline talks to xray's
-- HandlerService directly (Add/Remove/Alter), so we want structured columns
-- that the backend can map straight into the proto messages.
--
-- Scope of v1 (intentionally narrow): VLESS protocol only, Reality security
-- only, network = tcp or xhttp. Other protocols/transports stay as TEXT
-- enums for forward compatibility — adding them later is a code change, not
-- a migration.
--
-- The `clients` FK from 0001_init still points at this table; we keep the
-- same primary-key shape (TEXT id) so that FK survives. The clients table
-- itself is unused today and gets its own redesign migration in Phase 2.

DROP INDEX IF EXISTS idx_inbounds_tag;
DROP INDEX IF EXISTS idx_inbounds_enabled;
DROP TABLE IF EXISTS inbounds;

CREATE TABLE inbounds (
    id                       TEXT NOT NULL PRIMARY KEY,
    tag                      TEXT NOT NULL UNIQUE,
    enabled                  INTEGER NOT NULL DEFAULT 1,

    -- Listening socket
    listen                   TEXT NOT NULL DEFAULT '0.0.0.0',
    port                     INTEGER NOT NULL,

    -- Protocol selector. Currently only 'vless' is supported; kept as TEXT so
    -- adding 'vmess'/'trojan' later is purely a code change.
    protocol                 TEXT NOT NULL DEFAULT 'vless',

    -- VLESS-specific knobs. `flow` is '' (none) or 'xtls-rprx-vision'; the
    -- backend rejects vision when network='xhttp' (XTLS Vision works only
    -- over raw TCP). `decryption` is required-but-trivial in VLESS — xray
    -- expects the literal string "none".
    vless_flow               TEXT NOT NULL DEFAULT '',
    vless_decryption         TEXT NOT NULL DEFAULT 'none',

    -- Network: 'tcp' | 'xhttp'. Internally xhttp is the splithttp transport
    -- (xray.transport.internet.splithttp.Config); we expose it under its
    -- user-facing name. Kept TEXT for future 'ws'/'grpc' etc.
    network                  TEXT NOT NULL DEFAULT 'tcp',

    -- Security: only 'reality' for now; column kept for future 'tls'.
    security                 TEXT NOT NULL DEFAULT 'reality',

    -- Reality settings. Always populated while security='reality' is the
    -- only option. Keys are base64-url-encoded x25519 (43 chars, no
    -- padding), matching `xray x25519` CLI output — easier to copy/paste
    -- and won't accidentally leak via SQL logs the way raw bytes would.
    -- `reality_server_names` and `reality_short_ids` are JSON arrays of
    -- strings; SQLite's JSON1 functions cover the few queries we need.
    reality_dest             TEXT NOT NULL,
    reality_server_names     TEXT NOT NULL,
    reality_private_key      TEXT NOT NULL,
    reality_public_key       TEXT NOT NULL,
    reality_short_ids        TEXT NOT NULL,
    reality_fingerprint      TEXT NOT NULL DEFAULT 'chrome',
    reality_xver             INTEGER NOT NULL DEFAULT 0,

    -- XHTTP transport settings. NULL when network='tcp'.
    xhttp_path               TEXT,
    xhttp_host               TEXT,
    xhttp_mode               TEXT,

    -- Operator-visible metadata
    note                     TEXT,
    created_at               TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at               TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_inbounds_tag ON inbounds(tag);
CREATE INDEX idx_inbounds_enabled ON inbounds(enabled);
