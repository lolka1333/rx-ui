-- Redesign of `clients` table for Phase 2.
--
-- The original schema in 0001_init.sql defined a `clients` table that was
-- never read or written by the panel — Phase 1 left it as dead structure.
-- Phase 2 actually starts using it, with a slimmed-down v1 column set
-- focused on what's strictly required to push a VLESS user into xray via
-- `HandlerService.AlterInbound + AddUserOperation`:
--
--   * email  — user identifier xray uses for stats/logs.
--   * uuid   — VLESS Account.id (the client's secret).
--   * flow   — optional per-client override of the inbound's vless_flow.
--              NULL means "inherit"; explicit '' or 'xtls-rprx-vision'
--              override the inbound default.
--   * enabled — disabled clients are removed from xray but stay in DB.
--
-- Quota (traffic_limit_bytes) and expiry (expires_at) lived on the 0001
-- table but had no enforcement code. They'll come back in a later migration
-- once we have a stats-poller + scheduled reaper to actually act on them.
-- Dropping them now keeps the schema honest.
--
-- ON DELETE CASCADE: when an inbound is deleted, its clients go with it —
-- mirrors xray's own semantics (RemoveInbound implicitly drops the users).

DROP INDEX IF EXISTS idx_clients_inbound;
DROP TABLE IF EXISTS clients;

CREATE TABLE clients (
    id           TEXT NOT NULL PRIMARY KEY,
    inbound_id   TEXT NOT NULL,
    email        TEXT NOT NULL,
    uuid         TEXT NOT NULL,
    flow         TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    note         TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE,
    UNIQUE (inbound_id, email)
);

CREATE INDEX idx_clients_inbound ON clients(inbound_id);
CREATE INDEX idx_clients_enabled ON clients(enabled);
