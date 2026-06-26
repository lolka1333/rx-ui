-- Per-outbound lifetime traffic, persisted across xray / panel restarts — the
-- outbound analogue of `clients.uplink_total` / `downlink_total`. Keyed by the
-- outbound tag, so it covers both custom outbounds and the built-ins
-- (direct / blocked / direct-ipv4).
--
-- xray's per-outbound counters are session-only (they reset to zero on every
-- xray restart). A background poller folds the per-tick deltas into this table
-- so the totals shown on the Outbounds page survive restarts, the same way the
-- per-client counters do.
CREATE TABLE IF NOT EXISTS outbound_traffic (
    tag            TEXT PRIMARY KEY NOT NULL,
    uplink_total   INTEGER NOT NULL DEFAULT 0,
    downlink_total INTEGER NOT NULL DEFAULT 0,
    updated_at     TEXT
);
