-- Per-inbound lifetime traffic, persisted across xray / panel restarts — the
-- inbound analogue of `outbound_traffic`. Keyed by the inbound tag, so the
-- Inbounds page can show an accurate per-inbound total instead of the old
-- front-end approximation (which credited a shared client's whole per-email
-- total to a single inbound, misattributing traffic when one client spans
-- several inbounds).
--
-- xray's per-inbound counters (`inbound>>>{tag}>>>traffic>>>*`, enabled by
-- `policy.system.statsInbound*`) are session-only — they reset to zero on
-- every xray restart. A background poller folds the per-tick deltas into this
-- table so the totals survive restarts, exactly like `outbound_traffic`.
CREATE TABLE IF NOT EXISTS inbound_traffic (
    tag            TEXT PRIMARY KEY NOT NULL,
    uplink_total   INTEGER NOT NULL DEFAULT 0,
    downlink_total INTEGER NOT NULL DEFAULT 0,
    updated_at     TEXT
);
