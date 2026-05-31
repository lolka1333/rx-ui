-- Persist per-client cumulative traffic across xray / backend restarts.
--
-- xray's `StatsService` is the source of truth for live counters but
-- keeps them strictly in-memory — a restart (intentional config swap,
-- crash, OS reboot) zeroes everything. We sidestep that by having the
-- backend poller accumulate the per-tick deltas straight into these
-- columns; the API then serves `db_total + current_xray_session` so
-- the operator sees a monotonic "since panel deployed" number.
--
-- `traffic_updated_at` is a wall-clock timestamp of the last DB write;
-- the poller only updates the row when a delta is non-zero, so a
-- stale timestamp on a client doubles as "no traffic since X".

ALTER TABLE clients ADD COLUMN uplink_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN downlink_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN traffic_updated_at TEXT;
