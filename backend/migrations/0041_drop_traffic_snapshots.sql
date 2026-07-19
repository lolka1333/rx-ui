-- `traffic_snapshots` was created by 0001_init and never read or written: the
-- panel keeps cumulative totals on `clients` and per-tag totals in the
-- `inbound_traffic` (0039) / `outbound_traffic` (0035) tables instead.
-- 0001_init is left untouched — its checksum is recorded in _sqlx_migrations.
DROP INDEX IF EXISTS idx_traffic_scope_time;
DROP TABLE IF EXISTS traffic_snapshots;
