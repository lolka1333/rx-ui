-- Three indexes that cost a write each and buy nothing — one of them harmful.
--
-- `idx_clients_enabled` is the harmful one. No query filters clients on
-- `enabled` alone; the hot one is `WHERE inbound_id = ? AND enabled = 1`
-- (`api::clients::load_enabled_clients`), run once per inbound at boot and on
-- every client mutation. With no ANALYZE statistics SQLite picks the boolean
-- index and walks every enabled row: measured on 100k clients across 6
-- inbounds, reading one inbound's 10 clients took 21.5ms with the index and
-- 0.01ms without it, where the plan switches to `idx_clients_inbound`. The
-- cost scales with the TOTAL client count, not with the inbound's own.
--
-- The other two are already covered by a UNIQUE constraint's automatic index:
--   * `idx_clients_inbound(inbound_id)` is a prefix of the index behind
--     `UNIQUE (inbound_id, email)`.
--   * `idx_inbounds_tag(tag)` duplicates the index behind `tag ... UNIQUE`.
-- Both lookups keep their seek through those.
--
-- `IF EXISTS` so this is a no-op on a database that never had them.
DROP INDEX IF EXISTS idx_clients_enabled;
DROP INDEX IF EXISTS idx_clients_inbound;
DROP INDEX IF EXISTS idx_inbounds_tag;
