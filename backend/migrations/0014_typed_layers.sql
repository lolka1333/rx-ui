-- Switch the inbound schema from ~80 flat columns to four typed JSON
-- blobs (protocol / transport / security / sniffing). Mirrors the new
-- backend module layout in `protocols/`, `transports/`, `security/`:
-- each blob is a tagged enum (`{"kind": "...", ...}`) describing one
-- layer of the stream config. Adding a new protocol or transport is
-- now a Rust-level change with zero schema work.
--
-- The migration is non-destructive — old flat columns stay so the
-- legacy in-flight code paths keep working until the swap commit lands
-- in the application layer. A follow-up migration (when we're confident
-- nothing reads them) will drop the legacy columns.
--
-- Empty-string default on the three "_config" blobs is a deliberate
-- "not yet backfilled" sentinel — the startup backfill in
-- `models::inbound_typed_backfill` rewrites every row that still has
-- the sentinel by re-encoding the row's flat columns through the new
-- typed structs. After backfill all rows have valid JSON; reads from
-- empty values are treated as a panic-worthy bug.

ALTER TABLE inbounds ADD COLUMN protocol_config TEXT NOT NULL DEFAULT '';
ALTER TABLE inbounds ADD COLUMN transport_config TEXT NOT NULL DEFAULT '';
ALTER TABLE inbounds ADD COLUMN security_config TEXT NOT NULL DEFAULT '';
ALTER TABLE inbounds ADD COLUMN sniffing_config TEXT NOT NULL DEFAULT '{"enabled":true,"dest_override":["http","tls","fakedns"]}';
