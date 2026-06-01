-- Per-inbound sniffing settings + opening the `security` column to `none`.
--
-- Before this migration `sniffing` was hard-coded in `inbound_proto.rs`
-- (always enabled with `["http","tls","fakedns"]`). That worked for the
-- common case but didn't let the operator turn sniffing off for an
-- inbound where it would either be wasted CPU (e.g. a forwarding-only
-- inbound) or actively harmful (a router needs the raw destination, not
-- the sniffed one).
--
-- `security` was already a TEXT column with the implicit value 'reality'.
-- We don't need a schema change to add 'none' as a legal value — only the
-- defaults below acknowledge that 'reality' will continue to be the
-- preferred choice for new rows.

ALTER TABLE inbounds
    ADD COLUMN sniffing_enabled INTEGER NOT NULL DEFAULT 1;

-- JSON array of strings: subset of ['http','tls','fakedns','quic'].
-- Stored as TEXT because sqlite has no first-class arrays; SQLite's JSON1
-- functions handle the few queries that may need to inspect this.
ALTER TABLE inbounds
    ADD COLUMN sniffing_dest_override TEXT NOT NULL DEFAULT '["http","tls","fakedns"]';
