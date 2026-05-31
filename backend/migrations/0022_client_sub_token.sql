-- Per-client subscription token. Public `GET /sub/{token}` resolves to
-- the client row, then aggregates all share-links for that client's
-- email across every inbound — that's how one URL maps to "all my
-- configs" in v2rayN / Hiddify / NekoBox / sing-box.
--
-- Each row gets its own token so the operator can rotate one URL
-- independently. The aggregation-by-email at read time means a row
-- created later in another inbound is automatically picked up by the
-- existing token (the client app pulls the bundle on every refresh).
--
-- Token is a 32-char hex string (16 random bytes). Backfill uses
-- SQLite's `randomblob` + `hex`, which is good enough for existing
-- rows; new rows get RNG-generated tokens from the application side.

ALTER TABLE clients ADD COLUMN sub_token TEXT NOT NULL DEFAULT '';
UPDATE clients SET sub_token = lower(hex(randomblob(16))) WHERE sub_token = '';

-- Lookup index for the subscription endpoint — `WHERE sub_token = ?`
-- has to be O(log n) since the URL is public-facing and untrusted
-- requesters could hammer it; full scan would be a trivial DoS.
CREATE UNIQUE INDEX idx_clients_sub_token ON clients (sub_token);
