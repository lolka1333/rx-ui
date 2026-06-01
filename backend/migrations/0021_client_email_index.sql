-- Standalone index on `clients.email`.
--
-- The stats poller (`client_stats::spawn_poller`) issues
-- `UPDATE clients SET uplink_total = uplink_total + ?, ... WHERE email = ?`
-- once per email per 5-second tick. The existing `UNIQUE (inbound_id,
-- email)` constraint creates a composite index, but SQLite's left-prefix
-- matching means a bare `WHERE email = ?` cannot use it — every poller
-- UPDATE degenerates to a full table scan.
--
-- At a few hundred clients the scan is invisible; at the commercial
-- target of ~100k clients each scan is ~50 ms × tens of thousands of
-- emails → poll ticks miss their 5-second deadline by an order of
-- magnitude. A standalone `email` index turns each UPDATE into an
-- index-seek (O(log N)) and the loop time drops back into ms-range.

CREATE INDEX IF NOT EXISTS idx_clients_email ON clients(email);
