-- Per-client time-based expiry.
--
-- `expires_at` is an absolute expiry instant stored as a UTC
-- `YYYY-MM-DD HH:MM:SS` string (the `datetime('now')` shape, so it
-- compares directly in SQL); NULL means the client never expires.
-- When `expires_at <= datetime('now')` the stats poller flips the
-- client to disabled and tells xray to drop the user — the same
-- mechanism as the traffic quota, just time-driven instead of
-- byte-driven.
--
-- `disabled_reason = 'expired'` records that the poller (not the
-- operator, not the quota) turned it off, so clearing or extending the
-- date can re-enable the row while leaving manually-disabled ones
-- alone — mirroring how 'quota' behaves for "reset traffic".
--
-- (`expires_at` originally lived on the 0001 schema and was dropped in
-- 0004 as deferred work; this restores it with the now-established
-- poller-enforcement semantics.)

ALTER TABLE clients ADD COLUMN expires_at TEXT;
