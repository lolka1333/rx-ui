-- Per-client traffic quota.
--
-- `traffic_limit_bytes` is the hard cap in bytes; NULL means no limit.
-- When `uplink_total + downlink_total` crosses the limit, the stats
-- poller flips the client to disabled and tells xray to drop the user
-- so further bytes are physically refused, not just hidden from the UI.
--
-- `disabled_reason` records WHY the client is off:
--   * NULL      — currently enabled (or never disabled)
--   * 'manual'  — the operator clicked the toggle / saved with off
--   * 'quota'   — the poller hit the cap and disabled it
-- The distinction matters for "reset traffic" UX: a quota-disabled
-- client should come back on once the counter is cleared, but a
-- manually-disabled one should stay off until the operator says so.
-- Without the column we'd have no way to tell which case we're in.

ALTER TABLE clients ADD COLUMN traffic_limit_bytes INTEGER;
ALTER TABLE clients ADD COLUMN disabled_reason TEXT;
