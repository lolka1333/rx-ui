-- Subscription-level settings on the singleton `panel_settings` row.
--
-- `sub_host_override`: when non-empty, the public `/sub/{token}` endpoint
-- substitutes this hostname into every share-link inside the bundle
-- instead of the auto-detected IPv4/IPv6 of the host. Use case: panel
-- runs on one IP but operator wants subscriptions to point clients at a
-- CDN-fronted hostname (or a different IP for traffic reasons). Empty
-- string ≡ keep the auto-detect behaviour.
--
-- `sub_update_interval_hours`: value the subscription response emits as
-- the `Profile-Update-Interval` header; clients use it to schedule
-- background refresh. 12 was the historical hardcoded value — keeping
-- it as the default means an upgrade is a no-op until the operator
-- changes it through the UI.

ALTER TABLE panel_settings
    ADD COLUMN sub_host_override TEXT NOT NULL DEFAULT '';

ALTER TABLE panel_settings
    ADD COLUMN sub_update_interval_hours INTEGER NOT NULL DEFAULT 12;
