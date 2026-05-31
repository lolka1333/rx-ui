-- Global kill-switch for the public `/sub/{token}` endpoint.
--
-- Set to 0 to make every subscription URL return 404 — same response
-- an invalid token would produce, so an attacker probing the surface
-- can't tell whether subscriptions are deliberately off or whether
-- they just guessed wrong. Individual share-links built from the panel
-- UI keep working; only the aggregated /sub/{token} endpoint is gated.
--
-- Defaults to 1 so existing deployments behave exactly as before.

ALTER TABLE panel_settings
    ADD COLUMN sub_enabled INTEGER NOT NULL DEFAULT 1;
