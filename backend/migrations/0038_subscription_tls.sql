-- Independent TLS for the dedicated subscription listener, decoupled from the
-- panel's own HTTPS. Three modes:
--   * 'inherit' (default) — serve /sub over the panel's cert, preserving the
--     existing behaviour (direct access, no proxy in front).
--   * 'off' — serve /sub over plain HTTP. For deployments that publish the
--     subscription behind a CDN / tunnel (e.g. a Cloudflare tunnel routing only
--     `host/sub`) which terminates TLS at the edge, so the origin should be HTTP.
--   * 'custom' — serve /sub with a separate cert/key, independent of the panel
--     (e.g. a cert for a dedicated subscription hostname).
--
-- Same storage convention as panel_tls_* (0036): the cert is public and
-- round-tripped to the UI; the private key is stored inline but never echoed
-- back by GET /api/settings/panel (the UI only learns whether a key is set).
-- TLS binds when the sub listener (re)spawns, so a change applies on the next
-- settings save (the listener swaps) or panel restart.
ALTER TABLE panel_settings ADD COLUMN sub_tls_mode TEXT NOT NULL DEFAULT 'inherit';
ALTER TABLE panel_settings ADD COLUMN sub_cert_pem TEXT NOT NULL DEFAULT '';
ALTER TABLE panel_settings ADD COLUMN sub_key_pem TEXT NOT NULL DEFAULT '';
