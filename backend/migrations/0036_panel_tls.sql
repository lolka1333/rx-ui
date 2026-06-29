-- Operator-provided HTTPS for the panel's own web server. When enabled and a
-- valid certificate + private key are present, the panel serves its existing
-- port over TLS instead of plain HTTP. TLS is bound at process startup, so a
-- change here takes effect on the next panel restart (the cert/key are also
-- validated at save time, and a malformed pair falls back to plain HTTP at boot
-- rather than locking the operator out).
--
-- The cert is public; the private key is stored inline (same convention as the
-- inbound TLS certs in security/tls.rs) but never echoed back to the client by
-- GET /api/settings/panel — the UI only learns whether a key is set.
ALTER TABLE panel_settings ADD COLUMN panel_tls_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_settings ADD COLUMN panel_tls_cert TEXT NOT NULL DEFAULT '';
ALTER TABLE panel_settings ADD COLUMN panel_tls_key TEXT NOT NULL DEFAULT '';
