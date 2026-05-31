-- TLS security mode (alongside existing none/reality). Adds the cert+key
-- material as inline PEM blobs and the most-tweaked TLS knobs. We
-- intentionally do NOT support cert/key files on disk (no certificate_path
-- in the proto layer) — the panel stores the PEM directly in the DB so a
-- backup is self-contained. ACME / autorenew is deferred to a later
-- iteration; operators paste their own certs (Let's Encrypt via certbot,
-- self-signed for testing, etc.).
--
-- Field semantics mirror xray-core's `transport/internet/tls/Config`:
--   tls_cert_pem            — PEM-encoded certificate (full chain, fullchain.pem)
--   tls_key_pem             — PEM-encoded private key (privkey.pem)
--   tls_server_name         — overrides client SNI for cert selection; empty = auto
--   tls_alpn                — JSON array of ALPN strings (e.g. ["h2","http/1.1"])
--   tls_min_version         — "1.0" | "1.1" | "1.2" | "1.3"; empty = xray default "1.2"
--   tls_reject_unknown_sni  — 0/1; if true, drop the connection rather than
--                             returning a cert for unmatched SNI (helps avoid
--                             accidentally exposing internal hostnames)
--
-- All nullable — only the `tls_cert_pem`/`tls_key_pem` pair becomes
-- mandatory at validation time when security='tls'.

ALTER TABLE inbounds ADD COLUMN tls_cert_pem TEXT;
ALTER TABLE inbounds ADD COLUMN tls_key_pem TEXT;
ALTER TABLE inbounds ADD COLUMN tls_server_name TEXT;
ALTER TABLE inbounds ADD COLUMN tls_alpn TEXT;
ALTER TABLE inbounds ADD COLUMN tls_min_version TEXT;
ALTER TABLE inbounds ADD COLUMN tls_reject_unknown_sni INTEGER;
