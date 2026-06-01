-- Expand TLS surface to a multi-cert array + ECH + auxiliary tuning knobs.
-- Mirrors xray-core's `transport/internet/tls/Config` + `Certificate` shapes
-- canonically; see `infra/conf/transport_internet.go` for the operator-side
-- JSON the panel re-exposes here.
--
-- Cert storage shifts from the single `tls_cert_pem` + `tls_key_pem` pair
-- (migration 0009) to a JSON array `tls_certificates`. Each entry is either
-- an inline PEM blob (`source=inline`) or a filesystem path
-- (`source=path`) — the latter lets an external tool (certbot, vault-agent,
-- etc.) own cert rotation while xray re-reads on disk change.
--
-- Per-cert knobs match xray's `Certificate` proto:
--   usage             — encipherment | verify | issue (server inbounds = enc.)
--   ocsp_stapling     — refresh interval in seconds (0 = disabled)
--   build_chain       — let xray build the chain from system roots
--   one_time_loading  — load once at startup vs. watch the file for change
--                       (only meaningful for source=path)
--
-- Top-level additions:
--   tls_max_version              — upper bound TLS version
--   tls_cipher_suites            — TLS 1.2 cipher list (xray syntax)
--   tls_enable_session_resumption— bool, perf
--   tls_master_key_log           — TLS keylog file path (Wireshark debug)
--   tls_ech_server_keys          — base64-encoded ECH (Encrypted Client
--                                  Hello) server key bundle. xray decodes
--                                  with `base64.StdEncoding.DecodeString`.
--
-- Legacy columns `tls_cert_pem` / `tls_key_pem` are NOT dropped — SQLite
-- can't drop columns without a full table rebuild and we want a safe
-- rollback path. They become read-only after this migration backfills
-- their contents into `tls_certificates`. Future cleanup migration may
-- drop them once we're confident no rollback is needed.

ALTER TABLE inbounds ADD COLUMN tls_certificates TEXT NOT NULL DEFAULT '[]';
ALTER TABLE inbounds ADD COLUMN tls_max_version TEXT;
ALTER TABLE inbounds ADD COLUMN tls_cipher_suites TEXT;
ALTER TABLE inbounds ADD COLUMN tls_enable_session_resumption INTEGER;
ALTER TABLE inbounds ADD COLUMN tls_master_key_log TEXT;
ALTER TABLE inbounds ADD COLUMN tls_ech_server_keys TEXT;

-- Backfill: every existing TLS inbound with a non-empty PEM blob becomes a
-- single-entry JSON array. `usage=encipherment` and `one_time_loading=1`
-- match the values the old build_tls_config() hard-coded, so handler
-- output stays bit-identical after the migration.
--
-- SQLite's json1 functions (json_array / json_object) escape embedded
-- newlines and quotes in the PEM text. json1 is statically linked into
-- libsqlite3 since 3.38.0, which sqlx ships with.
UPDATE inbounds
SET tls_certificates = json_array(json_object(
    'source', 'inline',
    'cert', COALESCE(tls_cert_pem, ''),
    'key', COALESCE(tls_key_pem, ''),
    'usage', 'encipherment',
    'ocsp_stapling', 0,
    'build_chain', 0,
    'one_time_loading', 1
))
WHERE tls_cert_pem IS NOT NULL AND tls_cert_pem != '';
