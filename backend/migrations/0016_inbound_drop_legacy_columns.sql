-- Drop every flat inbound column now that 0015 has projected them into
-- the typed JSON blobs. After this migration the inbounds table holds
-- only: id, tag, enabled, listen, port, protocol_config,
-- transport_config, security_config, sniffing_config, note,
-- created_at, updated_at.
--
-- The `protocol` text column also goes — `protocol_config.kind` carries
-- the same value. `vless_decryption` is dropped without a replacement:
-- VLESS's only legal value was the literal "none", and the new
-- `VlessProtocol` struct synthesizes that at proto-build time.
--
-- SQLite requires one `ALTER TABLE ... DROP COLUMN` per statement and
-- doesn't allow dropping a column referenced by an active index. None
-- of these are indexed (the only inbound indexes are on id/tag), so
-- the drops succeed in any order.

ALTER TABLE inbounds DROP COLUMN protocol;
ALTER TABLE inbounds DROP COLUMN vless_flow;
ALTER TABLE inbounds DROP COLUMN vless_decryption;
ALTER TABLE inbounds DROP COLUMN network;
ALTER TABLE inbounds DROP COLUMN security;

ALTER TABLE inbounds DROP COLUMN vless_encryption_mode;
ALTER TABLE inbounds DROP COLUMN vless_encryption_auth;
ALTER TABLE inbounds DROP COLUMN vless_encryption_xor_mode;
ALTER TABLE inbounds DROP COLUMN vless_encryption_seconds_from;
ALTER TABLE inbounds DROP COLUMN vless_encryption_seconds_to;
ALTER TABLE inbounds DROP COLUMN vless_encryption_padding;
ALTER TABLE inbounds DROP COLUMN vless_encryption_server_key;
ALTER TABLE inbounds DROP COLUMN vless_encryption_client_key;

ALTER TABLE inbounds DROP COLUMN reality_dest;
ALTER TABLE inbounds DROP COLUMN reality_server_names;
ALTER TABLE inbounds DROP COLUMN reality_private_key;
ALTER TABLE inbounds DROP COLUMN reality_public_key;
ALTER TABLE inbounds DROP COLUMN reality_short_ids;
ALTER TABLE inbounds DROP COLUMN reality_fingerprint;
ALTER TABLE inbounds DROP COLUMN reality_xver;

ALTER TABLE inbounds DROP COLUMN ws_path;
ALTER TABLE inbounds DROP COLUMN ws_host;
ALTER TABLE inbounds DROP COLUMN ws_headers;
ALTER TABLE inbounds DROP COLUMN ws_accept_proxy_protocol;
ALTER TABLE inbounds DROP COLUMN ws_heartbeat_period;

ALTER TABLE inbounds DROP COLUMN tls_cert_pem;
ALTER TABLE inbounds DROP COLUMN tls_key_pem;
ALTER TABLE inbounds DROP COLUMN tls_certificates;
ALTER TABLE inbounds DROP COLUMN tls_server_name;
ALTER TABLE inbounds DROP COLUMN tls_alpn;
ALTER TABLE inbounds DROP COLUMN tls_min_version;
ALTER TABLE inbounds DROP COLUMN tls_max_version;
ALTER TABLE inbounds DROP COLUMN tls_cipher_suites;
ALTER TABLE inbounds DROP COLUMN tls_enable_session_resumption;
ALTER TABLE inbounds DROP COLUMN tls_reject_unknown_sni;
ALTER TABLE inbounds DROP COLUMN tls_master_key_log;
ALTER TABLE inbounds DROP COLUMN tls_ech_server_keys;
ALTER TABLE inbounds DROP COLUMN tls_curve_preferences;

ALTER TABLE inbounds DROP COLUMN xhttp_path;
ALTER TABLE inbounds DROP COLUMN xhttp_host;
ALTER TABLE inbounds DROP COLUMN xhttp_mode;
ALTER TABLE inbounds DROP COLUMN xhttp_headers;
ALTER TABLE inbounds DROP COLUMN xhttp_x_padding_bytes;
ALTER TABLE inbounds DROP COLUMN xhttp_no_grpc_header;
ALTER TABLE inbounds DROP COLUMN xhttp_no_sse_header;
ALTER TABLE inbounds DROP COLUMN xhttp_sc_max_each_post_bytes;
ALTER TABLE inbounds DROP COLUMN xhttp_sc_min_posts_interval_ms;
ALTER TABLE inbounds DROP COLUMN xhttp_sc_max_buffered_posts;
ALTER TABLE inbounds DROP COLUMN xhttp_sc_stream_up_server_secs;
ALTER TABLE inbounds DROP COLUMN xhttp_xmux_max_concurrency;
ALTER TABLE inbounds DROP COLUMN xhttp_xmux_max_connections;
ALTER TABLE inbounds DROP COLUMN xhttp_xmux_c_max_reuse_times;
ALTER TABLE inbounds DROP COLUMN xhttp_xmux_h_max_request_times;
ALTER TABLE inbounds DROP COLUMN xhttp_xmux_h_max_reusable_secs;
ALTER TABLE inbounds DROP COLUMN xhttp_xmux_h_keep_alive_period;
ALTER TABLE inbounds DROP COLUMN xhttp_x_padding_obfs_mode;
ALTER TABLE inbounds DROP COLUMN xhttp_x_padding_key;
ALTER TABLE inbounds DROP COLUMN xhttp_x_padding_header;
ALTER TABLE inbounds DROP COLUMN xhttp_x_padding_placement;
ALTER TABLE inbounds DROP COLUMN xhttp_x_padding_method;
ALTER TABLE inbounds DROP COLUMN xhttp_uplink_http_method;
ALTER TABLE inbounds DROP COLUMN xhttp_session_placement;
ALTER TABLE inbounds DROP COLUMN xhttp_session_key;
ALTER TABLE inbounds DROP COLUMN xhttp_seq_placement;
ALTER TABLE inbounds DROP COLUMN xhttp_seq_key;
ALTER TABLE inbounds DROP COLUMN xhttp_uplink_data_placement;
ALTER TABLE inbounds DROP COLUMN xhttp_uplink_data_key;
ALTER TABLE inbounds DROP COLUMN xhttp_uplink_chunk_size;
ALTER TABLE inbounds DROP COLUMN xhttp_server_max_header_bytes;

ALTER TABLE inbounds DROP COLUMN sniffing_enabled;
ALTER TABLE inbounds DROP COLUMN sniffing_dest_override;

-- `note` was carried for years but never surfaced in the panel UI for
-- inbounds (clients have their own note column, which stays). The
-- frontend still sends `note: null` for backward-compat; the API
-- accepts and ignores it. Drop the column now that the new typed
-- create/update bodies omit the field entirely.
ALTER TABLE inbounds DROP COLUMN note;
