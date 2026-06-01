-- Backfill the typed JSON blobs from the flat legacy columns for every
-- existing inbound row. After this migration runs, the application
-- reads exclusively from `protocol_config / transport_config /
-- security_config / sniffing_config`; the flat columns hang around for
-- one more migration's worth of safety, then get dropped in 0016.
--
-- Implementation notes:
--   * Tagged-enum payloads are assembled with `json_object()` so the
--     output exactly matches what `serde_json` would emit for the Rust
--     types (`{"kind": "vless", ...}` for protocol, etc.). Variant-
--     specific fields live inside a CASE so a Reality row doesn't carry
--     TLS keys it can't use, and vice versa.
--   * `json()` calls re-parse string columns that were already JSON
--     (reality_server_names, tls_certificates, ...) so they nest as
--     real JSON values inside the new blob instead of as escaped strings.
--   * SQLite's `json_object` writes integers 0/1 for `col = 1`
--     expressions instead of JSON booleans; the helper `json('true' /
--     'false')` snippet below gives real `true / false` literals so
--     serde's `bool` deserializer is happy.
--   * Idempotent: the WHERE-clause sentinels (empty string on three
--     blobs) mean the migration is a no-op on rows already backfilled.

UPDATE inbounds
SET protocol_config = json_object(
        'kind',                   'vless',
        'flow',                   vless_flow,
        'encryption_mode',        vless_encryption_mode,
        'encryption_auth',        vless_encryption_auth,
        'encryption_xor_mode',    vless_encryption_xor_mode,
        'encryption_seconds_from', vless_encryption_seconds_from,
        'encryption_seconds_to',   vless_encryption_seconds_to,
        'encryption_padding',     vless_encryption_padding,
        'encryption_server_key',  vless_encryption_server_key,
        'encryption_client_key',  vless_encryption_client_key
    )
WHERE protocol_config = '';

UPDATE inbounds
SET transport_config = CASE network
        WHEN 'tcp' THEN json_object('kind', 'tcp')
        WHEN 'ws'  THEN json_object(
            'kind',                   'ws',
            'path',                   ws_path,
            'host',                   ws_host,
            'headers',                CASE WHEN ws_headers IS NULL OR ws_headers = '' THEN NULL ELSE json(ws_headers) END,
            'accept_proxy_protocol',  CASE WHEN ws_accept_proxy_protocol IS NULL THEN NULL WHEN ws_accept_proxy_protocol = 1 THEN json('true') ELSE json('false') END,
            'heartbeat_period',       ws_heartbeat_period
        )
        WHEN 'xhttp' THEN json_object(
            'kind',                       'xhttp',
            'path',                       xhttp_path,
            'host',                       xhttp_host,
            'mode',                       xhttp_mode,
            'headers',                    CASE WHEN xhttp_headers IS NULL OR xhttp_headers = '' THEN NULL ELSE json(xhttp_headers) END,
            'x_padding_bytes',            xhttp_x_padding_bytes,
            'no_grpc_header',             CASE WHEN xhttp_no_grpc_header  IS NULL THEN NULL WHEN xhttp_no_grpc_header  = 1 THEN json('true') ELSE json('false') END,
            'no_sse_header',              CASE WHEN xhttp_no_sse_header   IS NULL THEN NULL WHEN xhttp_no_sse_header   = 1 THEN json('true') ELSE json('false') END,
            'sc_max_each_post_bytes',     xhttp_sc_max_each_post_bytes,
            'sc_min_posts_interval_ms',   xhttp_sc_min_posts_interval_ms,
            'sc_max_buffered_posts',      xhttp_sc_max_buffered_posts,
            'sc_stream_up_server_secs',   xhttp_sc_stream_up_server_secs,
            'xmux_max_concurrency',       xhttp_xmux_max_concurrency,
            'xmux_max_connections',       xhttp_xmux_max_connections,
            'xmux_c_max_reuse_times',     xhttp_xmux_c_max_reuse_times,
            'xmux_h_max_request_times',   xhttp_xmux_h_max_request_times,
            'xmux_h_max_reusable_secs',   xhttp_xmux_h_max_reusable_secs,
            'xmux_h_keep_alive_period',   xhttp_xmux_h_keep_alive_period,
            'x_padding_obfs_mode',        CASE WHEN xhttp_x_padding_obfs_mode IS NULL THEN NULL WHEN xhttp_x_padding_obfs_mode = 1 THEN json('true') ELSE json('false') END,
            'x_padding_key',              xhttp_x_padding_key,
            'x_padding_header',           xhttp_x_padding_header,
            'x_padding_placement',        xhttp_x_padding_placement,
            'x_padding_method',           xhttp_x_padding_method,
            'uplink_http_method',         xhttp_uplink_http_method,
            'session_placement',          xhttp_session_placement,
            'session_key',                xhttp_session_key,
            'seq_placement',              xhttp_seq_placement,
            'seq_key',                    xhttp_seq_key,
            'uplink_data_placement',      xhttp_uplink_data_placement,
            'uplink_data_key',            xhttp_uplink_data_key,
            'uplink_chunk_size',          xhttp_uplink_chunk_size,
            'server_max_header_bytes',    xhttp_server_max_header_bytes
        )
    END
WHERE transport_config = '';

UPDATE inbounds
SET security_config = CASE security
        WHEN 'none' THEN json_object('kind', 'none')
        WHEN 'reality' THEN json_object(
            'kind',          'reality',
            'dest',          reality_dest,
            'server_names',  json(reality_server_names),
            'private_key',   reality_private_key,
            'public_key',    reality_public_key,
            'short_ids',     json(reality_short_ids),
            'fingerprint',   reality_fingerprint,
            'xver',          reality_xver
        )
        WHEN 'tls' THEN json_object(
            'kind',                       'tls',
            'certificates',               json(tls_certificates),
            'server_name',                tls_server_name,
            'alpn',                       CASE WHEN tls_alpn IS NULL OR tls_alpn = '' THEN NULL ELSE json(tls_alpn) END,
            'min_version',                tls_min_version,
            'max_version',                tls_max_version,
            'cipher_suites',              tls_cipher_suites,
            'enable_session_resumption',  CASE WHEN tls_enable_session_resumption IS NULL THEN NULL WHEN tls_enable_session_resumption = 1 THEN json('true') ELSE json('false') END,
            'reject_unknown_sni',         CASE WHEN tls_reject_unknown_sni        IS NULL THEN NULL WHEN tls_reject_unknown_sni        = 1 THEN json('true') ELSE json('false') END,
            'master_key_log',             tls_master_key_log,
            'ech_server_keys',            tls_ech_server_keys,
            'curve_preferences',          CASE WHEN tls_curve_preferences IS NULL OR tls_curve_preferences = '' THEN NULL ELSE json(tls_curve_preferences) END
        )
    END
WHERE security_config = '';

-- Sniffing always backfills from the flat columns — the 0014 default
-- on the JSON column was a placeholder, the operator's real choice
-- still lives in `sniffing_enabled / sniffing_dest_override`. sqlx's
-- migration tracker ensures we only run this UPDATE once.
UPDATE inbounds
SET sniffing_config = json_object(
        'enabled',       CASE WHEN sniffing_enabled = 1 THEN json('true') ELSE json('false') END,
        'dest_override', json(sniffing_dest_override)
    );
