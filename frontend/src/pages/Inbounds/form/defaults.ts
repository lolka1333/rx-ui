//! Default values for the inbound-form's state store. Used both by
//! Antd's `Form.useForm({ initialValues })` and by the `inboundToForm`
//! adapter — every field a form might touch has an explicit baseline
//! here so the form never sees `undefined`.

import type { FormValues } from './types';

export const DEFAULTS: FormValues = {
  tag: '',
  port: 443,
  listen: '0.0.0.0',
  // VLESS is the historical default — Hysteria 2 is opt-in for operators
  // who specifically want QUIC obfuscation. Picking it requires real-cert
  // TLS, which most newcomers don't have on hand.
  protocol_kind: 'vless',
  network: 'tcp',
  // Hysteria defaults: empty server-wide auth (per-user auth is the norm),
  // upstream-default UDP idle (None → xray's built-in 60s), and `notfound`
  // masquerade so unauthenticated traffic gets a clean 404 instead of
  // accidentally exposing a directory listing.
  hysteria_auth: '',
  hysteria_udp_idle_timeout: null,
  hysteria_masq_kind: 'notfound',
  hysteria_masq_file_root: '',
  hysteria_masq_proxy_url: '',
  hysteria_masq_proxy_rewrite_host: false,
  hysteria_masq_proxy_insecure: false,
  hysteria_masq_string_content: '',
  hysteria_masq_string_status_code: 200,
  quic_congestion: 'default',
  quic_bbr_profile: '',
  quic_brutal_up_mbps: null,
  quic_brutal_down_mbps: null,
  quic_max_idle_timeout_secs: null,
  quic_keep_alive_period_secs: null,
  quic_init_stream_receive_window: null,
  quic_max_stream_receive_window: null,
  quic_init_conn_receive_window: null,
  quic_max_conn_receive_window: null,
  quic_disable_path_mtu_discovery: false,
  quic_max_incoming_streams: null,
  quic_udp_hop_ports: [],
  quic_udp_hop_interval_min: null,
  quic_udp_hop_interval_max: null,
  // Base mode: no flow. XTLS Vision is the recommended add-on for VLESS+Reality
  // but it's still an extra layer the user opts into — match xray's own default
  // (empty flow) so newcomers get a working baseline they can extend.
  vless_flow: 'none',
  security: 'reality',
  // VLESS Encryption defaults: off. When operator enables, defaults to
  // post-quantum ML-KEM-768 + native XOR + 600s session — sensible
  // "just turn it on" baseline.
  vless_encryption_mode: 'none',
  vless_encryption_auth: 'mlkem768',
  vless_encryption_xor_mode: 'native',
  vless_encryption_seconds_from: 600,
  vless_encryption_seconds_to: null,
  vless_encryption_padding: '',
  vless_encryption_server_key: '',
  vless_encryption_client_key: '',
  vless_fallbacks: [],
  reality_dest: 'www.cloudflare.com:443',
  reality_server_names: ['www.cloudflare.com'],
  reality_short_ids: [],
  reality_fingerprint: 'chrome',
  reality_spider_x: '/',
  reality_xver: 0,
  reality_private_key: '',
  reality_public_key: '',
  ws_path: '/',
  ws_host: '',
  ws_headers: [],
  ws_accept_proxy_protocol: false,
  ws_heartbeat_period: null,
  // No certs by default — the operator adds at least one before flipping
  // security to "tls". The form validation enforces that the array is
  // non-empty when security=tls (backend would otherwise reject the save).
  tls_certificates: [],
  tls_server_name: '',
  // Default ALPN = http/1.1 only. h2 must come BEFORE http/1.1 in the
  // negotiation order or it's never used; but `h2` over WebSocket is
  // impossible (WS upgrade is HTTP/1.1-only), so defaulting to ["h2","http/1.1"]
  // would silently break WS+TLS. Operators using XHTTP add `h2` explicitly.
  tls_alpn: ['http/1.1'],
  tls_fingerprint: 'chrome',
  tls_min_version: '',
  tls_max_version: '',
  tls_cipher_suites: [],
  tls_enable_session_resumption: false,
  tls_reject_unknown_sni: false,
  tls_self_signed: false,
  tls_master_key_log: '',
  tls_ech_server_keys: '',
  tls_ech_config_list: '',
  tls_curve_preferences: [],
  xhttp_path: '/upload',
  xhttp_host: '',
  xhttp_mode: 'auto',
  xhttp_headers: [],
  xhttp_x_padding_bytes: '',
  xhttp_no_grpc_header: false,
  xhttp_no_sse_header: false,
  xhttp_sc_max_each_post_bytes: '',
  xhttp_sc_min_posts_interval_ms: '',
  xhttp_sc_max_buffered_posts: null,
  xhttp_sc_stream_up_server_secs: '',
  xhttp_xmux_max_concurrency: '',
  xhttp_xmux_max_connections: '',
  xhttp_xmux_c_max_reuse_times: '',
  xhttp_xmux_h_max_request_times: '',
  xhttp_xmux_h_max_reusable_secs: '',
  xhttp_xmux_h_keep_alive_period: null,
  xhttp_x_padding_obfs_mode: false,
  xhttp_x_padding_key: '',
  xhttp_x_padding_header: '',
  xhttp_x_padding_placement: '',
  xhttp_x_padding_method: '',
  xhttp_uplink_http_method: '',
  xhttp_session_placement: '',
  xhttp_session_key: '',
  xhttp_session_id_table: '',
  xhttp_session_id_length: '',
  xhttp_seq_placement: '',
  xhttp_seq_key: '',
  xhttp_uplink_data_placement: '',
  xhttp_uplink_data_key: '',
  xhttp_uplink_chunk_size: '',
  xhttp_server_max_header_bytes: null,
  // Base mode: sniffing off (matches xray's own default). The
  // dest_override preset stays as a sane starting point for the moment
  // the operator decides to enable sniffing for domain-based routing.
  sniffing_enabled: false,
  sniffing_dest_override: ['http', 'tls', 'fakedns'],
  sniffing_route_only: false,
  sniffing_metadata_only: false,
  sniffing_domains_excluded: [],
  sniffing_ips_excluded: [],
  // FinalMask off by default — adding obfuscation only makes sense
  // when the operator has a concrete reason (active DPI, censorship).
  // The sudoku sub-fields are pre-filled with xray's documented
  // defaults so flipping `kind` works without extra clicks beyond
  // setting the password.
  finalmask_kind: 'none',
  finalmask_sudoku_password: '',
  finalmask_sudoku_ascii: 'prefer_entropy',
  finalmask_sudoku_padding_min: null,
  finalmask_sudoku_padding_max: null,
  // Fragment / noise sub-fields pre-filled with safe-default ranges
  // (length 100..200 is the documented xray sensible-default; rand 5..10
  // bytes for noise is enough to break common QUIC-fingerprint rules).
  // Operator can override; empty (null) means "use xray's own default".
  // tlshello is the sensible default: fragmenting the ClientHello is what
  // defeats handshake-severing DPI; it maps to packets=(0,1) on the wire.
  finalmask_fragment_packets_mode: 'tlshello',
  finalmask_fragment_packets_from: null,
  finalmask_fragment_packets_to: null,
  finalmask_fragment_lengths: '100-200',
  finalmask_fragment_delays: '',
  finalmask_noise_packet_hex: '',
  finalmask_noise_rand_min: 5,
  finalmask_noise_rand_max: 10,
  finalmask_salamander_password: '',
  // Sockopt off by default — empty trusted list + null keepalive + no
  // mptcp means `buildSockopt` returns an all-empty SocketOpt, the
  // backend's `is_active` skips it, and xray gets no sockopt block.
  sockopt_trusted_x_forwarded_for: [],
  sockopt_tcp_keep_alive_interval: null,
  sockopt_tcp_keep_alive_idle: null,
  sockopt_tcp_mptcp: false,
  sockopt_accept_proxy_protocol: false,
  sockopt_tcp_fast_open: null,
  sockopt_v6only: false,
};
