//! Form-layer type aliases used across the Inbounds form. The form
//! keeps a flat shape (one field per knob, the way the operator
//! types it) while the backend consumes tagged-enum layers
//! (protocol/transport/security/sniffing). The adapters in
//! `./adapters` translate between the two at the boundary.

import type {
  FinalMask,
  QuicCongestion,
  SecurityConfig,
  TlsCertificate,
  TransportConfig,
  VlessEncryptionAuth,
  VlessEncryptionMode,
  VlessFallback,
  VlessFlow,
  VlessXorMode,
  XhttpMode,
} from '@/api/types';

/** Operator-facing transport label, derived from the typed transport.
 *  `hysteria` is omitted on purpose — it's not a free-standing operator
 *  choice; it's force-paired with `protocol_kind === 'hysteria2'` and
 *  the transport selector is hidden in that mode. */
export type FormNetwork = 'tcp' | 'ws' | 'xhttp';

/** Operator-facing security label, derived from the typed security. */
export type FormSecurity = 'none' | 'tls' | 'reality';

/** Operator-facing protocol label. The set of registered protocols
 *  lives in `./registry::PROTOCOL_REGISTRY` — keep this union in sync. */
export type FormProtocol = 'vless' | 'hysteria2';

/** Operator-facing masquerade mode for the Hysteria 2 transport. */
export type FormMasqueradeKind = 'notfound' | 'file' | 'proxy' | 'string';

/** Congestion choice including a `default` sentinel — picking it
 *  leaves `quic_params.congestion` unset so xray applies its own
 *  default (BBR). */
export type FormCongestion = 'default' | QuicCongestion;

/** Operator-selectable ASCII mode for Sudoku FinalMask. `''` is the
 *  resting state — xray then applies its built-in default. */
export type SudokuAscii = '' | 'prefer_entropy' | 'prefer_ascii';

/** Per-protocol metadata. Owns the rules that drive form layout
 *  (which transports/securities are valid, which tabs to render, what
 *  per-protocol UI sits under General). Adding a new protocol is:
 *    1. extend `FormProtocol` and `ProtocolConfig` (backend ts-rs export)
 *    2. add one entry to `PROTOCOL_REGISTRY`
 *    3. drop a tab component if it has its own knobs
 *  Form auto-reset, tab visibility, and selector option-filtering all
 *  flow from the registry — no `isHysteria` branches scattered around. */
export interface ProtocolDef {
  /** Display label in the protocol Select. */
  label: string;
  /** Transports the protocol can pair with. A single-entry list means
   *  the transport selector is hidden in the form. */
  allowedTransports: ReadonlyArray<TransportConfig['kind']>;
  /** Same shape for the security layer. */
  allowedSecurities: ReadonlyArray<SecurityConfig['kind']>;
  /** Snap target when the operator switches protocol and the current
   *  transport/security is no longer allowed. */
  defaultTransport: TransportConfig['kind'];
  defaultSecurity: SecurityConfig['kind'];
  /** True if the protocol carries a `flow` field (VLESS-style). When
   *  false the Flow selector hides and `vless_flow` snaps to 'none'. */
  hasFlow: boolean;
  /** Extra form tabs to render. Mounted only when the protocol is the
   *  currently-selected one. */
  extraTabs?: ReadonlyArray<{
    key: string;
    labelKey: string;
    Component: () => React.ReactElement;
  }>;
  /** Optional component rendered inside `GeneralTab` below the security
   *  row — used by VLESS for its post-quantum encryption section. */
  MainTabExtras?: () => React.ReactElement;
}

/** Shape of the form's value store, with array fields kept as arrays
 *  (Antd's Select mode="tags" hands us `string[]` directly). One field
 *  per operator-visible knob; the adapters convert from/to the typed
 *  Inbound shape at the boundary. */
export interface FormValues {
  tag: string;
  port: number;
  listen: string;
  /** Top-level protocol family. Determines whether the network selector
   *  + VLESS-specific knobs (flow, encryption) apply, or whether the
   *  Hysteria-specific transport (auth, masq, udp_idle) takes over. */
  protocol_kind: FormProtocol;
  network: FormNetwork;
  vless_flow: VlessFlow;
  security: FormSecurity;
  // VLESS Encryption — post-quantum / X25519 application-layer cipher
  // on top of TLS/Reality. `none` keeps current legacy behaviour.
  vless_encryption_mode: VlessEncryptionMode;
  vless_encryption_auth: VlessEncryptionAuth;
  vless_encryption_xor_mode: VlessXorMode;
  vless_encryption_seconds_from: number;
  vless_encryption_seconds_to: number | null;
  vless_encryption_padding: string;
  // Pre-generated keypair stored in the form so the operator sees the
  // public/private values immediately after flipping the mode, and so
  // submit can hand the same keys back to the backend (no double-gen).
  // Empty strings ≡ "not yet generated"; backend's
  // `complete_server_managed_fields` falls back to generating then.
  vless_encryption_server_key: string;
  vless_encryption_client_key: string;
  // VLESS fallbacks. Mutually exclusive with `vless_encryption_mode !=
  // 'none'`; xray-core rejects the combo at startup. Tab is only
  // accessible when network=tcp + encryption_mode=none.
  vless_fallbacks: VlessFallback[];
  reality_dest: string;
  reality_server_names: string[];
  reality_short_ids: string[];
  reality_fingerprint: string;
  // SpiderX crawl path — client-side camouflage walked on the real dest
  // after an unverified handshake. Rides in the share-link as `spx=`.
  reality_spider_x: string;
  reality_xver: number;
  // Reality x25519 keypair — body-carried (generated via
  // POST /api/keygen/reality-keypair) so the public key shows on the create
  // form immediately. The server re-derives the public from the private on
  // save, so the stored pair is always consistent.
  reality_private_key: string;
  reality_public_key: string;
  ws_path: string;
  ws_host: string;
  ws_headers: { name: string; value: string }[];
  ws_accept_proxy_protocol: boolean;
  ws_heartbeat_period: number | null;
  // TLS certificates — one or more entries, each with its own source
  // (inline PEM vs filesystem path), usage, OCSP+chain knobs.
  tls_certificates: TlsCertificate[];
  tls_server_name: string;
  tls_alpn: string[];
  // uTLS ClientHello fingerprint the client emulates on the standard-TLS
  // path (Reality has its own). Travels in the share-link as `fp=`; empty
  // defaults to "chrome" server-side.
  tls_fingerprint: string;
  tls_min_version: string;
  tls_max_version: string;
  // xray `cipherSuites` field — TLS 1.2 cipher list. Stored as an
  // array in the form so the UI can render a tags-multi-select; the
  // backend receives the `:`-joined string xray's parser expects.
  tls_cipher_suites: string[];
  tls_enable_session_resumption: boolean;
  tls_reject_unknown_sni: boolean;
  // File path xray writes the NSS-format TLS keylog to. Debug-only.
  tls_master_key_log: string;
  // base64-encoded ECH server key bundle.
  tls_ech_server_keys: string;
  // Public ECH config list — derived from server_keys by the Generate
  // mutation. Embedded in the share-link as the `ech=` param.
  tls_ech_config_list: string;
  // Ordered list of TLS 1.3 curves (first match wins). Empty = xray default.
  tls_curve_preferences: string[];
  xhttp_path: string;
  xhttp_host: string;
  xhttp_mode: XhttpMode;
  // Advanced XHTTP — `headers` lives as an ordered list of {name,value}
  // entries in the form so the React inputs stay stable while the
  // operator edits a key (a Record<string,string> would re-key on
  // every name edit and break focus). The save mutation collapses
  // duplicates / drops empty names before sending to the backend.
  xhttp_headers: Array<{ name: string; value: string }>;
  xhttp_x_padding_bytes: string;
  xhttp_no_grpc_header: boolean;
  xhttp_no_sse_header: boolean;
  xhttp_sc_max_each_post_bytes: string;
  xhttp_sc_min_posts_interval_ms: string;
  xhttp_sc_max_buffered_posts: number | null;
  xhttp_sc_stream_up_server_secs: string;
  xhttp_xmux_max_concurrency: string;
  xhttp_xmux_max_connections: string;
  xhttp_xmux_c_max_reuse_times: string;
  xhttp_xmux_h_max_request_times: string;
  xhttp_xmux_h_max_reusable_secs: string;
  xhttp_xmux_h_keep_alive_period: number | null;
  xhttp_x_padding_obfs_mode: boolean;
  xhttp_x_padding_key: string;
  xhttp_x_padding_header: string;
  xhttp_x_padding_placement: string;
  xhttp_x_padding_method: string;
  xhttp_uplink_http_method: string;
  xhttp_session_placement: string;
  xhttp_session_key: string;
  xhttp_seq_placement: string;
  xhttp_seq_key: string;
  xhttp_uplink_data_placement: string;
  xhttp_uplink_data_key: string;
  xhttp_uplink_chunk_size: string;
  xhttp_server_max_header_bytes: number | null;
  // Hysteria 2 transport — server-wide preshared auth (rarely used in the
  // panel since per-client auth lives on Client.auth), QUIC UDP idle, and
  // a tagged masquerade selector with per-kind subfields.
  hysteria_auth: string;
  hysteria_udp_idle_timeout: number | null;
  hysteria_masq_kind: FormMasqueradeKind;
  hysteria_masq_file_root: string;
  hysteria_masq_proxy_url: string;
  hysteria_masq_proxy_rewrite_host: boolean;
  hysteria_masq_proxy_insecure: boolean;
  hysteria_masq_string_content: string;
  hysteria_masq_string_status_code: number;
  // Stream-level QUIC tuning. Shared between Hysteria 2 and XHTTP+H3:
  // both transports route the values onto `StreamConfig.quic_params`.
  // Every field is optional — empty leaves xray's default in place.
  quic_congestion: FormCongestion;
  quic_bbr_profile: string;
  quic_brutal_up_mbps: number | null;
  quic_brutal_down_mbps: number | null;
  quic_max_idle_timeout_secs: number | null;
  quic_keep_alive_period_secs: number | null;
  quic_init_stream_receive_window: number | null;
  quic_max_stream_receive_window: number | null;
  quic_init_conn_receive_window: number | null;
  quic_max_conn_receive_window: number | null;
  quic_disable_path_mtu_discovery: boolean;
  quic_max_incoming_streams: number | null;
  quic_udp_hop_ports: string[];
  quic_udp_hop_interval_min: number | null;
  quic_udp_hop_interval_max: number | null;
  // FinalMask — wire-level obfuscation wrapping socket bytes after the
  // TLS/Reality handshake. Variants:
  //   * sudoku   — TCP + UDP, password-derived lookup + entropy + padding
  //   * fragment — TCP-only, random-sized chunks with delays
  //   * noise    — UDP-only, prepended random bytes per datagram
  // Settings must match symmetrically on the client; the share-link's
  // `fm=` param ships them so subscriptions bootstrap clients automatically.
  finalmask_kind: FinalMask['kind'];
  // sudoku
  finalmask_sudoku_password: string;
  finalmask_sudoku_ascii: SudokuAscii;
  finalmask_sudoku_padding_min: number | null;
  finalmask_sudoku_padding_max: number | null;
  // fragment
  // UI-only discriminator that maps to the packets_from/to pair xray's conf
  // parser consumes (see infra/conf/transport_internet.go FragmentMask.Build):
  //   tlshello → (0,1)  fragment ONLY the TLS ClientHello — beats DPI that
  //                     severs the handshake by reading the SNI
  //   all      → (0,0)  segment the whole TCP stream
  //   range    → (from,to) from the inputs below (from ≥ 1)
  finalmask_fragment_packets_mode: 'tlshello' | 'all' | 'range';
  finalmask_fragment_packets_from: number | null;
  finalmask_fragment_packets_to: number | null;
  finalmask_fragment_length_min: number | null;
  finalmask_fragment_length_max: number | null;
  finalmask_fragment_delay_min: number | null;
  finalmask_fragment_delay_max: number | null;
  // noise
  finalmask_noise_packet_hex: string;
  finalmask_noise_rand_min: number | null;
  finalmask_noise_rand_max: number | null;
  sniffing_enabled: boolean;
  sniffing_dest_override: string[];
  // routeOnly — use the sniffed domain for routing only, without
  // rewriting the connection's destination (keeps the original target on
  // the wire). Off preserves xray's dest-rewrite behaviour.
  sniffing_route_only: boolean;
  // Sockopt — socket-level options (streamSettings.sockopt). Kept flat
  // like the rest of the form; `buildSockopt` collapses them back into
  // the typed `SocketOpt` at the boundary.
  //   * trusted_x_forwarded_for — CIDRs of trusted upstream proxies whose
  //     X-Forwarded-For xray may believe. xray-core #6159 warns when unset
  //     on XHTTP/WS/HU inbounds. Empty array = trust nothing.
  sockopt_trusted_x_forwarded_for: string[];
  sockopt_tcp_keep_alive_interval: number | null;
  sockopt_tcp_keep_alive_idle: number | null;
  sockopt_tcp_mptcp: boolean;
  //   * accept_proxy_protocol — believe a PROXY-protocol header from a
  //     trusted upstream LB/proxy so xray recovers the real client IP.
  //   * tcp_fast_open — TFO on the listen socket. null = OS default,
  //     256 = enable, -1 = force-disable (maps 1:1 to xray's `tfo`).
  //   * v6only — IPV6_V6ONLY on a [::] listener; off = dual-stack.
  sockopt_accept_proxy_protocol: boolean;
  sockopt_tcp_fast_open: number | null;
  sockopt_v6only: boolean;
}
