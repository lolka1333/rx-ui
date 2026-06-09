//! Form ↔ typed payload adapters.
//!
//! The form keeps a flat shape (one field per knob, the way the operator
//! types it) while the backend consumes/returns tagged-enum layers
//! (`protocol/transport/security/sniffing`). These helpers translate
//! between the two at the boundary so the rest of the form stays
//! flat-shape-only and the field-by-field rendering doesn't have to
//! switch on `inb.transport.kind` everywhere.

import type {
  FinalMask,
  HysteriaMasquerade,
  HysteriaTransport,
  Inbound,
  InboundCreate,
  InboundUpdate,
  ProtocolConfig,
  QuicParams,
  SecurityConfig,
  Sniffing,
  SocketOpt,
  TlsSecurity,
  TransportConfig,
  UdpHop,
  VlessProtocol,
  WsTransport,
  XhttpTransport,
} from '@/api/types';
import { DEFAULTS } from './defaults';
import type { FormValues } from './types';

/**
 * Hydrate the flat form state from a typed `Inbound`. Each typed-layer
 * variant peels into the matching flat fields; layers the inbound
 * doesn't use (e.g. WS fields on an XHTTP inbound) stay at their
 * DEFAULTS so the operator sees sensible placeholders when they switch
 * the network selector mid-edit.
 */
export function inboundToForm(inb: Inbound): FormValues {
  const v: FormValues = { ...DEFAULTS, tag: inb.tag, listen: inb.listen, port: inb.port };

  v.protocol_kind = inb.protocol.kind;

  if (inb.protocol.kind === 'vless') {
    v.vless_flow = inb.protocol.flow;
    v.vless_encryption_mode = inb.protocol.encryption_mode;
    v.vless_encryption_auth = inb.protocol.encryption_auth ?? 'mlkem768';
    v.vless_encryption_xor_mode = inb.protocol.encryption_xor_mode ?? 'native';
    v.vless_encryption_seconds_from = inb.protocol.encryption_seconds_from ?? 600;
    v.vless_encryption_seconds_to = inb.protocol.encryption_seconds_to ?? null;
    v.vless_encryption_padding = inb.protocol.encryption_padding ?? '';
    v.vless_encryption_server_key = inb.protocol.encryption_server_key ?? '';
    v.vless_encryption_client_key = inb.protocol.encryption_client_key ?? '';
    v.vless_fallbacks = inb.protocol.fallbacks ?? [];
  }

  // Hysteria transport hydration. The transport carries the QUIC/masq
  // knobs; the protocol layer is empty in v1 (per HysteriaProtocol = {}).
  if (inb.transport.kind === 'hysteria') {
    const h = inb.transport;
    v.hysteria_auth = h.auth ?? '';
    v.hysteria_udp_idle_timeout = h.udp_idle_timeout ?? null;
    v.hysteria_masq_kind = h.masquerade.kind;
    if (h.masquerade.kind === 'file') {
      v.hysteria_masq_file_root = h.masquerade.root;
    } else if (h.masquerade.kind === 'proxy') {
      v.hysteria_masq_proxy_url = h.masquerade.url;
      v.hysteria_masq_proxy_rewrite_host = h.masquerade.rewrite_host;
      v.hysteria_masq_proxy_insecure = h.masquerade.insecure;
    } else if (h.masquerade.kind === 'string') {
      v.hysteria_masq_string_content = h.masquerade.content;
      v.hysteria_masq_string_status_code = h.masquerade.status_code;
    }
    if (h.quic_params) hydrateQuicParams(v, h.quic_params);
  }

  // `network` stays as the typed transport kind for non-hysteria
  // inbounds. Hysteria transports drive their own UI block, but we still
  // keep `network` at its default so buildTransport's switch has a sane
  // fallback if protocol_kind ever flips back to vless mid-edit.
  v.network = inb.transport.kind === 'hysteria' ? 'tcp' : inb.transport.kind;
  if (inb.transport.kind === 'ws') {
    const w = inb.transport;
    v.ws_path = w.path ?? '';
    v.ws_host = w.host ?? '';
    v.ws_headers = w.headers
      ? Object.entries(w.headers).map(([name, value]) => ({ name, value }))
      : [];
    v.ws_accept_proxy_protocol = w.accept_proxy_protocol ?? false;
    v.ws_heartbeat_period = w.heartbeat_period ?? null;
  } else if (inb.transport.kind === 'xhttp') {
    const x = inb.transport;
    v.xhttp_path = x.path ?? '';
    v.xhttp_host = x.host ?? '';
    v.xhttp_mode = x.mode ?? 'auto';
    v.xhttp_headers = x.headers
      ? Object.entries(x.headers).map(([name, value]) => ({ name, value }))
      : [];
    v.xhttp_x_padding_bytes = x.x_padding_bytes ?? '';
    v.xhttp_no_grpc_header = x.no_grpc_header ?? false;
    v.xhttp_no_sse_header = x.no_sse_header ?? false;
    v.xhttp_sc_max_each_post_bytes = x.sc_max_each_post_bytes ?? '';
    v.xhttp_sc_min_posts_interval_ms = x.sc_min_posts_interval_ms ?? '';
    v.xhttp_sc_max_buffered_posts = x.sc_max_buffered_posts ?? null;
    v.xhttp_sc_stream_up_server_secs = x.sc_stream_up_server_secs ?? '';
    v.xhttp_xmux_max_concurrency = x.xmux_max_concurrency ?? '';
    v.xhttp_xmux_max_connections = x.xmux_max_connections ?? '';
    v.xhttp_xmux_c_max_reuse_times = x.xmux_c_max_reuse_times ?? '';
    v.xhttp_xmux_h_max_request_times = x.xmux_h_max_request_times ?? '';
    v.xhttp_xmux_h_max_reusable_secs = x.xmux_h_max_reusable_secs ?? '';
    v.xhttp_xmux_h_keep_alive_period = x.xmux_h_keep_alive_period ?? null;
    v.xhttp_x_padding_obfs_mode = x.x_padding_obfs_mode ?? false;
    v.xhttp_x_padding_key = x.x_padding_key ?? '';
    v.xhttp_x_padding_header = x.x_padding_header ?? '';
    v.xhttp_x_padding_placement = x.x_padding_placement ?? '';
    v.xhttp_x_padding_method = x.x_padding_method ?? '';
    v.xhttp_uplink_http_method = x.uplink_http_method ?? '';
    v.xhttp_session_placement = x.session_placement ?? '';
    v.xhttp_session_key = x.session_key ?? '';
    v.xhttp_seq_placement = x.seq_placement ?? '';
    v.xhttp_seq_key = x.seq_key ?? '';
    v.xhttp_uplink_data_placement = x.uplink_data_placement ?? '';
    v.xhttp_uplink_data_key = x.uplink_data_key ?? '';
    v.xhttp_uplink_chunk_size = x.uplink_chunk_size ?? '';
    v.xhttp_server_max_header_bytes = x.server_max_header_bytes ?? null;
    if (x.quic_params) hydrateQuicParams(v, x.quic_params);
  }

  v.security = inb.security.kind;
  if (inb.security.kind === 'reality') {
    const r = inb.security;
    v.reality_dest = r.dest;
    v.reality_server_names = r.server_names;
    v.reality_short_ids = r.short_ids;
    v.reality_fingerprint = r.fingerprint;
    v.reality_spider_x = r.spider_x || '/';
    v.reality_xver = r.xver;
    v.reality_private_key = r.private_key;
    v.reality_public_key = r.public_key;
  } else if (inb.security.kind === 'tls') {
    const s = inb.security;
    v.tls_certificates = s.certificates;
    v.tls_server_name = s.server_name ?? '';
    v.tls_alpn = s.alpn ?? ['h2', 'http/1.1'];
    v.tls_fingerprint = s.fingerprint ?? 'chrome';
    v.tls_min_version = s.min_version ?? '';
    v.tls_max_version = s.max_version ?? '';
    v.tls_cipher_suites = s.cipher_suites
      ? s.cipher_suites.split(':').filter(Boolean)
      : [];
    v.tls_enable_session_resumption = s.enable_session_resumption ?? false;
    v.tls_reject_unknown_sni = s.reject_unknown_sni ?? false;
    v.tls_master_key_log = s.master_key_log ?? '';
    v.tls_ech_server_keys = s.ech_server_keys ?? '';
    v.tls_ech_config_list = s.ech_config_list ?? '';
    v.tls_curve_preferences = s.curve_preferences ?? [];
  }

  v.sniffing_enabled = inb.sniffing.enabled;
  v.sniffing_dest_override = inb.sniffing.dest_override;
  v.sniffing_route_only = inb.sniffing.route_only;

  // Sockopt is always present on the typed inbound (defaults to an empty
  // SocketOpt). Peel each field into its flat form slot; empty/null stay
  // at DEFAULTS so the operator sees placeholders.
  v.sockopt_trusted_x_forwarded_for = inb.sockopt.trusted_x_forwarded_for ?? [];
  v.sockopt_tcp_keep_alive_interval = inb.sockopt.tcp_keep_alive_interval ?? null;
  v.sockopt_tcp_keep_alive_idle = inb.sockopt.tcp_keep_alive_idle ?? null;
  v.sockopt_tcp_mptcp = inb.sockopt.tcp_mptcp ?? false;
  v.sockopt_accept_proxy_protocol = inb.sockopt.accept_proxy_protocol ?? false;
  v.sockopt_tcp_fast_open = inb.sockopt.tcp_fast_open ?? null;
  v.sockopt_v6only = inb.sockopt.v6only ?? false;

  // Active variants peel into their field set; inactive ones keep
  // DEFAULTS so the operator sees placeholders when flipping the dropdown.
  if (inb.finalmask.kind === 'sudoku') {
    v.finalmask_kind = 'sudoku';
    v.finalmask_sudoku_password = inb.finalmask.password;
    // Backend's `ascii` is `String`; narrow to the operator-selectable
    // union here so the form's typed union stays honest. Unknown values
    // (forward-compat from a future xray release) collapse to `''`.
    v.finalmask_sudoku_ascii =
      inb.finalmask.ascii === 'prefer_entropy' || inb.finalmask.ascii === 'prefer_ascii'
        ? inb.finalmask.ascii
        : '';
    v.finalmask_sudoku_padding_min = inb.finalmask.padding_min;
    v.finalmask_sudoku_padding_max = inb.finalmask.padding_max;
  } else if (inb.finalmask.kind === 'fragment') {
    v.finalmask_kind = 'fragment';
    // Recover the UI mode from the (from,to) pair xray stores: (0,1) is the
    // tlshello shortcut, (0,0) is whole-stream segmentation, anything else is
    // an explicit segment range.
    const pf = inb.finalmask.packets_from ?? 0;
    const pt = inb.finalmask.packets_to ?? 0;
    v.finalmask_fragment_packets_mode =
      pf === 0 && pt === 1 ? 'tlshello' : pf === 0 && pt === 0 ? 'all' : 'range';
    v.finalmask_fragment_packets_from = inb.finalmask.packets_from;
    v.finalmask_fragment_packets_to = inb.finalmask.packets_to;
    v.finalmask_fragment_length_min = inb.finalmask.length_min;
    v.finalmask_fragment_length_max = inb.finalmask.length_max;
    v.finalmask_fragment_delay_min = inb.finalmask.delay_min;
    v.finalmask_fragment_delay_max = inb.finalmask.delay_max;
  } else if (inb.finalmask.kind === 'noise') {
    v.finalmask_kind = 'noise';
    v.finalmask_noise_packet_hex = inb.finalmask.packet_hex;
    v.finalmask_noise_rand_min = inb.finalmask.rand_min;
    v.finalmask_noise_rand_max = inb.finalmask.rand_max;
  }

  return v;
}

/** Build the typed `ProtocolConfig` from the flat form. Dispatches on
 *  `protocol_kind`. Hysteria 2's protocol-side config is currently empty
 *  (all knobs live on the transport / per-client auth layers). */
export function buildProtocol(v: FormValues): ProtocolConfig {
  if (v.protocol_kind === 'hysteria2') {
    return { kind: 'hysteria2' };
  }
  const isEnc = v.vless_encryption_mode !== 'none';
  const vless: VlessProtocol = {
    flow: v.vless_flow,
    encryption_mode: v.vless_encryption_mode,
    encryption_auth: isEnc ? v.vless_encryption_auth : null,
    encryption_xor_mode: isEnc ? v.vless_encryption_xor_mode : null,
    encryption_seconds_from: isEnc ? v.vless_encryption_seconds_from : null,
    encryption_seconds_to:
      isEnc && v.vless_encryption_seconds_to !== null
        ? v.vless_encryption_seconds_to
        : null,
    encryption_padding:
      isEnc && v.vless_encryption_padding.trim() !== ''
        ? v.vless_encryption_padding.trim()
        : null,
    // Frontend pre-generates the keypair through `POST /api/keygen/
    // vless-encryption` so the operator can inspect / regenerate
    // before saving. Pass them straight through to the backend —
    // `complete_server_managed_fields` will only fall back to its
    // own keygen if both halves are empty (e.g. an older API client).
    encryption_server_key:
      isEnc && v.vless_encryption_server_key !== ''
        ? v.vless_encryption_server_key
        : null,
    encryption_client_key:
      isEnc && v.vless_encryption_client_key !== ''
        ? v.vless_encryption_client_key
        : null,
    // Backend rejects fallbacks paired with VLESS Encryption, so we
    // drop them at submit time when encryption is on. The form's UI
    // tab is also gated on `encryption_mode === 'none'`, so the
    // operator can't add entries here in the first place — this is
    // defence in depth against a stale form value carried over from
    // a previous edit session.
    fallbacks: isEnc ? [] : v.vless_fallbacks,
  };
  return { kind: 'vless', ...vless };
}

/** Pour a server-side `QuicParams` back into the flat form fields.
 *  Called from `inboundToForm` on both transports that carry the
 *  struct (Hysteria, XHTTP) — only one branch fires per inbound. */
export function hydrateQuicParams(v: FormValues, q: QuicParams) {
  v.quic_congestion = q.congestion ?? 'default';
  v.quic_bbr_profile = q.bbr_profile ?? '';
  v.quic_brutal_up_mbps = q.brutal_up_mbps ?? null;
  v.quic_brutal_down_mbps = q.brutal_down_mbps ?? null;
  v.quic_max_idle_timeout_secs = q.max_idle_timeout_secs ?? null;
  v.quic_keep_alive_period_secs = q.keep_alive_period_secs ?? null;
  v.quic_init_stream_receive_window = q.init_stream_receive_window ?? null;
  v.quic_max_stream_receive_window = q.max_stream_receive_window ?? null;
  v.quic_init_conn_receive_window = q.init_conn_receive_window ?? null;
  v.quic_max_conn_receive_window = q.max_conn_receive_window ?? null;
  v.quic_disable_path_mtu_discovery = q.disable_path_mtu_discovery;
  v.quic_max_incoming_streams = q.max_incoming_streams ?? null;
  if (q.udp_hop) {
    v.quic_udp_hop_ports = q.udp_hop.ports.map(String);
    v.quic_udp_hop_interval_min = q.udp_hop.interval_min;
    v.quic_udp_hop_interval_max = q.udp_hop.interval_max;
  }
}

/** Collect the operator-set QUIC tuning fields into a `QuicParams`,
 *  or `null` if every knob is still at its default. Lets the backend
 *  skip persisting an empty object and leave xray on its hard-coded
 *  defaults. */
export function buildQuicParams(v: FormValues): QuicParams | null {
  const ports = v.quic_udp_hop_ports
    .map((p) => Number.parseInt(p, 10))
    .filter((n) => Number.isFinite(n) && n > 0 && n < 65536);
  const udpHop: UdpHop | null =
    ports.length > 0
      ? {
          ports,
          interval_min: v.quic_udp_hop_interval_min ?? 0,
          interval_max: v.quic_udp_hop_interval_max ?? 0,
        }
      : null;
  const q: QuicParams = {
    congestion: v.quic_congestion === 'default' ? null : v.quic_congestion,
    bbr_profile: orNull(v.quic_bbr_profile),
    brutal_up_mbps: orNullNum(v.quic_brutal_up_mbps),
    brutal_down_mbps: orNullNum(v.quic_brutal_down_mbps),
    udp_hop: udpHop,
    init_stream_receive_window: orNullNum(v.quic_init_stream_receive_window),
    max_stream_receive_window: orNullNum(v.quic_max_stream_receive_window),
    init_conn_receive_window: orNullNum(v.quic_init_conn_receive_window),
    max_conn_receive_window: orNullNum(v.quic_max_conn_receive_window),
    max_idle_timeout_secs: orNullNum(v.quic_max_idle_timeout_secs),
    keep_alive_period_secs: orNullNum(v.quic_keep_alive_period_secs),
    disable_path_mtu_discovery: v.quic_disable_path_mtu_discovery,
    max_incoming_streams: orNullNum(v.quic_max_incoming_streams),
  };
  // True only when every nullable field is null AND the two booleans
  // sit at their defaults — that's "operator hasn't touched the panel".
  const isEmpty =
    q.congestion === null &&
    q.bbr_profile === null &&
    q.brutal_up_mbps === null &&
    q.brutal_down_mbps === null &&
    q.udp_hop === null &&
    q.init_stream_receive_window === null &&
    q.max_stream_receive_window === null &&
    q.init_conn_receive_window === null &&
    q.max_conn_receive_window === null &&
    q.max_idle_timeout_secs === null &&
    q.keep_alive_period_secs === null &&
    !q.disable_path_mtu_discovery &&
    q.max_incoming_streams === null;
  return isEmpty ? null : q;
}

/** Compose a `HysteriaMasquerade` from the flat per-kind form fields. */
export function buildMasquerade(v: FormValues): HysteriaMasquerade {
  switch (v.hysteria_masq_kind) {
    case 'notfound':
      return { kind: 'notfound' };
    case 'file':
      return { kind: 'file', root: v.hysteria_masq_file_root };
    case 'proxy':
      return {
        kind: 'proxy',
        url: v.hysteria_masq_proxy_url,
        rewrite_host: v.hysteria_masq_proxy_rewrite_host,
        insecure: v.hysteria_masq_proxy_insecure,
      };
    case 'string':
      return {
        kind: 'string',
        content: v.hysteria_masq_string_content,
        // Custom response headers aren't exposed in the UI yet — the
        // proto allows them but the use case is niche enough that we
        // leave the map empty. Add a key/value editor here when an
        // operator asks for it.
        headers: {},
        status_code: v.hysteria_masq_string_status_code,
      };
  }
}

export function buildTransport(v: FormValues): TransportConfig {
  // Hysteria 2 force-pairs proxy + transport — skip the network switch.
  if (v.protocol_kind === 'hysteria2') {
    const h: HysteriaTransport = {
      auth: orNull(v.hysteria_auth),
      udp_idle_timeout: orNullNum(v.hysteria_udp_idle_timeout),
      masquerade: buildMasquerade(v),
      quic_params: buildQuicParams(v),
    };
    return { kind: 'hysteria', ...h };
  }
  switch (v.network) {
    case 'tcp':
      return { kind: 'tcp' };
    case 'ws': {
      const headers = collapseHeaders(v.ws_headers);
      const ws: WsTransport = {
        path: v.ws_path || null,
        host: v.ws_host || null,
        headers: Object.keys(headers).length > 0 ? headers : null,
        accept_proxy_protocol: v.ws_accept_proxy_protocol,
        heartbeat_period: orNullNum(v.ws_heartbeat_period),
      };
      return { kind: 'ws', ...ws };
    }
    case 'xhttp': {
      const headers = collapseHeaders(v.xhttp_headers);
      const x: XhttpTransport = {
        path: v.xhttp_path || null,
        host: v.xhttp_host || null,
        mode: v.xhttp_mode,
        headers: Object.keys(headers).length > 0 ? headers : null,
        x_padding_bytes: orNull(v.xhttp_x_padding_bytes),
        no_grpc_header: v.xhttp_no_grpc_header,
        no_sse_header: v.xhttp_no_sse_header,
        sc_max_each_post_bytes: orNull(v.xhttp_sc_max_each_post_bytes),
        sc_min_posts_interval_ms: orNull(v.xhttp_sc_min_posts_interval_ms),
        sc_max_buffered_posts: orNullNum(v.xhttp_sc_max_buffered_posts),
        sc_stream_up_server_secs: orNull(v.xhttp_sc_stream_up_server_secs),
        xmux_max_concurrency: orNull(v.xhttp_xmux_max_concurrency),
        xmux_max_connections: orNull(v.xhttp_xmux_max_connections),
        xmux_c_max_reuse_times: orNull(v.xhttp_xmux_c_max_reuse_times),
        xmux_h_max_request_times: orNull(v.xhttp_xmux_h_max_request_times),
        xmux_h_max_reusable_secs: orNull(v.xhttp_xmux_h_max_reusable_secs),
        xmux_h_keep_alive_period: orNullNum(v.xhttp_xmux_h_keep_alive_period),
        x_padding_obfs_mode: v.xhttp_x_padding_obfs_mode,
        x_padding_key: orNull(v.xhttp_x_padding_key),
        x_padding_header: orNull(v.xhttp_x_padding_header),
        x_padding_placement: orNull(v.xhttp_x_padding_placement),
        x_padding_method: orNull(v.xhttp_x_padding_method),
        uplink_http_method: orNull(v.xhttp_uplink_http_method),
        session_placement: orNull(v.xhttp_session_placement),
        session_key: orNull(v.xhttp_session_key),
        seq_placement: orNull(v.xhttp_seq_placement),
        seq_key: orNull(v.xhttp_seq_key),
        uplink_data_placement: orNull(v.xhttp_uplink_data_placement),
        uplink_data_key: orNull(v.xhttp_uplink_data_key),
        uplink_chunk_size: orNull(v.xhttp_uplink_chunk_size),
        server_max_header_bytes: orNullNum(v.xhttp_server_max_header_bytes),
        quic_params: buildQuicParams(v),
      };
      return { kind: 'xhttp', ...x };
    }
  }
}

export function buildSecurity(v: FormValues): SecurityConfig {
  switch (v.security) {
    case 'none':
      return { kind: 'none' };
    case 'reality':
      return {
        kind: 'reality',
        dest: v.reality_dest,
        server_names: v.reality_server_names,
        // Body-carried keypair: the create form pre-generates it via
        // /api/keygen/reality-keypair so the public key is visible up front.
        // The backend re-derives the public from the private on save; on edit
        // it preserves the stored pair (changing it only via explicit rotate).
        private_key: v.reality_private_key,
        public_key: v.reality_public_key,
        short_ids: v.reality_short_ids,
        fingerprint: v.reality_fingerprint || 'chrome',
        spider_x: v.reality_spider_x || '/',
        xver: v.reality_xver,
      };
    case 'tls': {
      const tls: TlsSecurity = {
        certificates: (v.tls_certificates ?? []).filter(
          (c) => c.cert.trim() !== '' && c.key.trim() !== '',
        ),
        server_name: v.tls_server_name || null,
        alpn: v.tls_alpn && v.tls_alpn.length > 0 ? v.tls_alpn : null,
        fingerprint: orNull(v.tls_fingerprint),
        min_version: v.tls_min_version || null,
        max_version: v.tls_max_version || null,
        cipher_suites: v.tls_cipher_suites.length > 0
          ? v.tls_cipher_suites.join(':')
          : null,
        enable_session_resumption: v.tls_enable_session_resumption,
        reject_unknown_sni: v.tls_reject_unknown_sni,
        master_key_log: orNull(v.tls_master_key_log),
        ech_server_keys: orNull(v.tls_ech_server_keys),
        ech_config_list: orNull(v.tls_ech_config_list),
        curve_preferences:
          v.tls_curve_preferences && v.tls_curve_preferences.length > 0
            ? v.tls_curve_preferences
            : null,
      };
      return { kind: 'tls', ...tls };
    }
  }
}

export function buildSniffing(v: FormValues): Sniffing {
  return {
    enabled: v.sniffing_enabled,
    dest_override: v.sniffing_dest_override,
    route_only: v.sniffing_route_only,
  };
}

/** Collect the flat sockopt fields into a typed `SocketOpt`. Always
 *  returns the object (never null) — the backend's `is_active` guard
 *  decides whether to emit a sockopt block, so an all-empty value here
 *  is harmless and serializes to `{}`. Blank CIDR entries are dropped. */
export function buildSockopt(v: FormValues): SocketOpt {
  return {
    trusted_x_forwarded_for: (v.sockopt_trusted_x_forwarded_for ?? [])
      .map((s) => s.trim())
      .filter(Boolean),
    tcp_keep_alive_interval: orNullNum(v.sockopt_tcp_keep_alive_interval),
    tcp_keep_alive_idle: orNullNum(v.sockopt_tcp_keep_alive_idle),
    tcp_mptcp: v.sockopt_tcp_mptcp,
    accept_proxy_protocol: v.sockopt_accept_proxy_protocol,
    tcp_fast_open: orNullNum(v.sockopt_tcp_fast_open),
    v6only: v.sockopt_v6only,
  };
}

/** Compose `FinalMask` from the flat form. Dispatches on `kind`;
 *  `none` returns the typed `{kind:'none'}` blob (orchestrator's
 *  `is_active` guard skips emitting the mask). */
export function buildFinalMask(v: FormValues): FinalMask {
  // `max_split_*` (fragment) and `reset_*` (noise) are accepted by the
  // backend / xray-core but the v1 UI doesn't surface them — they stay
  // pinned to null so the operator sees the documented xray defaults.
  switch (v.finalmask_kind) {
    case 'none':
      return { kind: 'none' };
    case 'sudoku':
      return {
        kind: 'sudoku',
        password: v.finalmask_sudoku_password,
        ascii: v.finalmask_sudoku_ascii,
        custom_table: '',
        padding_min: v.finalmask_sudoku_padding_min,
        padding_max: v.finalmask_sudoku_padding_max,
        custom_tables: [],
      };
    case 'fragment': {
      // Mode → the (from,to) pair xray's conf parser understands:
      //   tlshello → (0,1)  share-link emits packets:"tlshello"
      //   all      → (0,0)  packets:"" (whole-stream TCP segmentation)
      //   range    → operator's (from,to), from ≥ 1
      const [packets_from, packets_to]: [number | null, number | null] =
        v.finalmask_fragment_packets_mode === 'tlshello'
          ? [0, 1]
          : v.finalmask_fragment_packets_mode === 'all'
            ? [0, 0]
            : [v.finalmask_fragment_packets_from, v.finalmask_fragment_packets_to];
      return {
        kind: 'fragment',
        packets_from,
        packets_to,
        length_min: v.finalmask_fragment_length_min,
        length_max: v.finalmask_fragment_length_max,
        delay_min: v.finalmask_fragment_delay_min,
        delay_max: v.finalmask_fragment_delay_max,
        max_split_min: null,
        max_split_max: null,
      };
    }
    case 'noise':
      return {
        kind: 'noise',
        packet_hex: v.finalmask_noise_packet_hex,
        rand_min: v.finalmask_noise_rand_min,
        rand_max: v.finalmask_noise_rand_max,
        reset_min: null,
        reset_max: null,
      };
  }
}

/** Form → POST body. */
export function formToCreate(v: FormValues): InboundCreate {
  return {
    tag: v.tag,
    listen: v.listen || null,
    port: v.port,
    protocol: buildProtocol(v),
    transport: buildTransport(v),
    security: buildSecurity(v),
    sniffing: buildSniffing(v),
    finalmask: buildFinalMask(v),
    sockopt: buildSockopt(v),
  };
}

/** Form → PATCH body. Every layer is sent so a transport / security swap
 *  takes effect atomically. The backend treats each layer slot as a full
 *  replacement of the previous JSON blob. */
export function formToUpdate(v: FormValues): InboundUpdate {
  return {
    tag: v.tag,
    enabled: null,
    listen: v.listen || null,
    port: v.port,
    protocol: buildProtocol(v),
    transport: buildTransport(v),
    security: buildSecurity(v),
    sniffing: buildSniffing(v),
    finalmask: buildFinalMask(v),
    sockopt: buildSockopt(v),
  };
}

/** Drop entries with empty names, last-wins on duplicate keys. */
export function collapseHeaders(
  rows: Array<{ name: string; value: string }>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const h of rows ?? []) {
    const k = h.name.trim();
    if (k) out[k] = h.value;
  }
  return out;
}

export function orNull(s: string): string | null {
  return s.trim() ? s.trim() : null;
}

export function orNullNum(n: number | null): number | null {
  return n === null || Number.isNaN(n) ? null : n;
}
