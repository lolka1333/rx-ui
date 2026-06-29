//! Flat form-value shape for the outbound editor + adapters to/from the typed
//! `CustomOutbound`. Mirrors the inbound `form/` split but far smaller: one
//! protocol (VLESS), client-side security (no certs / keypair), no
//! users/sniffing/finalmask. The transport/security objects are built to the
//! same `TransportConfig` / `SecurityConfig` shapes the backend reuses — only
//! the client-relevant fields are populated; the rest stay null/empty.

import type {
  CustomOutbound,
  SecurityConfig,
  TransportConfig,
  VlessEncryptionMode,
  VlessXorMode,
  XhttpMode,
} from '@/api/types';
// Reuse the inbound form's header collapser + finalmask builder so ws/xhttp
// headers and the FinalMask cipher serialize identically on both sides.
import { uuid } from '@/lib/id';
import {
  buildFinalMask,
  collapseHeaders,
  hydrateFinalMask,
  type FinalMaskFormFields,
} from '@/pages/Inbounds/form/adapters';
import { DEFAULTS as INB_DEFAULTS } from '@/pages/Inbounds/form/defaults';
import type { FormValues as InbFormValues } from '@/pages/Inbounds/form/types';

/** {name,value} header pair — the shape `HeaderListField` reads/writes. */
export interface HeaderPair {
  name: string;
  value: string;
}

export type OutboundNetwork = 'tcp' | 'ws' | 'xhttp';
export type OutboundSecurity = 'none' | 'tls' | 'reality';

export interface OutboundFormValues extends FinalMaskFormFields {
  tag: string;
  enabled: boolean;
  // VLESS endpoint
  address: string;
  port: number;
  uuid: string;
  flow: string; // '' | 'xtls-rprx-vision'
  // VLESS application-layer encryption — must MATCH the upstream server.
  encryption_mode: VlessEncryptionMode;
  encryption_xor_mode: VlessXorMode;
  encryption_client_key: string; // server's public client_key
  encryption_padding: string;
  // transport
  network: OutboundNetwork;
  ws_path: string;
  ws_host: string;
  ws_headers: HeaderPair[];
  ws_heartbeat_period: number | null;
  xhttp_path: string;
  xhttp_host: string;
  xhttp_mode: XhttpMode;
  xhttp_headers: HeaderPair[];
  // XHTTP meta knobs that MUST match the server (else it 400s every request).
  xhttp_x_padding_bytes: string;
  xhttp_x_padding_obfs_mode: boolean;
  xhttp_x_padding_key: string;
  xhttp_x_padding_header: string;
  xhttp_x_padding_placement: string;
  xhttp_x_padding_method: string;
  xhttp_session_placement: string;
  xhttp_session_key: string;
  xhttp_session_id_table: string;
  xhttp_session_id_length: string;
  xhttp_seq_placement: string;
  xhttp_seq_key: string;
  xhttp_uplink_data_placement: string;
  xhttp_uplink_data_key: string;
  // security (client side)
  security: OutboundSecurity;
  tls_server_name: string;
  tls_alpn: string[];
  tls_fingerprint: string;
  tls_verify_peer_cert_by_name: string[];
  tls_pinned_peer_cert_sha256: string[];
  reality_server_name: string;
  reality_public_key: string;
  reality_short_id: string;
  reality_fingerprint: string;
  reality_spider_x: string;
  // mux
  mux_enabled: boolean;
  mux_concurrency: number;
  // advanced
  send_through: string;
  proxy_tag: string;
}

export const OUTBOUND_DEFAULTS: OutboundFormValues = {
  tag: '',
  enabled: true,
  address: '',
  port: 443,
  uuid: '',
  flow: '',
  encryption_mode: 'none',
  encryption_xor_mode: 'native',
  encryption_client_key: '',
  encryption_padding: '',
  network: 'tcp',
  ws_path: '/',
  ws_host: '',
  ws_headers: [],
  ws_heartbeat_period: null,
  xhttp_path: '/',
  xhttp_host: '',
  xhttp_mode: 'auto',
  xhttp_headers: [],
  xhttp_x_padding_bytes: '',
  xhttp_x_padding_obfs_mode: false,
  xhttp_x_padding_key: '',
  xhttp_x_padding_header: '',
  xhttp_x_padding_placement: '',
  xhttp_x_padding_method: '',
  xhttp_session_placement: '',
  xhttp_session_key: '',
  xhttp_session_id_table: '',
  xhttp_session_id_length: '',
  xhttp_seq_placement: '',
  xhttp_seq_key: '',
  xhttp_uplink_data_placement: '',
  xhttp_uplink_data_key: '',
  security: 'reality',
  tls_server_name: '',
  tls_alpn: [],
  tls_fingerprint: 'chrome',
  tls_verify_peer_cert_by_name: [],
  tls_pinned_peer_cert_sha256: [],
  reality_server_name: '',
  reality_public_key: '',
  reality_short_id: '',
  reality_fingerprint: 'chrome',
  reality_spider_x: '/',
  mux_enabled: false,
  mux_concurrency: 8,
  send_through: '',
  proxy_tag: '',
  // FinalMask defaults reused verbatim from the inbound form.
  finalmask_kind: INB_DEFAULTS.finalmask_kind,
  finalmask_sudoku_password: INB_DEFAULTS.finalmask_sudoku_password,
  finalmask_sudoku_ascii: INB_DEFAULTS.finalmask_sudoku_ascii,
  finalmask_sudoku_padding_min: INB_DEFAULTS.finalmask_sudoku_padding_min,
  finalmask_sudoku_padding_max: INB_DEFAULTS.finalmask_sudoku_padding_max,
  finalmask_fragment_packets_mode: INB_DEFAULTS.finalmask_fragment_packets_mode,
  finalmask_fragment_packets_from: INB_DEFAULTS.finalmask_fragment_packets_from,
  finalmask_fragment_packets_to: INB_DEFAULTS.finalmask_fragment_packets_to,
  finalmask_fragment_lengths: INB_DEFAULTS.finalmask_fragment_lengths,
  finalmask_fragment_delays: INB_DEFAULTS.finalmask_fragment_delays,
  finalmask_noise_packet_hex: INB_DEFAULTS.finalmask_noise_packet_hex,
  finalmask_noise_rand_min: INB_DEFAULTS.finalmask_noise_rand_min,
  finalmask_noise_rand_max: INB_DEFAULTS.finalmask_noise_rand_max,
};

/** The XHTTP knobs the outbound form does NOT expose — the tuning/sizing
 *  settings (xmux, sc_*, padding-sizing, quic) that ride as xray defaults.
 *  Spread first in the xhttp branch; everything connectivity-relevant
 *  (path/host/mode/headers/padding-obfs/session/seq/uplink) is set explicitly. */
const XHTTP_NULL = {
  no_grpc_header: null,
  no_sse_header: null,
  sc_max_each_post_bytes: null,
  sc_min_posts_interval_ms: null,
  sc_max_buffered_posts: null,
  sc_stream_up_server_secs: null,
  xmux_max_concurrency: null,
  xmux_max_connections: null,
  xmux_c_max_reuse_times: null,
  xmux_h_max_request_times: null,
  xmux_h_max_reusable_secs: null,
  xmux_h_keep_alive_period: null,
  uplink_http_method: null,
  uplink_chunk_size: null,
  server_max_header_bytes: null,
  quic_params: null,
} as const;

function buildTransport(v: OutboundFormValues): TransportConfig {
  const orNull = (s: string) => s.trim() || null;
  if (v.network === 'ws') {
    const h = collapseHeaders(v.ws_headers);
    return {
      kind: 'ws',
      path: orNull(v.ws_path),
      host: orNull(v.ws_host),
      headers: Object.keys(h).length > 0 ? h : null,
      // accept_proxy_protocol is a server-receive option — N/A on a client.
      accept_proxy_protocol: null,
      heartbeat_period: v.ws_heartbeat_period,
    };
  }
  if (v.network === 'xhttp') {
    const h = collapseHeaders(v.xhttp_headers);
    return {
      ...XHTTP_NULL,
      kind: 'xhttp',
      path: orNull(v.xhttp_path),
      host: orNull(v.xhttp_host),
      mode: v.xhttp_mode,
      headers: Object.keys(h).length > 0 ? h : null,
      x_padding_bytes: orNull(v.xhttp_x_padding_bytes),
      x_padding_obfs_mode: v.xhttp_x_padding_obfs_mode,
      x_padding_key: orNull(v.xhttp_x_padding_key),
      x_padding_header: orNull(v.xhttp_x_padding_header),
      x_padding_placement: orNull(v.xhttp_x_padding_placement),
      x_padding_method: orNull(v.xhttp_x_padding_method),
      session_id_placement: orNull(v.xhttp_session_placement),
      session_id_key: orNull(v.xhttp_session_key),
      session_id_table: orNull(v.xhttp_session_id_table),
      session_id_length: orNull(v.xhttp_session_id_length),
      seq_placement: orNull(v.xhttp_seq_placement),
      seq_key: orNull(v.xhttp_seq_key),
      uplink_data_placement: orNull(v.xhttp_uplink_data_placement),
      uplink_data_key: orNull(v.xhttp_uplink_data_key),
    };
  }
  return { kind: 'tcp' };
}

function buildSecurity(v: OutboundFormValues): SecurityConfig {
  if (v.security === 'tls') {
    return {
      kind: 'tls',
      certificates: [],
      server_name: v.tls_server_name.trim() || null,
      alpn: v.tls_alpn.length > 0 ? v.tls_alpn : null,
      min_version: null,
      max_version: null,
      cipher_suites: null,
      enable_session_resumption: null,
      reject_unknown_sni: null,
      master_key_log: null,
      ech_server_keys: null,
      ech_config_list: null,
      curve_preferences: null,
      fingerprint: v.tls_fingerprint.trim() || null,
      verify_peer_cert_by_name:
        v.tls_verify_peer_cert_by_name.length > 0 ? v.tls_verify_peer_cert_by_name : null,
      pinned_peer_cert_sha256:
        v.tls_pinned_peer_cert_sha256.length > 0 ? v.tls_pinned_peer_cert_sha256 : null,
    };
  }
  if (v.security === 'reality') {
    return {
      kind: 'reality',
      dest: '',
      server_names: [v.reality_server_name.trim()],
      private_key: '',
      public_key: v.reality_public_key.trim(),
      short_ids: [v.reality_short_id.trim()],
      fingerprint: v.reality_fingerprint.trim() || 'chrome',
      xver: 0,
      spider_x: v.reality_spider_x.trim() || '/',
    };
  }
  return { kind: 'none' };
}

/** Build the typed `CustomOutbound` the API stores. `existing` preserves the
 *  id + created_at on edit; a fresh row mints both. Timestamps are ISO-8601
 *  (the backend stores the array verbatim — no server-side stamping). */
export function formToOutbound(
  v: OutboundFormValues,
  existing: CustomOutbound | null,
): CustomOutbound {
  const now = new Date().toISOString();
  return {
    id: existing?.id ?? uuid(),
    tag: v.tag.trim(),
    enabled: v.enabled,
    protocol: {
      kind: 'vless',
      address: v.address.trim(),
      port: v.port,
      id: v.uuid.trim(),
      flow: v.flow,
      encryption_mode: v.encryption_mode,
      // null out the cipher detail when not using native encryption.
      encryption_xor_mode: v.encryption_mode === 'none' ? null : v.encryption_xor_mode,
      encryption_client_key:
        v.encryption_mode === 'none' ? null : v.encryption_client_key.trim() || null,
      encryption_padding:
        v.encryption_mode === 'none' ? null : v.encryption_padding.trim() || null,
    },
    transport: buildTransport(v),
    security: buildSecurity(v),
    // `buildFinalMask` reads only the finalmask_* fields, which OutboundFormValues
    // carries via FinalMaskFormFields — the cast just bridges the wider param type.
    finalmask: buildFinalMask(v as unknown as InbFormValues),
    mux: { enabled: v.mux_enabled, concurrency: v.mux_concurrency },
    send_through: v.send_through.trim(),
    proxy_tag: v.proxy_tag.trim(),
    created_at: existing?.created_at ?? now,
    updated_at: now,
  };
}

/** Hydrate the flat form from a stored outbound (edit path). */
export function outboundToForm(ob: CustomOutbound): OutboundFormValues {
  const d: OutboundFormValues = { ...OUTBOUND_DEFAULTS };
  d.tag = ob.tag;
  d.enabled = ob.enabled;

  if (ob.protocol.kind === 'vless') {
    const p = ob.protocol;
    d.address = p.address;
    d.port = p.port;
    d.uuid = p.id;
    d.flow = p.flow;
    d.encryption_mode = p.encryption_mode;
    d.encryption_xor_mode = p.encryption_xor_mode ?? 'native';
    d.encryption_client_key = p.encryption_client_key ?? '';
    d.encryption_padding = p.encryption_padding ?? '';
  }

  const tr = ob.transport;
  d.network = tr.kind === 'hysteria' ? 'tcp' : tr.kind;
  const toPairs = (h: { [k: string]: string } | null): HeaderPair[] =>
    h ? Object.entries(h).map(([name, value]) => ({ name, value })) : [];
  if (tr.kind === 'ws') {
    d.ws_path = tr.path ?? '/';
    d.ws_host = tr.host ?? '';
    d.ws_headers = toPairs(tr.headers);
    d.ws_heartbeat_period = tr.heartbeat_period ?? null;
  } else if (tr.kind === 'xhttp') {
    d.xhttp_path = tr.path ?? '/';
    d.xhttp_host = tr.host ?? '';
    d.xhttp_mode = tr.mode ?? 'auto';
    d.xhttp_headers = toPairs(tr.headers);
    d.xhttp_x_padding_bytes = tr.x_padding_bytes ?? '';
    d.xhttp_x_padding_obfs_mode = tr.x_padding_obfs_mode ?? false;
    d.xhttp_x_padding_key = tr.x_padding_key ?? '';
    d.xhttp_x_padding_header = tr.x_padding_header ?? '';
    d.xhttp_x_padding_placement = tr.x_padding_placement ?? '';
    d.xhttp_x_padding_method = tr.x_padding_method ?? '';
    d.xhttp_session_placement = tr.session_id_placement ?? '';
    d.xhttp_session_key = tr.session_id_key ?? '';
    d.xhttp_session_id_table = tr.session_id_table ?? '';
    d.xhttp_session_id_length = tr.session_id_length ?? '';
    d.xhttp_seq_placement = tr.seq_placement ?? '';
    d.xhttp_seq_key = tr.seq_key ?? '';
    d.xhttp_uplink_data_placement = tr.uplink_data_placement ?? '';
    d.xhttp_uplink_data_key = tr.uplink_data_key ?? '';
  }

  const s = ob.security;
  d.security = s.kind;
  if (s.kind === 'tls') {
    d.tls_server_name = s.server_name ?? '';
    d.tls_alpn = s.alpn ?? [];
    d.tls_fingerprint = s.fingerprint ?? 'chrome';
    d.tls_verify_peer_cert_by_name = s.verify_peer_cert_by_name ?? [];
    d.tls_pinned_peer_cert_sha256 = s.pinned_peer_cert_sha256 ?? [];
  } else if (s.kind === 'reality') {
    d.reality_server_name = s.server_names[0] ?? '';
    d.reality_public_key = s.public_key;
    d.reality_short_id = s.short_ids[0] ?? '';
    d.reality_fingerprint = s.fingerprint;
    d.reality_spider_x = s.spider_x || '/';
  }

  d.mux_enabled = ob.mux.enabled;
  d.mux_concurrency = ob.mux.concurrency;
  d.send_through = ob.send_through;
  d.proxy_tag = ob.proxy_tag;

  // FinalMask hydration — shares the inbound adapter's mapper.
  hydrateFinalMask(d, ob.finalmask);
  return d;
}
