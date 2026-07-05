//! Parse a `vless://` or `hysteria2://` share-link into outbound form values, so
//! the operator can paste a link and have the form fill itself. Mirrors the
//! field mapping the backend round-trips. Other schemes raise a clear message.

import type {
  OutboundFormValues,
} from './form';
import type { VlessXorMode, XhttpMode } from '@/api/types';

/** Thrown on any parse problem. Carries an i18n key (+ optional interpolation
 *  params) rather than a literal string, so the UI layer renders the message in
 *  the active language. */
export class LinkParseError extends Error {
  constructor(
    public readonly i18nKey: string,
    public readonly params?: Record<string, unknown>,
  ) {
    super(i18nKey);
  }
}

function parsePort(s: string): number {
  const p = Number.parseInt(s, 10);
  if (!Number.isFinite(p) || p < 1 || p > 65535) {
    throw new LinkParseError('outbounds.linkErrHostPort');
  }
  return p;
}

/** Split `host:port`, honouring bracketed IPv6 (`[::1]:443`). */
function splitHostPort(hostport: string): [string, string] {
  if (hostport.startsWith('[')) {
    const close = hostport.indexOf(']');
    if (close < 0) throw new LinkParseError('outbounds.linkErrIpv6');
    return [hostport.slice(1, close), hostport.slice(close + 2)];
  }
  const colon = hostport.lastIndexOf(':');
  return colon >= 0
    ? [hostport.slice(0, colon), hostport.slice(colon + 1)]
    : [hostport, ''];
}

/**
 * Parse a vless:// or hysteria2:// share-link into a partial set of outbound
 * form values (hysteria2:// / hy2:// dispatch to {@link parseHysteriaLink}).
 * Returns only the keys the link specifies; the caller overlays them on the
 * defaults. Throws {@link LinkParseError} (with a friendly message) on any
 * problem.
 */
export function parseOutboundLink(raw: string): Partial<OutboundFormValues> {
  const link = raw.trim();
  if (!link) throw new LinkParseError('outbounds.linkErrEmpty');

  const scheme = link.slice(0, link.indexOf('://')).toLowerCase();
  if (scheme === 'hysteria2' || scheme === 'hy2') {
    return parseHysteriaLink(link.slice(link.indexOf('://') + 3));
  }
  if (scheme !== 'vless') {
    const known = ['vmess', 'trojan', 'ss'];
    throw known.includes(scheme)
      ? new LinkParseError('outbounds.linkErrScheme', { scheme })
      : new LinkParseError('outbounds.linkErrUnknown');
  }

  // vless://UUID@HOST:PORT?QUERY#NAME
  const body = link.slice('vless://'.length);
  const hashAt = body.indexOf('#');
  const name = hashAt >= 0 ? safeDecode(body.slice(hashAt + 1)) : '';
  const beforeHash = hashAt >= 0 ? body.slice(0, hashAt) : body;
  const qAt = beforeHash.indexOf('?');
  const query = qAt >= 0 ? beforeHash.slice(qAt + 1) : '';
  const authority = qAt >= 0 ? beforeHash.slice(0, qAt) : beforeHash;

  const at = authority.lastIndexOf('@');
  if (at < 0) {
    throw new LinkParseError('outbounds.linkErrNoUuid');
  }
  const uuid = safeDecode(authority.slice(0, at));
  const [host, portStr] = splitHostPort(authority.slice(at + 1));
  if (!host) throw new LinkParseError('outbounds.linkErrNoHost');

  const q = new URLSearchParams(query);
  const get = (k: string) => q.get(k) ?? '';

  const out: Partial<OutboundFormValues> = {
    tag: name,
    address: host,
    port: parsePort(portStr),
    uuid,
    // Collapse an unknown flow to empty — the form accepts only '' or
    // 'xtls-rprx-vision', mirroring how security/network below reject unknowns.
    flow: get('flow') === 'xtls-rprx-vision' ? 'xtls-rprx-vision' : '',
  };

  // --- VLESS encryption ---
  const enc = get('encryption');
  if (enc && enc.startsWith('mlkem768x25519plus')) {
    // mlkem768x25519plus . <xor> . 0rtt [ . <pad> ] . <client_key>
    const parts = enc.split('.');
    out.encryption_mode = 'mlkem768x25519plus';
    out.encryption_xor_mode = (parts[1] || 'native') as VlessXorMode;
    const rem = parts.slice(3); // everything after the "0rtt" token
    if (rem.length <= 1) {
      out.encryption_client_key = rem[0] ?? '';
      out.encryption_padding = '';
    } else {
      out.encryption_padding = rem.slice(0, -1).join('.');
      out.encryption_client_key = rem[rem.length - 1];
    }
  } else {
    out.encryption_mode = 'none';
  }

  // --- security (client side) ---
  const sec = get('security');
  out.security = sec === 'reality' || sec === 'tls' ? sec : 'none';
  if (out.security === 'reality') {
    out.reality_server_name = get('sni');
    out.reality_public_key = get('pbk');
    out.reality_short_id = get('sid');
    out.reality_fingerprint = get('fp') || 'chrome';
    out.reality_spider_x = get('spx') || '/';
  } else if (out.security === 'tls') {
    out.tls_server_name = get('sni');
    const alpn = get('alpn');
    out.tls_alpn = alpn
      ? alpn.split(',').map((s) => s.trim()).filter(Boolean)
      : [];
    out.tls_fingerprint = get('fp') || 'chrome';
  }

  // --- transport ---
  const type = get('type') || 'tcp';
  if (type === 'ws') {
    out.network = 'ws';
    out.ws_path = get('path') || '/';
    out.ws_host = get('host');
  } else if (type === 'xhttp' || type === 'splithttp') {
    out.network = 'xhttp';
    out.xhttp_path = get('path') || '/';
    out.xhttp_host = get('host');
    out.xhttp_mode = (get('mode') || 'auto') as XhttpMode;
    applyXhttpExtra(out, get('extra'));
  } else {
    out.network = 'tcp';
  }

  // --- FinalMask (fm) ---
  applyFinalMask(out, get('fm'));

  return out;
}

/**
 * Parse a `hysteria2://` (or `hy2://`) share-link. Shape:
 * `hysteria2://PASSWORD@HOST:PORT/?sni=…&insecure=1&pinSHA256=…#NAME`. The
 * password is the auth; QUIC is always TLS, so security is fixed to `tls` and
 * the cert knobs (sni / pin / accept-by-name) map onto the TLS security block.
 * `alpn` and salamander `obfs` are honoured too — the latter maps onto the
 * panel's native FinalMask salamander (a client that doesn't mirror it can't
 * complete the QUIC handshake).
 */
function parseHysteriaLink(body: string): Partial<OutboundFormValues> {
  const hashAt = body.indexOf('#');
  const name = hashAt >= 0 ? safeDecode(body.slice(hashAt + 1)) : '';
  const beforeHash = hashAt >= 0 ? body.slice(0, hashAt) : body;
  const qAt = beforeHash.indexOf('?');
  const query = qAt >= 0 ? beforeHash.slice(qAt + 1) : '';
  const authority = qAt >= 0 ? beforeHash.slice(0, qAt) : beforeHash;

  const at = authority.lastIndexOf('@');
  const auth = at >= 0 ? safeDecode(authority.slice(0, at)) : '';
  // Drop any path after `host:port` (links often carry a bare trailing `/`).
  let hostPart = at >= 0 ? authority.slice(at + 1) : authority;
  const slash = hostPart.indexOf('/');
  if (slash >= 0) hostPart = hostPart.slice(0, slash);
  const [host, portStr] = splitHostPort(hostPart);
  if (!host) throw new LinkParseError('outbounds.linkErrNoHost');

  const q = new URLSearchParams(query);
  const get = (k: string) => q.get(k) ?? '';
  // Fall back to the host as serverName when the link omits `sni` (common when
  // the host is already the cert's domain).
  const serverName = get('sni') || host;

  const out: Partial<OutboundFormValues> = {
    tag: name,
    protocol_kind: 'hysteria',
    address: host,
    port: parsePort(portStr),
    hysteria_auth: auth,
    security: 'tls',
    tls_server_name: serverName,
  };
  const pin = get('pinSHA256') || get('pinsha256');
  if (pin) {
    out.tls_pinned_peer_cert_sha256 = [pin];
  } else if (get('insecure') === '1' || get('insecure') === 'true') {
    // The panel models no plain allowInsecure — accept-by-name is the closest
    // equivalent for the typical self-signed hysteria server.
    out.tls_verify_peer_cert_by_name = [serverName];
  }
  // ALPN — hysteria2 is QUIC/h3, but honour whatever the link advertises.
  const alpn = get('alpn');
  out.tls_alpn = alpn ? alpn.split(',').map((s) => s.trim()).filter(Boolean) : [];
  // Salamander obfs → the panel's native FinalMask salamander. The client must
  // mirror the server's obfs password or the obfuscated QUIC never handshakes.
  if (get('obfs') === 'salamander') {
    out.finalmask_kind = 'salamander';
    out.finalmask_salamander_password = get('obfs-password');
  }
  return out;
}

/** Map the splithttp `extra` JSON (padding-obfs + session-id + seq + uplink). */
function applyXhttpExtra(out: Partial<OutboundFormValues>, extraRaw: string): void {
  if (!extraRaw) return;
  let ex: Record<string, unknown>;
  try {
    ex = JSON.parse(extraRaw) as Record<string, unknown>;
  } catch {
    return; // malformed extra — leave defaults
  }
  const s = (k: string) => (typeof ex[k] === 'string' ? (ex[k] as string) : '');
  out.xhttp_x_padding_obfs_mode = ex.xPaddingObfsMode === true;
  out.xhttp_x_padding_key = s('xPaddingKey');
  out.xhttp_x_padding_header = s('xPaddingHeader');
  out.xhttp_x_padding_placement = s('xPaddingPlacement');
  out.xhttp_x_padding_method = s('xPaddingMethod');
  out.xhttp_session_placement = s('sessionIDPlacement');
  out.xhttp_session_key = s('sessionIDKey');
  out.xhttp_session_id_table = s('sessionIDTable');
  out.xhttp_session_id_length = s('sessionIDLength');
  out.xhttp_seq_placement = s('seqPlacement');
  out.xhttp_seq_key = s('seqKey');
  out.xhttp_uplink_data_placement = s('uplinkDataPlacement');
  out.xhttp_uplink_data_key = s('uplinkDataKey');
}

interface FmItem {
  type?: string;
  settings?: Record<string, unknown>;
}

/** Map the `fm` JSON (`{tcp:[…],udp:[…]}`) into the finalmask form fields. */
function applyFinalMask(out: Partial<OutboundFormValues>, fmRaw: string): void {
  if (!fmRaw) return;
  let fm: { tcp?: FmItem[]; udp?: FmItem[] };
  try {
    fm = JSON.parse(fmRaw) as { tcp?: FmItem[]; udp?: FmItem[] };
  } catch {
    return;
  }
  const item = [...(fm.tcp ?? []), ...(fm.udp ?? [])][0];
  if (!item?.type || !item.settings) return;
  const st = item.settings;
  const arr = (k: string) => (Array.isArray(st[k]) ? (st[k] as unknown[]) : []);
  const str = (k: string) => (typeof st[k] === 'string' ? (st[k] as string) : '');

  if (item.type === 'fragment') {
    out.finalmask_kind = 'fragment';
    const packets = str('packets');
    if (packets === 'tlshello') {
      out.finalmask_fragment_packets_mode = 'tlshello';
    } else if (packets === '') {
      out.finalmask_fragment_packets_mode = 'all';
    } else {
      out.finalmask_fragment_packets_mode = 'range';
      const [a, b] = packets.split('-').map((x) => Number.parseInt(x.trim(), 10));
      if (Number.isFinite(a)) out.finalmask_fragment_packets_from = a;
      if (Number.isFinite(b)) out.finalmask_fragment_packets_to = b;
    }
    out.finalmask_fragment_lengths = arr('lengths').join(', ');
    out.finalmask_fragment_delays = arr('delays').join(', ');
  } else if (item.type === 'sudoku') {
    out.finalmask_kind = 'sudoku';
    out.finalmask_sudoku_password = str('password');
  } else if (item.type === 'noise') {
    out.finalmask_kind = 'noise';
    out.finalmask_noise_packet_hex = str('packet');
  } else if (item.type === 'salamander') {
    out.finalmask_kind = 'salamander';
    out.finalmask_salamander_password = str('password');
  }
}

/** `decodeURIComponent` that never throws on malformed input. */
function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
