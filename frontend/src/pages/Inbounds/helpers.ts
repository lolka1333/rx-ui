//! Display helpers + small shared option lists used by the table and
//! several tabs. None of these own state — pure data / lookup.

import type { Inbound, TransportConfig, VlessFlow } from '@/api/types';

/** Operator-facing display label for a transport's table cell. */
export const TRANSPORT_LABEL: Record<TransportConfig['kind'], string> = {
  tcp: 'TCP',
  ws: 'WS',
  xhttp: 'XHTTP',
  hysteria: 'QUIC',
};

/** Tag colour used for the protocol-column chip. */
export const PROTOCOL_COLOR = 'geekblue';

export function vlessFlow(inb: Inbound): VlessFlow {
  return inb.protocol.kind === 'vless' ? inb.protocol.flow : 'none';
}

export function realityPublicKey(inb: Inbound): string {
  return inb.security.kind === 'reality' ? inb.security.public_key : '';
}

/** uTLS fingerprint presets exposed by both Reality and (future) TLS+uTLS.
 *  Values must match xray's whitelist — `PresetFingerprints` +
 *  `ModernFingerprints` in `transport/internet/tls/tls.go` (the latter
 *  pulled in by xray-core #6181 / commit 455f6bc2). Generic "auto"
 *  presets come first (they track the newest hello for that browser);
 *  `random` rotates a modern hello per process; the version-pinned
 *  `hello*` entries let an operator nail an exact ClientHello when a
 *  specific one slips past DPI. Unknown values are rejected by xray, so
 *  this list is the single source of truth for the dropdown. */
export const FINGERPRINT_OPTIONS = [
  // Generic auto presets (recommended default — newest hello per vendor)
  { value: 'chrome', label: 'chrome' },
  { value: 'firefox', label: 'firefox' },
  { value: 'safari', label: 'safari' },
  { value: 'ios', label: 'ios' },
  { value: 'android', label: 'android' },
  { value: 'edge', label: 'edge' },
  { value: '360', label: '360' },
  { value: 'qq', label: 'qq' },
  // Randomized — a fresh modern ClientHello chosen at startup / per dial
  { value: 'random', label: 'random' },
  { value: 'randomized', label: 'randomized' },
  // Version-pinned modern hellos (xray-core ModernFingerprints, #6181)
  { value: 'hellochrome_133', label: 'hellochrome_133' },
  { value: 'hellochrome_131', label: 'hellochrome_131' },
  { value: 'hellochrome_120', label: 'hellochrome_120' },
  { value: 'hellofirefox_148', label: 'hellofirefox_148' },
  { value: 'hellofirefox_120', label: 'hellofirefox_120' },
  { value: 'hellosafari_26_3', label: 'hellosafari_26_3' },
  { value: 'helloedge_106', label: 'helloedge_106' },
  { value: 'helloios_14', label: 'helloios_14' },
  { value: 'helloios_13', label: 'helloios_13' },
  { value: 'hello360_11_0', label: 'hello360_11_0' },
  { value: 'helloqq_11_1', label: 'helloqq_11_1' },
];
