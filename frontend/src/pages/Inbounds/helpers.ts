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

/** uTLS fingerprint presets exposed by both Reality and TLS+uTLS. Values must
 *  match xray's whitelist — `PresetFingerprints` + `ModernFingerprints` in
 *  `transport/internet/tls/tls.go` (xray-core v26.11.9). Generic "auto"
 *  presets come first: they track the newest hello for that browser, so
 *  `chrome` is Chrome 155 on a v26.11.9+ core and the newest that core knows on
 *  an older one. `random` rotates a modern hello per process; the
 *  version-pinned `hello*` entries let an operator nail an exact ClientHello
 *  when a specific one slips past DPI — at the price of every client core
 *  having to know that name. */
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
  // Version-pinned modern hellos (xray-core ModernFingerprints). Pinning one
  // reaches clients only through cores that know it: hellochrome_155 needs
  // v26.11.9+, and an older client core refuses the whole config over it.
  { value: 'hellochrome_155', label: 'hellochrome_155' },
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

/** Every name xray v26.11.9 resolves (`GetFingerprint`): the options above plus
 *  its `OtherFingerprints` — older hellos the dropdown does not offer but a
 *  pasted share link may carry. */
const KNOWN_FINGERPRINTS = new Set([
  ...FINGERPRINT_OPTIONS.map((o) => o.value),
  'randomizednoalpn',
  'hellorandomized',
  'hellorandomizedalpn',
  'hellorandomizednoalpn',
  'hellofirefox_auto',
  'hellofirefox_55',
  'hellofirefox_56',
  'hellofirefox_63',
  'hellofirefox_65',
  'hellofirefox_99',
  'hellofirefox_102',
  'hellofirefox_105',
  'hellochrome_auto',
  'hellochrome_58',
  'hellochrome_62',
  'hellochrome_70',
  'hellochrome_72',
  'hellochrome_83',
  'hellochrome_87',
  'hellochrome_96',
  'hellochrome_100',
  'hellochrome_102',
  'hellochrome_106_shuffle',
  'helloios_auto',
  'helloios_11_1',
  'helloios_12_1',
  'helloandroid_11_okhttp',
  'helloedge_85',
  'helloedge_auto',
  'hellosafari_16_0',
  'hellosafari_auto',
  'hello360_auto',
  'hello360_7_5',
  'helloqq_auto',
  'hellochrome_100_psk',
  'hellochrome_112_psk_shuf',
  'hellochrome_114_padding_psk_shuf',
  'hellochrome_115_pq',
  'hellochrome_115_pq_psk',
  'hellochrome_120_pq',
]);

/** Form rule for a fingerprint field. A name xray does not know is not ignored:
 *  the core refuses the whole config (`unknown "fingerprint"`) — on the
 *  client's side for an inbound's share link, on this panel's own core for an
 *  outbound. So a stored or pasted one is flagged before it is saved again.
 *  Empty stays allowed: the forms fill in "chrome". */
export function fingerprintRule(message: string) {
  return {
    validator: (_: unknown, value: string | undefined) =>
      !value || KNOWN_FINGERPRINTS.has(value.trim().toLowerCase())
        ? Promise.resolve()
        : Promise.reject(new Error(message)),
  };
}
