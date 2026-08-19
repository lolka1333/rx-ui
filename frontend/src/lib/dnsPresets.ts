//! Quick-pick resolvers for the Xray -> DNS tab.
//!
//! The values are xray name-server strings exactly as `app/dns/nameserver.go`
//! parses them, so a preset and a hand-typed entry go down the same path - the
//! field stays `mode="tags"` and anything the backend validator accepts
//! (`tcp://`, `quic+local://`, a plain hostname) still works.
//!
//! Two spellings per provider on purpose. A bare IP is plain UDP on 53: fast,
//! and readable by anyone on the path. The `https://` form is DNS-over-HTTPS,
//! which hides the query - but xray sends those through its own routing and
//! outbounds, so on a relay the DoH request travels the same tunnel as the
//! traffic it is resolving for. `https+local://` is the third option:
//! encrypted, and resolved straight from the node instead of through the chain.
//!
//! Labels stay short, plain English and untranslated, matching `geoPresets`:
//! these are proper nouns, and the badge only repeats the transport.

export type DnsPreset = { value: string; label: string; code?: string };

export const DNS_PRESETS: DnsPreset[] = [
  { value: 'localhost', code: 'SYS', label: 'System resolver' },
  { value: '1.1.1.1', code: 'UDP', label: 'Cloudflare' },
  { value: '8.8.8.8', code: 'UDP', label: 'Google' },
  { value: '9.9.9.9', code: 'UDP', label: 'Quad9' },
  { value: '94.140.14.14', code: 'UDP', label: 'AdGuard' },
  { value: '77.88.8.8', code: 'UDP', label: 'Yandex' },
  { value: 'https://1.1.1.1/dns-query', code: 'DoH', label: 'Cloudflare' },
  { value: 'https://dns.google/dns-query', code: 'DoH', label: 'Google' },
  { value: 'https://dns.quad9.net/dns-query', code: 'DoH', label: 'Quad9' },
  { value: 'https+local://1.1.1.1/dns-query', code: 'DoH', label: 'Cloudflare, off-tunnel' },
];

export const DNS_PRESET_BY_VALUE = new Map(DNS_PRESETS.map((p) => [p.value, p]));

/** `dns.queryStrategy`: which address families the resolver may answer with.
 *  Mirrors `resolveQueryStrategy` in the core; `UseIP` is its default. */
export const DNS_QUERY_STRATEGIES = ['UseIP', 'UseIPv4', 'UseIPv6', 'UseSystem'] as const;

/** Whether a per-server strategy and the section-wide one leave the core
 *  nothing to ask for.
 *
 *  A per-server value does not replace the section's, it narrows it — the core
 *  intersects the two (`ResolveIpOptionOverride`). Ask for one family at the
 *  top and the other at a server and no family is left, at which point the core
 *  refuses the entire config, not just that server. The API rejects the pair;
 *  disabling the option keeps it from being picked in the first place. */
export function strategyClashes(section: string, perServer: string): boolean {
  return (
    (section === 'UseIPv4' && perServer === 'UseIPv6') ||
    (section === 'UseIPv6' && perServer === 'UseIPv4')
  );
}
