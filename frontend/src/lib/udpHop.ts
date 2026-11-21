//! Port hopping (xray's `udphop` finalmask) as flat form fields, shared by the
//! Hysteria inbound form (where it only rides to clients in the share link)
//! and the Hysteria outbound form (where the panel's own client hops).

import type { UdpHop, UdpHopRemote } from '@/api/types';

/** The `hy_hop_*` fields both forms carry. */
export interface HopFormFields {
  hy_hop_local: boolean;
  hy_hop_remote: UdpHopRemote;
  hy_hop_ports: string;
  hy_hop_interval_min: number | null;
  hy_hop_interval_max: number | null;
}

export const HOP_DEFAULTS: HopFormFields = {
  hy_hop_local: false,
  hy_hop_remote: 'off',
  hy_hop_ports: '',
  hy_hop_interval_min: null,
  hy_hop_interval_max: null,
};

export function hopToForm(h: UdpHop | null | undefined): HopFormFields {
  if (!h) return { ...HOP_DEFAULTS };
  return {
    hy_hop_local: h.local,
    hy_hop_remote: h.remote,
    hy_hop_ports: h.ports,
    hy_hop_interval_min: h.interval_min,
    hy_hop_interval_max: h.interval_max,
  };
}

/** XICMP and `udphop` both open their own socket, and the core takes only one
 *  such mask — so under XICMP hopping is shown locked and never saved. */
export function hopBlockedByMask(maskKind: string | undefined): boolean {
  return maskKind === 'xicmp';
}

/** The stored `UdpHop`, or null when nothing hops (no block is kept then) or
 *  the mask rules it out. */
export function formToHop(v: HopFormFields & { finalmask_kind?: string }): UdpHop | null {
  if (hopBlockedByMask(v.finalmask_kind)) return null;
  if (!v.hy_hop_local && v.hy_hop_remote === 'off') return null;
  return {
    local: v.hy_hop_local,
    remote: v.hy_hop_remote,
    // Kept even with the server port fixed, so switching it back on later
    // brings the list back.
    ports: v.hy_hop_ports.trim(),
    interval_min: v.hy_hop_interval_min ?? null,
    interval_max: v.hy_hop_interval_max ?? null,
  };
}

/** The core's port-list syntax (`443,20000-30000`) as iptables wants it:
 *  `a-b` becomes `a:b`. Null when the list is empty or malformed. */
function iptablesPorts(ports: string): string[] | null {
  const items = ports
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (items.length === 0) return null;
  const out: string[] = [];
  for (const item of items) {
    const m = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/.exec(item);
    if (!m) return null;
    out.push(m[2] ? `${m[1]}:${m[2]}` : m[1]);
  }
  return out;
}

/** The two lines that send the hop range to the inbound's own port — xray
 *  listens on one port, so the server half of hopping is the host's job.
 *  Empty when the list is unusable or the port is unknown. */
export function hopRedirectCommands(ports: string, toPort: number | null | undefined): string[] {
  const list = iptablesPorts(ports);
  if (!list || !toPort) return [];
  const match =
    list.length === 1 ? `--dport ${list[0]}` : `-m multiport --dports ${list.join(',')}`;
  return ['iptables', 'ip6tables'].map(
    (bin) => `${bin} -t nat -A PREROUTING -p udp ${match} -j REDIRECT --to-ports ${toPort}`,
  );
}
