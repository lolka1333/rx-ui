//! The outbound tags the backend emits into the bootstrap config by itself.
//!
//! Two screens have to agree on this: the routing editor offers them as rule
//! targets, and the Outbounds table lists them read-only above the custom
//! ones. `direct-ipv4` is the awkward one — it is grown on demand, and both
//! screens have to apply the same "on demand" test or one offers a target the
//! other says does not exist.
//!
//! Mirrors `config_gen::build_bootstrap_config`'s `needs_ipv4` and
//! `api::settings`' `VALID_RULE_TARGETS`.

import type { RoutingRule } from '@/api/types';

export const BUILTIN_OUTBOUND_TAGS = ['direct', 'blocked', 'direct-ipv4'] as const;

export type BuiltinOutboundTag = (typeof BUILTIN_OUTBOUND_TAGS)[number];

/** Is the on-demand IPv4-force outbound part of the running config? True once
 *  the IPv4-domains list is non-empty, or some enabled rule points at it. */
export function needsIpv4(ipv4Domains: readonly string[], rules: readonly RoutingRule[]): boolean {
  return (
    ipv4Domains.length > 0 ||
    rules.some((r) => r.enabled && r.outbound_tag === 'direct-ipv4')
  );
}
