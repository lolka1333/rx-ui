import { describe, expect, it } from 'vitest';
import type { RoutingRule } from '@/api/types';
import { needsIpv4 } from './builtinOutbounds';
import { DNS_QUERY_STRATEGIES, strategyClashes } from './dnsPresets';

const rule = (outbound_tag: string, enabled = true) => ({ outbound_tag, enabled }) as RoutingRule;

describe('needsIpv4 (mirrors the backend config_gen::needs_ipv4)', () => {
  it('is off with no IPv4 domains and no rule pointing at it', () => {
    expect(needsIpv4([], [rule('direct'), rule('blocked')])).toBe(false);
  });
  it('is on as soon as one IPv4 domain is listed', () => {
    expect(needsIpv4(['example.com'], [])).toBe(true);
  });
  it('is on for an enabled rule that targets it, and only an enabled one', () => {
    expect(needsIpv4([], [rule('direct-ipv4')])).toBe(true);
    expect(needsIpv4([], [rule('direct-ipv4', false)])).toBe(false);
  });
});

describe('strategyClashes', () => {
  it('flags only the two pairs that leave no address family', () => {
    const clashing = DNS_QUERY_STRATEGIES.flatMap((s) =>
      DNS_QUERY_STRATEGIES.filter((p) => strategyClashes(s, p)).map((p) => `${s}/${p}`),
    );
    expect(clashing.sort()).toEqual(['UseIPv4/UseIPv6', 'UseIPv6/UseIPv4']);
  });
});
