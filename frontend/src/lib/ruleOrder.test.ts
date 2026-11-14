import { describe, expect, it } from 'vitest';
import { activeSystemTokens, deriveRuleOrder } from './ruleOrder';

const move = (list: string[], from: number, to: number) => {
  const next = list.slice();
  const [m] = next.splice(from, 1);
  next.splice(to, 0, m);
  return next;
};

describe('deriveRuleOrder', () => {
  const sys = activeSystemTokens({ xray_blocked_ips: ['geoip:ru'] });

  it('fills a short stored order the way the backend does', () => {
    // Stored before the blocked-IP row existed: it is slotted in right after
    // the last built-in token already present (here the api pin, saved after
    // `a`), the unreferenced rule goes last, and the api pin is hoisted to the
    // front — the same steps, in the same order, as `ordered_rule_tokens`.
    expect(deriveRuleOrder(['a', 'api'], ['a', 'b'], sys)).toEqual([
      'api',
      'a',
      'blocked_ips',
      'b',
    ]);
  });

  it('drops tokens that no longer exist and repeated ones', () => {
    expect(deriveRuleOrder(['api', 'gone', 'a', 'a', 'ipv4'], ['a'], sys)).toEqual([
      'api',
      'blocked_ips',
      'a',
    ]);
  });

  /** The bug this exists for: the table writes the full derived list when a
   *  rule moves, so a stored `[]` and a rule moved away and back must come out
   *  the same, or the page offers to save nothing. */
  it('a rule moved away and back derives the stored order', () => {
    const ids = ['a', 'b', 'c'];
    const stored: string[] = [];
    const shown = deriveRuleOrder(stored, ids, sys);
    const there = move(shown, 2, 4);
    const back = move(there, 4, 2);
    expect(deriveRuleOrder(back, ids, sys)).toEqual(deriveRuleOrder(stored, ids, sys));
    expect(deriveRuleOrder(there, ids, sys)).not.toEqual(deriveRuleOrder(stored, ids, sys));
  });
});

describe('activeSystemTokens', () => {
  it('lists only the built-in rows that have something to match', () => {
    expect(activeSystemTokens({})).toEqual(['api']);
    expect(
      activeSystemTokens({
        xray_block_bittorrent: true,
        xray_blocked_domains: [],
        xray_direct_ips: ['10.0.0.0/8'],
        xray_ipv4_domains: ['example.com'],
      }),
    ).toEqual(['api', 'bittorrent', 'direct_ips', 'ipv4']);
  });
});
