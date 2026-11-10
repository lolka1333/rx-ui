import { describe, expect, it } from 'vitest';
import type { Client, TrafficSnapshot } from '@/api/types';
import { groupClients, type TrafficSnapshotMap } from './groups';

let seq = 0;
const row = (email: string, over: Partial<Client> = {}): Client =>
  ({
    id: `row-${++seq}`,
    inbound_id: `ib-${seq}`,
    email,
    enabled: true,
    disabled_reason: null,
    traffic_limit_bytes: null,
    expires_at: null,
    note: null,
    ...over,
  }) as Client;

const online = (email: string): TrafficSnapshotMap => ({ [email]: { online: true } as TrafficSnapshot });

describe('groupClients', () => {
  it('makes one group per email, sorted, with every row and inbound behind it', () => {
    const groups = groupClients(
      [row('b@t', { inbound_id: 'x' }), row('a@t'), row('b@t', { inbound_id: 'y' }), row('b@t', { inbound_id: 'x' })],
      '',
      'all',
      {},
    );
    expect(groups.map((g) => g.email)).toEqual(['a@t', 'b@t']);
    expect(groups[1].rows).toHaveLength(3);
    expect(groups[1].inboundIds).toEqual(['x', 'y']);
  });

  it('filters by an email substring, case-insensitively', () => {
    const groups = groupClients([row('Alice@t'), row('bob@t')], ' ALI ', 'all', {});
    expect(groups.map((g) => g.email)).toEqual(['Alice@t']);
  });

  it('judges the status filter on the whole group', () => {
    const rows = [
      row('on@t'),
      row('mixed@t'),
      row('mixed@t', { enabled: false, disabled_reason: 'manual' }),
      row('off@t', { enabled: false, disabled_reason: 'manual' }),
      row('quota@t', { enabled: false, disabled_reason: 'quota' }),
      row('late@t', { enabled: false, disabled_reason: 'expired' }),
    ];
    const pick = (f: Parameters<typeof groupClients>[2], stats: TrafficSnapshotMap = {}) =>
      groupClients(rows, '', f, stats).map((g) => g.email);
    expect(pick('enabled')).toEqual(['on@t']);
    // "disabled" is none enabled: the mixed group is neither.
    expect(pick('disabled')).toEqual(['late@t', 'off@t', 'quota@t']);
    expect(pick('quota')).toEqual(['quota@t']);
    expect(pick('expired')).toEqual(['late@t']);
    expect(pick('online', online('mixed@t'))).toEqual(['mixed@t']);
    expect(pick('all')).toHaveLength(5);
  });

  it('takes the per-email quota as the max of the rows, unlimited if any row is', () => {
    const [limited] = groupClients(
      [row('u@t', { traffic_limit_bytes: 5 }), row('u@t', { traffic_limit_bytes: 9 })],
      '',
      'all',
      {},
    );
    expect(limited.totalLimit).toBe(9);
    const [unlimited] = groupClients(
      [row('u@t', { traffic_limit_bytes: 5 }), row('u@t', { traffic_limit_bytes: null })],
      '',
      'all',
      {},
    );
    expect(unlimited.totalLimit).toBeNull();
  });

  it('shows the earliest expiry and the first note', () => {
    const [g] = groupClients(
      [
        row('u@t', { expires_at: '2030-05-01 00:00:00', note: null }),
        row('u@t', { expires_at: '2029-01-01 00:00:00', note: 'laptop' }),
        row('u@t', { expires_at: null, note: 'other' }),
      ],
      '',
      'all',
      {},
    );
    expect(g.expiresAt).toBe('2029-01-01 00:00:00');
    expect(g.note).toBe('laptop');
  });
});
