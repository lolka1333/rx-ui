import { describe, expect, it } from 'vitest';
import type { CustomOutbound } from '@/api/types';
import { OUTBOUND_DEFAULTS, formToOutbound, outboundToForm, type OutboundFormValues } from './form';

// The same property as the inbound form's (see Inbounds/form/adapters.test.ts):
// in every shape an outbound can take, a form field that changes what is saved
// must come back when the outbound is reopened — otherwise the next save quietly
// resets it. Walks every key, so new fields are covered without edits here.

/** The payload without the parts a save stamps afresh (id, timestamps). */
function payload(ob: CustomOutbound): CustomOutbound {
  return { ...ob, id: '', created_at: '', updated_at: '' };
}

const save = (v: OutboundFormValues) => formToOutbound(v, null);
const reopen = (v: OutboundFormValues) => outboundToForm(save(v));

const CHOICES: Partial<Record<keyof OutboundFormValues, readonly unknown[]>> = {
  protocol_kind: ['vless', 'hysteria', 'wireguard'],
  network: ['tcp', 'ws', 'xhttp'],
  security: ['none', 'tls', 'reality'],
  flow: ['', 'xtls-rprx-vision'],
  encryption_mode: ['none', 'mlkem768x25519plus'],
  encryption_xor_mode: ['native', 'xorpub', 'random'],
  hy_congestion: ['', 'brutal', 'bbr'],
  xhttp_mode: ['auto', 'packet-up', 'stream-up', 'stream-one'],
  finalmask_kind: ['none', 'sudoku', 'fragment', 'noise', 'salamander', 'xmc', 'xicmp'],
  finalmask_sudoku_ascii: ['', 'prefer_entropy', 'prefer_ascii'],
  finalmask_fragment_packets_mode: ['tlshello', 'all', 'range'],
};

const SAMPLES: Partial<Record<keyof OutboundFormValues, unknown>> = {
  ws_headers: [{ name: 'X-Probe', value: 'v' }],
  xhttp_headers: [{ name: 'X-Probe', value: 'v' }],
  // Shown as the form formats it: comma-and-space separated bytes.
  wg_reserved: '1, 2, 3',
  finalmask_noise_items: [
    { packet_hex: 'abcd', rand_min: null, rand_max: null, delay_min: 1, delay_max: 2 },
    { packet_hex: '', rand_min: 7, rand_max: 9, delay_min: null, delay_max: null },
  ],
  finalmask_xmc_profiles: [
    {
      username: 'probe',
      uuid: '00000000-0000-0000-0000-000000000001',
      textures_value: 'tv',
      textures_signature: 'ts',
    },
  ],
  finalmask_fragment_lengths: '10-20',
  finalmask_fragment_delays: '1-2',
};

function probe(key: keyof OutboundFormValues, current: unknown): unknown {
  if (key in SAMPLES) return SAMPLES[key];
  const choices = CHOICES[key];
  if (choices) return choices.find((c) => c !== current);
  if (typeof current === 'boolean') return !current;
  if (typeof current === 'number') return current + 7;
  if (current === null) return 42;
  if (Array.isArray(current)) return ['probe-a', 'probe-b'];
  if (typeof current === 'string') return 'probe';
  throw new Error(`no probe for ${String(key)}`);
}

const SHAPES: Record<string, Partial<OutboundFormValues>> = {
  'vless tcp reality': {},
  'vless tcp reality + encryption': { encryption_mode: 'mlkem768x25519plus' },
  'vless tcp tls': { security: 'tls' },
  'vless tcp none, mux': { security: 'none', mux_enabled: true },
  'vless ws tls': { network: 'ws', security: 'tls' },
  'vless xhttp tls': { network: 'xhttp', security: 'tls' },
  'hysteria tls': { protocol_kind: 'hysteria', security: 'tls' },
  'hysteria brutal': { protocol_kind: 'hysteria', security: 'tls', hy_congestion: 'brutal' },
  'hysteria salamander': {
    protocol_kind: 'hysteria',
    security: 'tls',
    finalmask_kind: 'salamander',
  },
  'hysteria xicmp': { protocol_kind: 'hysteria', security: 'tls', finalmask_kind: 'xicmp' },
  wireguard: { protocol_kind: 'wireguard', security: 'none' },
  'wireguard warp': { protocol_kind: 'wireguard', security: 'none', wg_warp: true },
  'sudoku mask': { finalmask_kind: 'sudoku' },
  'fragment mask range': {
    finalmask_kind: 'fragment',
    finalmask_fragment_packets_mode: 'range',
    finalmask_fragment_packets_from: 2,
    finalmask_fragment_packets_to: 5,
  },
  'noise mask': { finalmask_kind: 'noise' },
  'xmc mask': { finalmask_kind: 'xmc' },
};

const FIELDS = Object.keys(OUTBOUND_DEFAULTS) as (keyof OutboundFormValues)[];

describe.each(Object.entries(SHAPES))('outbound form: %s', (_, overrides) => {
  const base: OutboundFormValues = { ...OUTBOUND_DEFAULTS, ...overrides };

  it('reopens into the same payload', () => {
    expect(payload(save(reopen(base)))).toEqual(payload(save(base)));
  });

  it('keeps the identity of an existing outbound on save', () => {
    const first = save(base);
    const again = formToOutbound(outboundToForm(first), first);
    expect(again.id).toBe(first.id);
    expect(again.created_at).toBe(first.created_at);
  });

  it.each(FIELDS)('keeps %s across a save and a reopen', (key) => {
    const edited = { ...base, [key]: probe(key, base[key]) } as OutboundFormValues;
    const sent = payload(save(edited));
    if (JSON.stringify(sent) === JSON.stringify(payload(save(base)))) return;
    const back = reopen(edited);
    expect(back[key]).toEqual(edited[key]);
    expect(payload(save(back))).toEqual(sent);
  });
});
