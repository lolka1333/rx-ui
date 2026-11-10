import { describe, expect, it } from 'vitest';
import type { Inbound, InboundCreate } from '@/api/types';
import { formToCreate, formToUpdate, inboundToForm } from './adapters';
import { DEFAULTS } from './defaults';
import type { FormValues } from './types';

// The form is flat, the API is layered, and the two adapters translate. The bug
// they can hide is quiet: a field that `formToCreate` sends but `inboundToForm`
// does not read back. The operator saves it once, reopens the inbound, sees the
// default, saves again — and the value is gone without anyone touching it.
//
// So the property tested here is: in every shape an inbound can take, any form
// field that changes what is sent must come back from what is sent. It walks
// every key of `FormValues`, so a field added later is covered without editing
// this file.

/** What the backend hands back for a created inbound: the same layers. */
function stored(body: InboundCreate): Inbound {
  return {
    ...body,
    id: 'probe-id',
    enabled: true,
    listen: body.listen ?? '0.0.0.0',
    sniffing: body.sniffing!,
    finalmask: body.finalmask!,
    sockopt: body.sockopt!,
    created_at: '',
    updated_at: '',
  } as Inbound;
}

const reopen = (v: FormValues) => inboundToForm(stored(formToCreate(v)));

/** Values a field may take, for the ones that are not free text. */
const CHOICES: Partial<Record<keyof FormValues, readonly unknown[]>> = {
  protocol_kind: ['vless', 'hysteria2', 'wireguard'],
  network: ['tcp', 'ws', 'xhttp'],
  security: ['none', 'tls', 'reality'],
  vless_flow: ['none', 'xtls-rprx-vision'],
  vless_encryption_mode: ['none', 'mlkem768x25519plus'],
  vless_encryption_auth: ['mlkem768', 'x25519'],
  vless_encryption_xor_mode: ['native', 'xorpub', 'random'],
  xhttp_mode: ['auto', 'packet-up', 'stream-up', 'stream-one'],
  hysteria_masq_kind: ['notfound', 'file', 'proxy', 'string'],
  quic_congestion: ['default', 'reno', 'bbr', 'brutal', 'force-brutal'],
  finalmask_kind: ['none', 'sudoku', 'fragment', 'noise', 'salamander', 'xmc', 'xicmp'],
  finalmask_sudoku_ascii: ['', 'prefer_entropy', 'prefer_ascii'],
  finalmask_fragment_packets_mode: ['tlshello', 'all', 'range'],
  tls_min_version: ['', '1.2', '1.3'],
  tls_max_version: ['', '1.2', '1.3'],
};

/** Fields whose values have a shape a generic probe would not satisfy. */
const SAMPLES: Partial<Record<keyof FormValues, unknown>> = {
  vless_fallbacks: [
    { name: 'probe.example', alpn: 'h2', path: '/fb', type: 'tcp', dest: '127.0.0.1:8080', xver: 1 },
  ],
  tls_certificates: [
    {
      source: 'inline',
      cert: 'CERT',
      key: 'KEY',
      usage: 'encipherment',
      ocsp_stapling: 3600,
      build_chain: true,
      one_time_loading: false,
    },
  ],
  ws_headers: [{ name: 'X-Probe', value: 'v' }],
  xhttp_headers: [{ name: 'X-Probe', value: 'v' }],
  xhttp_h2_params: '{\n  "SendPingTimeout": "30s"\n}',
  // An item is literal bytes OR a random run, never both — xray rejects the pair.
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

function probe(key: keyof FormValues, current: unknown): unknown {
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

/** Every shape the form can produce, as overrides on top of DEFAULTS. */
const SHAPES: Record<string, Partial<FormValues>> = {
  'vless tcp reality': { sniffing_enabled: true },
  'vless tcp reality + encryption': { vless_encryption_mode: 'mlkem768x25519plus' },
  'vless tcp none': { security: 'none' },
  'vless ws tls': { network: 'ws', security: 'tls' },
  'vless xhttp tls': { network: 'xhttp', security: 'tls' },
  'vless xhttp tls packet-up': { network: 'xhttp', security: 'tls', xhttp_mode: 'packet-up' },
  'vless xhttp reality brutal quic': {
    network: 'xhttp',
    quic_congestion: 'brutal',
  },
  'hysteria2 notfound': { protocol_kind: 'hysteria2', security: 'tls' },
  'hysteria2 file': { protocol_kind: 'hysteria2', security: 'tls', hysteria_masq_kind: 'file' },
  'hysteria2 proxy': { protocol_kind: 'hysteria2', security: 'tls', hysteria_masq_kind: 'proxy' },
  'hysteria2 string': { protocol_kind: 'hysteria2', security: 'tls', hysteria_masq_kind: 'string' },
  'hysteria2 brutal': { protocol_kind: 'hysteria2', security: 'tls', quic_congestion: 'brutal' },
  'hysteria2 salamander': {
    protocol_kind: 'hysteria2',
    security: 'tls',
    finalmask_kind: 'salamander',
  },
  'hysteria2 xicmp': { protocol_kind: 'hysteria2', security: 'tls', finalmask_kind: 'xicmp' },
  wireguard: { protocol_kind: 'wireguard', security: 'none' },
  'sudoku mask': { finalmask_kind: 'sudoku' },
  'fragment mask tlshello': { finalmask_kind: 'fragment' },
  // The bounds are required in range mode (empty ones would mean another mode).
  'fragment mask range': {
    finalmask_kind: 'fragment',
    finalmask_fragment_packets_mode: 'range',
    finalmask_fragment_packets_from: 2,
    finalmask_fragment_packets_to: 5,
  },
  'noise mask': { finalmask_kind: 'noise' },
  'xmc mask': { finalmask_kind: 'xmc' },
};

const FIELDS = Object.keys(DEFAULTS) as (keyof FormValues)[];

describe.each(Object.entries(SHAPES))('inbound form: %s', (_, overrides) => {
  const base: FormValues = { ...DEFAULTS, ...overrides };

  it('reopens into the same payload', () => {
    expect(formToCreate(reopen(base))).toEqual(formToCreate(base));
  });

  it('builds the same layers for create and update', () => {
    const { enabled, ...update } = formToUpdate(base);
    expect(enabled).toBeNull();
    expect(update).toEqual(formToCreate(base));
  });

  it.each(FIELDS)('keeps %s across a save and a reopen', (key) => {
    const edited = { ...base, [key]: probe(key, base[key]) } as FormValues;
    const sent = formToCreate(edited);
    // A field this shape does not use changes nothing on the wire; there is
    // nothing to lose.
    if (JSON.stringify(sent) === JSON.stringify(formToCreate(base))) return;
    const back = reopen(edited);
    expect(back[key]).toEqual(edited[key]);
    expect(formToCreate(back)).toEqual(sent);
  });
});
