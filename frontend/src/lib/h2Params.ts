//! h2Params presets that add up.
//!
//! The field is one JSON object whose keys are independent fields of Go's
//! `http.HTTP2Config`, so a preset is a piece of the document rather than a
//! whole one: switching it on writes its keys into what is already there,
//! switching it off takes them back out. Two presets that set the same keys —
//! the three ping timings — cannot both be on: the later one overwrites the
//! earlier, which is the only sensible reading of picking both.
//!
//! The ping and the write stall cover opposite halves of a half-open
//! connection. The ping catches a peer that stopped SENDING (nothing read for
//! SendPingTimeout, then no answer within PingTimeout); WriteByteTimeout
//! catches one that stopped READING (nothing could be written for that long).
//! A bridge that wedges with one direction dead is caught by one or the other,
//! which is why the two are worth having together.

export interface H2Preset {
  /** On the chip. Short and plain: the hint carries the meaning. */
  label: string;
  hint: string;
  params: Record<string, string | number>;
}

export const H2_PRESETS: readonly H2Preset[] = [
  {
    label: 'Ping 15s/5s',
    hint: 'Ping after 15s of silence, drop the peer if no answer in 5s',
    params: { SendPingTimeout: '15s', PingTimeout: '5s' },
  },
  {
    label: 'Ping 30s/10s',
    hint: 'Ping after 30s of silence, drop the peer if no answer in 10s',
    params: { SendPingTimeout: '30s', PingTimeout: '10s' },
  },
  {
    label: 'Ping 60s/15s',
    hint: 'Ping after 60s of silence, drop the peer if no answer in 15s',
    params: { SendPingTimeout: '60s', PingTimeout: '15s' },
  },
  {
    label: 'Write stall 30s',
    hint: 'Drop a peer that stops reading for 30s',
    params: { WriteByteTimeout: '30s' },
  },
  {
    label: 'Windows 4/8 MB',
    hint: 'Receive window: 4 MB per stream, 8 MB per connection',
    params: { MaxReceiveBufferPerStream: 4194304, MaxReceiveBufferPerConnection: 8388608 },
  },
];

export type H2Doc = Record<string, unknown>;

/** The field's text as an object: `{}` for an empty field, `null` for text
 *  that is not a JSON object — the operator is mid-edit, and a preset written
 *  over that would throw their typing away. */
export function parseH2(text: string | undefined): H2Doc | null {
  if (!text?.trim()) return {};
  try {
    const v: unknown = JSON.parse(text);
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as H2Doc) : null;
  } catch {
    return null;
  }
}

// Go's encoding/json matches keys case-insensitively, so a hand-typed
// `sendPingTimeout` is the same field as the preset's `SendPingTimeout`.
const fold = (key: string) => key.toLowerCase();

/** On when the document already holds every one of the preset's values. */
export function presetActive(doc: H2Doc | null, preset: H2Preset): boolean {
  if (!doc) return false;
  return Object.entries(preset.params).every(([key, value]) =>
    Object.entries(doc).some(([k, v]) => fold(k) === fold(key) && v === value),
  );
}

/** The document with the preset switched on or off, as the field's text.
 *
 *  On: each of the preset's keys replaces the document's own spelling of it
 *  in place — so the rest of the document keeps its order — and the keys it
 *  did not have go at the end. Off: those keys are removed. A document left
 *  with nothing in it is an empty field, not `{}`. */
export function togglePreset(doc: H2Doc, preset: H2Preset, on: boolean): string {
  const wanted = new Map(Object.entries(preset.params).map(([k, v]) => [fold(k), [k, v] as const]));
  const written = new Set<string>();
  const next: H2Doc = {};
  for (const [k, v] of Object.entries(doc)) {
    const hit = wanted.get(fold(k));
    if (!hit) {
      next[k] = v;
    } else if (on && !written.has(fold(k))) {
      // A key spelled twice in different case is one field to Go; it comes
      // out once, under the preset's spelling.
      next[hit[0]] = hit[1];
      written.add(fold(k));
    }
  }
  if (on) {
    for (const [lower, [k, v]] of wanted) {
      if (!written.has(lower)) next[k] = v;
    }
  }
  return Object.keys(next).length > 0 ? JSON.stringify(next, null, 2) : '';
}
