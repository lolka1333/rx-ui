import { describe, expect, it } from 'vitest';
import { H2_PRESETS, parseH2, presetActive, togglePreset, type H2Preset } from './h2Params';

const preset = (label: string): H2Preset => {
  const p = H2_PRESETS.find((x) => x.label === label);
  if (!p) throw new Error(`no preset ${label}`);
  return p;
};
const ping15 = preset('Ping 15s/5s');
const ping30 = preset('Ping 30s/10s');
const stall = preset('Write stall 30s');
const windows = preset('Windows 4/8 MB');

/** Click `p` on (or off) in a field holding `text`; returns the new text. */
const click = (text: string, p: H2Preset, on = true) => togglePreset(parseH2(text)!, p, on);

describe('h2Params presets', () => {
  it('add up instead of replacing each other', () => {
    let text = '';
    for (const p of [ping30, stall, windows]) text = click(text, p);
    expect(parseH2(text)).toEqual({
      SendPingTimeout: '30s',
      PingTimeout: '10s',
      WriteByteTimeout: '30s',
      MaxReceiveBufferPerStream: 4194304,
      MaxReceiveBufferPerConnection: 8388608,
    });
    for (const p of [ping30, stall, windows]) expect(presetActive(parseH2(text), p)).toBe(true);
    expect(presetActive(parseH2(text), ping15)).toBe(false);
  });

  it('let one ping timing replace another in place', () => {
    const text = click(click(click('', ping30), stall), ping15);
    expect(Object.keys(parseH2(text)!)).toEqual(['SendPingTimeout', 'PingTimeout', 'WriteByteTimeout']);
    expect(presetActive(parseH2(text), ping15)).toBe(true);
    expect(presetActive(parseH2(text), ping30)).toBe(false);
  });

  it('take only their own keys out when switched off', () => {
    const text = click(click(click('', ping15), stall), stall, false);
    expect(parseH2(text)).toEqual({ SendPingTimeout: '15s', PingTimeout: '5s' });
  });

  it('leave an empty field, not {}, when the last one goes', () => {
    expect(click(click('', stall), stall, false)).toBe('');
  });

  it('read hand-typed keys in any case, the way Go does, and keep the rest', () => {
    const typed = '{"sendpingtimeout":"30s","pingTimeout":"10s","MaxConcurrentStreams":100}';
    expect(presetActive(parseH2(typed), ping30)).toBe(true);
    expect(parseH2(click(typed, stall))).toEqual({
      sendpingtimeout: '30s',
      pingTimeout: '10s',
      MaxConcurrentStreams: 100,
      WriteByteTimeout: '30s',
    });
    // A preset that overwrites them writes its own spelling, in place.
    expect(parseH2(click(typed, ping15))).toEqual({
      SendPingTimeout: '15s',
      PingTimeout: '5s',
      MaxConcurrentStreams: 100,
    });
  });

  it('fold a key spelled twice in different case into one', () => {
    const text = click('{"PingTimeout":"1s","pingtimeout":"2s"}', ping30);
    expect(parseH2(text)).toEqual({ PingTimeout: '10s', SendPingTimeout: '30s' });
  });

  it('count as on only when every value matches', () => {
    expect(presetActive(parseH2('{"SendPingTimeout":"30s"}'), ping30)).toBe(false);
    expect(presetActive(parseH2('{"SendPingTimeout":"30s","PingTimeout":"9s"}'), ping30)).toBe(false);
  });

  it('write pretty JSON the field can show', () => {
    expect(click('', stall)).toBe('{\n  "WriteByteTimeout": "30s"\n}');
  });
});

describe('parseH2', () => {
  it('treats an empty field as an empty document', () => {
    expect(parseH2('')).toEqual({});
    expect(parseH2('   ')).toEqual({});
    expect(parseH2(undefined)).toEqual({});
  });

  it.each(['{"SendPingTimeout":', '[1,2]', '"x"', 'null', '42'])(
    'refuses %s, which is not a JSON object',
    (text) => {
      expect(parseH2(text)).toBeNull();
      expect(presetActive(parseH2(text), ping30)).toBe(false);
    },
  );
});
