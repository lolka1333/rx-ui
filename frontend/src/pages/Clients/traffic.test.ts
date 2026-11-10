import { describe, expect, it } from 'vitest';
import { bytesToTrafficForm, trafficFormToBytes } from './traffic';

const GiB = 1024 ** 3;

describe('traffic limit <-> form', () => {
  it('reads no quota as an empty field under the GB default', () => {
    expect(bytesToTrafficForm(null)).toEqual({ value: null, unit: 'GB' });
    expect(bytesToTrafficForm(0)).toEqual({ value: null, unit: 'GB' });
  });

  it('picks the largest unit that divides cleanly', () => {
    expect(bytesToTrafficForm(5 * GiB)).toEqual({ value: 5, unit: 'GB' });
    expect(bytesToTrafficForm(1024 * GiB)).toEqual({ value: 1, unit: 'TB' });
    expect(bytesToTrafficForm(1.5 * GiB)).toEqual({ value: 1536, unit: 'MB' });
  });

  it('turns empty or zero into no quota, and anything else into whole bytes', () => {
    expect(trafficFormToBytes(null, 'GB')).toBeNull();
    expect(trafficFormToBytes(0, 'GB')).toBeNull();
    expect(trafficFormToBytes(5, 'GB')).toBe(5 * GiB);
    expect(trafficFormToBytes(0.5, 'MB')).toBe(524288);
  });

  it('round-trips what the form can express', () => {
    for (const bytes of [GiB, 50 * GiB, 3 * 1024 * GiB, 100 * 1024 ** 2]) {
      const { value, unit } = bytesToTrafficForm(bytes);
      expect(trafficFormToBytes(value, unit)).toBe(bytes);
    }
  });
});
