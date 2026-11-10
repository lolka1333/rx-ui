import { describe, expect, it } from 'vitest';
import { fitCount } from './tagFit';

// Chips of 100 px, a "+N" chip of 30 px, 6 px between chips.
const four = [100, 100, 100, 100];

describe('fitCount', () => {
  it('shows every chip when they all fit, with no room kept for "+N"', () => {
    // 4 × 100 + 3 × 6 = 418
    expect(fitCount(four, 30, 6, 418)).toBe(4);
    expect(fitCount(four, 30, 6, 2000)).toBe(4);
  });

  it('keeps room for "+N" once a chip has to go', () => {
    // 3 chips + "+N" = 3 × 100 + 2 × 6 + 6 + 30 = 348
    expect(fitCount(four, 30, 6, 417)).toBe(3);
    expect(fitCount(four, 30, 6, 348)).toBe(3);
    expect(fitCount(four, 30, 6, 347)).toBe(2);
  });

  it('never drops below one chip, and has nothing to show for no chips', () => {
    expect(fitCount(four, 30, 6, 10)).toBe(1);
    expect(fitCount([], 30, 6, 500)).toBe(0);
  });

  it('follows the real widths, not a fixed count', () => {
    // Short names first: 3 short + "+N" fit where 2 long ones would.
    expect(fitCount([40, 40, 40, 300], 30, 6, 200)).toBe(3);
  });
});
