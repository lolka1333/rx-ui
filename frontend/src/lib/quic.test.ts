import { describe, expect, it } from 'vitest';
import { MIN_RECEIVE_WINDOW, receiveWindowRule } from './quic';

describe('receive window floor', () => {
  const rule = receiveWindowRule('too small');

  it('lets empty, zero and the floor itself through', async () => {
    for (const v of [null, undefined, 0, MIN_RECEIVE_WINDOW, 8388608]) {
      await expect(rule.validator(undefined, v)).resolves.toBeUndefined();
    }
  });

  it('flags anything under the floor, as the core loader would', async () => {
    for (const v of [1, 1500, MIN_RECEIVE_WINDOW - 1]) {
      await expect(rule.validator(undefined, v)).rejects.toThrow('too small');
    }
  });
});
