import { describe, expect, it } from 'vitest';

import {
  createAttackState,
  getRecoveredCoeff,
  oracleQueryTime,
  recoveredKeyFromState,
  runAttack,
  statisticalAnalysis,
  walkthroughCoefficient,
  type SecretKey,
} from './attack';
import { setActivePlatform } from './timing-model';

function collapse(value: number): -1 | 0 | 1 {
  return value > 0 ? 1 : value < 0 ? -1 : 0;
}

function randomKey(length: number, seed: number): SecretKey {
  const coeffs = new Int16Array(length);
  let state = (seed ^ 0x2545f491) >>> 0;
  for (let index = 0; index < length; index += 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    coeffs[index] = ((state >>> 0) % 3) - 1; // {-1, 0, 1}
  }
  return { coeffs };
}

function meanOf(fn: () => number, n: number): number {
  let sum = 0;
  for (let i = 0; i < n; i += 1) sum += fn();
  return sum / n;
}

const PROBE_LOW = 191;
const PROBE_HIGH = 192;

describe('oracleQueryTime is a real boundary-crossing leak', () => {
  it('produces the (fast/slow) signature per secret value on the vulnerable path', () => {
    setActivePlatform('cortex-a7');
    // Decision threshold ~17.5 cycles between the two udiv levels (15 vs 20).
    const threshold = 17.5;
    const N = 400;

    // s = -1: neither boundary crossed -> both probes fast.
    expect(meanOf(() => oracleQueryTime(-1, PROBE_LOW, true), N)).toBeLessThan(threshold);
    expect(meanOf(() => oracleQueryTime(-1, PROBE_HIGH, true), N)).toBeLessThan(threshold);

    // s = 0: only the t=192 boundary crossed -> low fast, high slow.
    expect(meanOf(() => oracleQueryTime(0, PROBE_LOW, true), N)).toBeLessThan(threshold);
    expect(meanOf(() => oracleQueryTime(0, PROBE_HIGH, true), N)).toBeGreaterThan(threshold);

    // s = +1: both boundaries crossed -> both probes slow.
    expect(meanOf(() => oracleQueryTime(1, PROBE_LOW, true), N)).toBeGreaterThan(threshold);
    expect(meanOf(() => oracleQueryTime(1, PROBE_HIGH, true), N)).toBeGreaterThan(threshold);
  });

  it('carries NO secret-dependent signal on the patched path', () => {
    setActivePlatform('cortex-a7');
    const N = 2000;
    const a = meanOf(() => oracleQueryTime(-1, PROBE_LOW, false), N);
    const b = meanOf(() => oracleQueryTime(0, PROBE_HIGH, false), N);
    const c = meanOf(() => oracleQueryTime(1, PROBE_LOW, false), N);
    // All secret values collapse to the same constant-time cost (within jitter).
    expect(Math.abs(a - b)).toBeLessThan(0.3);
    expect(Math.abs(b - c)).toBeLessThan(0.3);
  });
});

describe('single-coefficient walkthrough matches the live attack model', () => {
  it('reproduces the (fast/slow) truth table and infers the true secret on A7', () => {
    setActivePlatform('cortex-a7');
    const minus = walkthroughCoefficient(-1);
    const zero = walkthroughCoefficient(0);
    const plus = walkthroughCoefficient(1);

    // The crux truth table the demo animates.
    expect([minus.low.slow, minus.high.slow]).toEqual([false, false]);
    expect([zero.low.slow, zero.high.slow]).toEqual([false, true]);
    expect([plus.low.slow, plus.high.slow]).toEqual([true, true]);

    // The walkthrough must recover exactly the secret it was fed — no fabrication.
    expect(minus.inferred).toBe(-1);
    expect(zero.inferred).toBe(0);
    expect(plus.inferred).toBe(1);

    // Dividends are the honest 2*w + q/2 straddling the 2048 boundary.
    expect(zero.low.dividend).toBe(2046);
    expect(zero.high.dividend).toBe(2048);
  });

  it('still infers correctly on the narrower-signal cortex-m4', () => {
    setActivePlatform('cortex-m4');
    for (const s of [-1, 0, 1] as const) {
      expect(walkthroughCoefficient(s).inferred).toBe(s);
    }
    setActivePlatform('cortex-a7');
  });
});

describe('honest key recovery driven by measured timing', () => {
  it('recovers arbitrary random keys, not just diagonal-friendly ones', async () => {
    setActivePlatform('cortex-a7');
    for (const seed of [1, 2, 3, 42]) {
      const key = randomKey(96, seed);
      const result = await runAttack(key, true, 20000);
      expect(result.matches, `seed ${seed}`).toBe(true);
      expect(result.recoveredKey).not.toBeNull();
      for (let i = 0; i < key.coeffs.length; i += 1) {
        expect(result.recoveredKey!.coeffs[i]).toBe(collapse(key.coeffs[i]));
      }
    }
  });

  it('reports recovered coefficients through the public grid accessor', async () => {
    setActivePlatform('cortex-a7');
    const key = randomKey(48, 7);
    const state = createAttackState(key);
    const { attackIteration } = await import('./attack');
    let guard = 0;
    while (state.currentCoefficient < key.coeffs.length && guard < 50000) {
      attackIteration(state, true);
      guard += 1;
    }
    for (let i = 0; i < key.coeffs.length; i += 1) {
      expect(getRecoveredCoeff(state, i)).toBe(collapse(key.coeffs[i]));
    }
    expect(recoveredKeyFromState(state)).not.toBeNull();
  });

  /**
   * HONESTY GUARD. The old implementation "recovered" the key by indexing a
   * hand-crafted matrix with the true secret, so it would have succeeded even
   * with a constant-time oracle. A genuine attack CANNOT: if the modelled leak
   * is removed (patched path), the timing carries no information and the key
   * must NOT be recoverable.
   */
  it('cannot recover the key when the leak is patched (constant-time oracle)', async () => {
    setActivePlatform('cortex-a7');
    const key = randomKey(96, 99);
    const patched = await runAttack(key, false, 20000);
    expect(patched.finalState.recoveredBits).toBe(0);
    expect(patched.recoveredKey).toBeNull();
    expect(patched.matches).toBe(false);
    expect(statisticalAnalysis(patched.finalState.timingProfile).distinguishable).toBe(false);
  });

  it('works across simulated platforms including the low-signal cortex-m4', async () => {
    for (const platform of ['cortex-a7', 'cortex-m4'] as const) {
      setActivePlatform(platform);
      const key = randomKey(64, 5);
      const result = await runAttack(key, true, 20000);
      expect(result.matches, platform).toBe(true);
    }
    setActivePlatform('cortex-a7');
  });
});
