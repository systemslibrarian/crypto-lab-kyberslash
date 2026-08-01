import { describe, expect, it } from 'vitest';

import {
  activeProbes,
  createAttackState,
  getRecoveredCoeff,
  oracleQueryTime,
  recoveredKeyFromState,
  runAttack,
  statisticalAnalysis,
  walkthroughCoefficient,
  type SecretKey,
} from './attack';
import { primaryCoefficientStep, setActivePlatform, type Platform } from './timing-model';

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

/**
 * The decision threshold sits midway between the two cost levels either side of
 * the active target's step. Derived, never hardcoded, because the step is
 * target-specific: coefficient 833 / +20 cycles on Cortex-A7 (the `divsi3`
 * jump, paper §5.1.1-§5.1.2), coefficient 192 / +2 cycles on Cortex-M4 (the
 * `udiv` crossover at 2^11, paper Table 4).
 */
function thresholdFor(platform: Platform): number {
  const step = primaryCoefficientStep(platform);
  return (step.fromCycles + step.toCycles) / 2;
}

describe('oracleQueryTime is a real step-crossing leak', () => {
  it.each(['cortex-a7', 'cortex-m4'] as const)(
    'produces the (fast/slow) signature per secret value on the vulnerable path (%s)',
    (platform) => {
      setActivePlatform(platform);
      const threshold = thresholdFor(platform);
      const [low, high] = activeProbes();
      const N = 400;

      // s = -1: neither probe reaches the step -> both fast.
      expect(meanOf(() => oracleQueryTime(-1, low, true), N)).toBeLessThan(threshold);
      expect(meanOf(() => oracleQueryTime(-1, high, true), N)).toBeLessThan(threshold);

      // s = 0: only the high probe reaches it -> low fast, high slow.
      expect(meanOf(() => oracleQueryTime(0, low, true), N)).toBeLessThan(threshold);
      expect(meanOf(() => oracleQueryTime(0, high, true), N)).toBeGreaterThan(threshold);

      // s = +1: both probes reach it -> both slow.
      expect(meanOf(() => oracleQueryTime(1, low, true), N)).toBeGreaterThan(threshold);
      expect(meanOf(() => oracleQueryTime(1, high, true), N)).toBeGreaterThan(threshold);

      setActivePlatform('cortex-a7');
    },
  );

  it('carries NO secret-dependent signal on the patched path', () => {
    setActivePlatform('cortex-a7');
    const [low, high] = activeProbes();
    const N = 2000;
    const a = meanOf(() => oracleQueryTime(-1, low, false), N);
    const b = meanOf(() => oracleQueryTime(0, high, false), N);
    const c = meanOf(() => oracleQueryTime(1, low, false), N);
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

    // The step it straddles is the paper's: numerator 3329, coefficient 833,
    // +20 cycles, and no `udiv` involved because gcc -Os calls `divsi3`.
    expect(zero.boundaryNumerator).toBe(3329);
    expect(zero.boundaryCoefficient).toBe(833);
    expect(zero.jumpCycles).toBe(20);
    expect(zero.divisionOp).toBe('__divsi3');

    // Probes are 832 / 833, and their honest 2*w + 1664 numerators straddle 3329.
    expect([zero.low.probe, zero.high.probe]).toEqual([832, 833]);
    expect(zero.low.dividend).toBe(3328);
    expect(zero.high.dividend).toBe(3330);
  });

  it('straddles the Table 4 udiv crossover instead when the target is cortex-m4', () => {
    setActivePlatform('cortex-m4');
    const zero = walkthroughCoefficient(0);

    expect(zero.boundaryNumerator).toBe(2048);
    expect(zero.boundaryCoefficient).toBe(192);
    expect(zero.jumpCycles).toBe(2);
    expect(zero.divisionOp).toBe('udiv');
    expect([zero.low.probe, zero.high.probe]).toEqual([191, 192]);
    expect(zero.low.dividend).toBe(2046);
    expect(zero.high.dividend).toBe(2048);

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
