import { describe, expect, it } from 'vitest';

import {
  aggregateTimings,
  coefficientSteps,
  getActivePlatform,
  getDisplayBands,
  getLatencyBands,
  getPlatformProfile,
  kyberSlash1Dividend,
  KYBERSLASH1_NUMERATOR_MAX,
  KYBERSLASH1_NUMERATOR_MIN,
  primaryCoefficientStep,
  probeOffsets,
  setActivePlatform,
  simulatedDecapsulationTime,
  simulatedDivCycles,
  type Platform,
} from './timing-model';

describe('the KyberSlash1 numerator', () => {
  it('is 2t + 1664, spanning 1664…8320 over the coefficient range', () => {
    expect(kyberSlash1Dividend(0)).toBe(KYBERSLASH1_NUMERATOR_MIN);
    expect(kyberSlash1Dividend(3328)).toBe(KYBERSLASH1_NUMERATOR_MAX);
    expect(kyberSlash1Dividend(833)).toBe(3330);
    // Always even, so the 3329 boundary itself is never hit exactly.
    for (const t of [0, 1, 191, 192, 832, 833, 3328]) {
      expect(kyberSlash1Dividend(t) % 2).toBe(0);
    }
  });
});

describe('simulatedDivCycles leakage model', () => {
  it('is deterministic with noise disabled', () => {
    expect(simulatedDivCycles(1000, 3329, false)).toBe(simulatedDivCycles(1000, 3329, false));
  });

  it('is a pure step function — no drift inside a band', () => {
    setActivePlatform('cortex-a7');
    expect(simulatedDivCycles(1664, 3329, false)).toBe(simulatedDivCycles(3328, 3329, false));
    expect(simulatedDivCycles(3330, 3329, false)).toBe(simulatedDivCycles(4094, 3329, false));
  });

  /**
   * KyberSlash paper §5.1.1 (Raspberry Pi 2, gcc 8.3.0 -Os): gcc emits a call to
   * the `divsi3` software routine rather than a `udiv` instruction, and its cost
   * "jump[s] by 20 cycles when the numerator n reaches 3329, a further jump by
   * 2 cycles when n reaches 4096, and a further jump by 1 cycle when n reaches
   * 8192". The absolute base cost is not reported by the paper and is
   * illustrative here — only the deltas asserted below are sourced.
   */
  it('reproduces the paper §5.1.1 divsi3 steps on cortex-a7', () => {
    setActivePlatform('cortex-a7');
    const at = (n: number): number => simulatedDivCycles(n, 3329, false);

    expect(at(3329) - at(3328)).toBe(20);
    expect(at(4096) - at(4095)).toBe(2);
    expect(at(8192) - at(8191)).toBe(1);
    // No step at 2048 — that boundary is a hardware-udiv artefact and belongs
    // to the Cortex-M4 profile, not to this software-division target.
    expect(at(2048) - at(2047)).toBe(0);
  });

  /**
   * KyberSlash paper Table 4 (udiv on STM32F407VG). For d = 3329 the measured
   * costs are 2 cycles at n = 0, 3 for 1…2^11-1, 5 for 2^11…2^15-1, then
   * 6/7/8/9/10 from 2^15 / 2^19 / 2^23 / 2^27 / 2^31. Note there is no 4-cycle
   * case: the cost jumps straight from 3 to 5.
   */
  it('reproduces the paper Table 4 udiv costs on cortex-m4', () => {
    setActivePlatform('cortex-m4');
    const at = (n: number): number => simulatedDivCycles(n, 3329, false);

    expect(at(0)).toBe(2);
    expect(at(1)).toBe(3);
    expect(at(2047)).toBe(3);
    expect(at(2048)).toBe(5);
    expect(at(32767)).toBe(5);
    expect(at(32768)).toBe(6);
    expect(at(524288)).toBe(7);
    expect(at(8388608)).toBe(8);
    expect(at(134217728)).toBe(9);
    expect(at(2147483648)).toBe(10);
    setActivePlatform('cortex-a7');
  });

  it('averaging noisy measurements converges to the noiseless model', () => {
    setActivePlatform('cortex-a7');
    const noiseless = simulatedDivCycles(1000, 3329, false);
    const samples = Array.from({ length: 20000 }, () => simulatedDivCycles(1000, 3329, true));
    const { value } = aggregateTimings(samples, 'mean');
    expect(Math.abs(value - noiseless) / noiseless).toBeLessThan(0.01);
  });

  it('decapsulation time depends on secret coefficient magnitudes', () => {
    const low = new Int16Array(256);
    const high = new Int16Array(256);
    high.fill(1664);
    expect(simulatedDecapsulationTime(low, false)).not.toBe(simulatedDecapsulationTime(high, false));
  });

  it('exposes and restores the active platform', () => {
    const original: Platform = getActivePlatform();
    setActivePlatform('cortex-m4');
    expect(getActivePlatform()).toBe('cortex-m4');
    setActivePlatform(original);
  });
});

describe('cost steps expressed in the units the attacker controls', () => {
  /**
   * Paper §5.1.2: "there is a big jump in division cost on this platform when t
   * reaches 833, and there are smaller jumps when t reaches 1216 and 3264."
   */
  it('lands the cortex-a7 steps at coefficients 833, 1216 and 3264', () => {
    const steps = coefficientSteps('cortex-a7');
    expect(steps.map((step) => step.coefficient)).toEqual([833, 1216, 3264]);
    expect(steps.map((step) => step.numerator)).toEqual([3329, 4096, 8192]);
    expect(steps.map((step) => step.jump)).toEqual([20, 2, 1]);
    expect(primaryCoefficientStep('cortex-a7').coefficient).toBe(833);
    expect(probeOffsets('cortex-a7')).toEqual({ low: 832, high: 833 });
  });

  /**
   * On Cortex-M4 only ONE of Table 4's crossovers (2^11) falls inside the
   * 1664…8320 numerators this line can produce, so the attack has a single,
   * much smaller step to straddle.
   */
  it('leaves exactly one in-range step on cortex-m4, at coefficient 192', () => {
    const steps = coefficientSteps('cortex-m4');
    expect(steps).toHaveLength(1);
    expect(steps[0]).toMatchObject({ coefficient: 192, numerator: 2048, jump: 2 });
    expect(probeOffsets('cortex-m4')).toEqual({ low: 191, high: 192 });
  });

  it('only reports steps a reachable numerator can actually trigger', () => {
    for (const platform of ['cortex-a7', 'cortex-m4'] as const) {
      for (const step of coefficientSteps(platform)) {
        expect(step.numerator).toBeGreaterThan(KYBERSLASH1_NUMERATOR_MIN);
        expect(step.numerator).toBeLessThanOrEqual(KYBERSLASH1_NUMERATOR_MAX);
        expect(kyberSlash1Dividend(step.coefficient)).toBeGreaterThanOrEqual(step.numerator);
        expect(kyberSlash1Dividend(step.coefficient - 1)).toBeLessThan(step.numerator);
      }
    }
  });
});

describe('teaching bands stay tied to the model the attack uses', () => {
  it('draws every band the cortex-a7 profile defines', () => {
    const bands = getLatencyBands('cortex-a7');
    expect(bands.map((band) => band.floor)).toEqual([0, 3329, 4096, 8192]);
    expect(bands.map((band) => band.delta)).toEqual([0, 20, 22, 23]);
  });

  it('drops cortex-m4 bands that no reachable numerator can land in', () => {
    const displayed = getDisplayBands('cortex-m4');
    expect(displayed).toHaveLength(2);
    expect(displayed.map((band) => band.cycles)).toEqual([3, 5]);
  });

  it('keeps the drawn window wide enough to contain the reachable numerators', () => {
    for (const platform of ['cortex-a7', 'cortex-m4'] as const) {
      const { display } = getPlatformProfile(platform);
      expect(display.min).toBeLessThan(KYBERSLASH1_NUMERATOR_MIN);
      expect(display.max).toBeGreaterThan(KYBERSLASH1_NUMERATOR_MAX);
    }
  });
});
