import { describe, expect, it } from 'vitest';

import {
  aggregateTimings,
  getActivePlatform,
  setActivePlatform,
  simulatedDecapsulationTime,
  simulatedDivCycles,
  type Platform,
} from './timing-model';

describe('simulatedDivCycles leakage model', () => {
  it('is deterministic with noise disabled', () => {
    expect(simulatedDivCycles(1000, 3329, false)).toBe(simulatedDivCycles(1000, 3329, false));
  });

  it('increases monotonically across udiv magnitude buckets (cortex-a7)', () => {
    setActivePlatform('cortex-a7');
    const tiny = simulatedDivCycles(0, 3329, false);
    const small = simulatedDivCycles(500, 3329, false);
    const medium = simulatedDivCycles(4000, 3329, false);
    const large = simulatedDivCycles(9000, 3329, false);
    expect(tiny).toBeGreaterThanOrEqual(6.9);
    expect(tiny).toBeLessThanOrEqual(7.6);
    expect(small).toBeGreaterThan(tiny);
    expect(medium).toBeGreaterThan(small);
    expect(large).toBeGreaterThan(medium);
  });

  it('crosses the 2048 dividend bucket boundary — the boundary the attack exploits', () => {
    setActivePlatform('cortex-a7');
    const below = simulatedDivCycles(2046, 3329, false);
    const above = simulatedDivCycles(2048, 3329, false);
    // A full bucket step so the boundary crossing is unambiguous under noise.
    expect(above - below).toBeGreaterThan(3);
  });

  it('averaging noisy measurements converges to the noiseless model', () => {
    const noiseless = simulatedDivCycles(1000, 3329, false);
    const samples = Array.from({ length: 20000 }, () => simulatedDivCycles(1000, 3329, true));
    const { value } = aggregateTimings(samples, 'mean');
    expect(Math.abs(value - noiseless) / noiseless).toBeLessThan(0.01);
  });

  it('leaks a smaller-but-nonzero boundary step on cortex-m4', () => {
    setActivePlatform('cortex-m4');
    const below = simulatedDivCycles(2046, 3329, false);
    const above = simulatedDivCycles(2048, 3329, false);
    expect(above - below).toBeGreaterThan(0.5);
    setActivePlatform('cortex-a7');
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
