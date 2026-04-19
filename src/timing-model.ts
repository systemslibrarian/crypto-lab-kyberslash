const KYBER_Q = 3329;
const DECAPSULATION_BASE_CYCLES = 1024;

/**
 * SIMULATED CPU timing model for integer division.
 *
 * Real ARM Cortex-A7 and Cortex-M4 take variable cycles for `udiv`
 * depending on operand magnitude. We cannot measure this from
 * JavaScript. Instead, we simulate the known leakage pattern.
 *
 * Reference values from the KyberSlash paper (Table 3, approx.):
 *   Cortex-A7 udiv cycles:
 *     dividend 0-255:     ~7 cycles
 *     dividend 256-2047:  ~12 cycles
 *     dividend 2048-8191: ~20 cycles
 *     dividend 8192+:     ~30 cycles
 */
export const TIMING_MODEL = {
  platform: 'ARM_CORTEX_A7',
  baseCycles: 7,
  scalingFactor: 3.0,
  noiseAmplitude: 1.5,
} as const;

let noiseCounter = 0;

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

function normalizeCoefficient(coefficient: number): number {
  const rounded = Math.trunc(coefficient);
  return rounded < 0 ? rounded + KYBER_Q : rounded;
}

function nextDeterministicNoise(dividend: number, divisor: number): number {
  noiseCounter = (noiseCounter + 0x9e3779b9) >>> 0;
  let state = noiseCounter ^ ((dividend * 2654435761) >>> 0) ^ ((divisor * 2246822519) >>> 0);
  state ^= state << 13;
  state ^= state >>> 17;
  state ^= state << 5;

  const normalized = (state >>> 0) / 0xffffffff;
  return (normalized * 2 - 1) * TIMING_MODEL.noiseAmplitude;
}

function bucketedCycles(dividend: number): number {
  const magnitude = Math.abs(Math.trunc(dividend));

  if (magnitude < 256) {
    return TIMING_MODEL.baseCycles + (magnitude / 255) * (TIMING_MODEL.scalingFactor * 0.75);
  }

  if (magnitude < 2048) {
    return 12 + ((magnitude - 256) / (2048 - 256)) * TIMING_MODEL.scalingFactor;
  }

  if (magnitude < 8192) {
    return 20 + ((magnitude - 2048) / (8192 - 2048)) * TIMING_MODEL.scalingFactor;
  }

  return 30 + clamp(Math.log2(magnitude / 8192 + 1), 0, 1) * TIMING_MODEL.scalingFactor;
}

/**
 * Simulate cycle count for `dividend / divisor` on Cortex-A7.
 * Returns a deterministic cycle count based on the paper's model,
 * plus optional small noise to simulate real measurements.
 */
export function simulatedDivCycles(
  dividend: number,
  divisor: number,
  withNoise: boolean = true,
): number {
  if (!Number.isFinite(dividend) || !Number.isFinite(divisor) || divisor === 0) {
    throw new Error('simulatedDivCycles requires finite operands and a non-zero divisor');
  }

  const baseCycles = bucketedCycles(dividend);

  if (!withNoise) {
    return Number(baseCycles.toFixed(3));
  }

  const noisyCycles = clamp(baseCycles + nextDeterministicNoise(dividend, divisor), 1, Number.POSITIVE_INFINITY);
  return Number(noisyCycles.toFixed(3));
}

/**
 * Simulate the total time for a full ML-KEM-768 decapsulation
 * operation. Includes ~256 division operations (one per coefficient),
 * each with its own timing based on the coefficient value.
 */
export function simulatedDecapsulationTime(
  coefficients: Int16Array,
  withNoise: boolean = true,
): number {
  let totalCycles = DECAPSULATION_BASE_CYCLES;

  for (let index = 0; index < coefficients.length; index += 1) {
    const normalized = normalizeCoefficient(coefficients[index]);
    const dividend = (normalized << 1) + Math.floor(KYBER_Q / 2);
    totalCycles += simulatedDivCycles(dividend, KYBER_Q, withNoise);
  }

  return Number(totalCycles.toFixed(3));
}

/**
 * Aggregate timing measurements across many runs.
 * The attacker averages to reduce noise.
 */
export function aggregateTimings(
  measurements: number[],
  method: 'mean' | 'median' = 'mean',
): { value: number; stddev: number } {
  if (measurements.length === 0) {
    return { value: 0, stddev: 0 };
  }

  const ordered = [...measurements].sort((left, right) => left - right);
  const sum = ordered.reduce((running, value) => running + value, 0);
  const mean = sum / ordered.length;
  const midpoint = Math.floor(ordered.length / 2);
  const median =
    ordered.length % 2 === 0 ? (ordered[midpoint - 1] + ordered[midpoint]) / 2 : ordered[midpoint];
  const center = method === 'mean' ? mean : median;

  const variance =
    ordered.reduce((running, value) => running + (value - mean) * (value - mean), 0) / ordered.length;

  return {
    value: Number(center.toFixed(6)),
    stddev: Number(Math.sqrt(variance).toFixed(6)),
  };
}