const KYBER_Q = 3329;
const DECAPSULATION_BASE_CYCLES = 1024;

export type Platform = 'cortex-a7' | 'cortex-m4';

/**
 * SIMULATED CPU timing model for integer division.
 *
 * Real ARM Cortex-A7 and Cortex-M4 take variable cycles for `udiv`
 * depending on operand magnitude. We cannot measure this from
 * JavaScript. Instead, we simulate the known leakage pattern.
 *
 * These bucket values are an ILLUSTRATIVE step function, not measurements
 * transcribed from the KyberSlash paper. What the paper actually reports:
 *
 *   Cortex-A7 / Raspberry Pi 2 (paper §5.1.1): with gcc -Os the division is
 *     NOT a `udiv` instruction at all — the default ABI does not guarantee one,
 *     so gcc emits a call to the `__divsi3` software routine, whose cost jumps
 *     by ~20 cycles when the numerator reaches 3329, by a further ~2 cycles at
 *     4096, and by a further ~1 cycle at 8192 (i.e. at coefficients t = 833,
 *     1216, 3264 for the dividend 2t + 1664).
 *   Cortex-M4 / STM32F407VG (paper Table 4): the `udiv` instruction takes
 *     2-12 cycles; with d = 3329 the crossovers sit at numerators
 *     1, 2^11, 2^15, 2^19, 2^23, 2^27, 2^31.
 *
 * The buckets below keep the same qualitative shape (a step function of
 * operand magnitude) with a boundary the demo's two-probe walkthrough can
 * straddle; they are not the paper's cycle counts.
 */
interface PlatformProfile {
  platform: Platform;
  label: string;
  baseCycles: number;
  scalingFactor: number;
  noiseAmplitude: number;
  buckets: readonly { ceiling: number; baseCycles: number; rangeWidth: number; rangeScale: number }[];
}

const PLATFORM_PROFILES: Record<Platform, PlatformProfile> = {
  'cortex-a7': {
    platform: 'cortex-a7',
    label: 'Raspberry Pi 2 · Cortex-A7',
    baseCycles: 7,
    scalingFactor: 3.0,
    noiseAmplitude: 1.5,
    buckets: [
      { ceiling: 256, baseCycles: 7, rangeWidth: 255, rangeScale: 2.25 },
      { ceiling: 2048, baseCycles: 12, rangeWidth: 1792, rangeScale: 3.0 },
      { ceiling: 8192, baseCycles: 20, rangeWidth: 6144, rangeScale: 3.0 },
      { ceiling: Number.POSITIVE_INFINITY, baseCycles: 30, rangeWidth: 8192, rangeScale: 3.0 },
    ],
  },
  'cortex-m4': {
    platform: 'cortex-m4',
    label: 'Embedded · Cortex-M4',
    baseCycles: 2,
    scalingFactor: 1.6,
    noiseAmplitude: 0.8,
    buckets: [
      { ceiling: 256, baseCycles: 2, rangeWidth: 255, rangeScale: 1.4 },
      { ceiling: 2048, baseCycles: 5, rangeWidth: 1792, rangeScale: 1.8 },
      { ceiling: 8192, baseCycles: 8, rangeWidth: 6144, rangeScale: 1.8 },
      { ceiling: Number.POSITIVE_INFINITY, baseCycles: 12, rangeWidth: 8192, rangeScale: 1.8 },
    ],
  },
};

/**
 * A single udiv latency band for teaching visuals: the operand-magnitude range
 * that maps to one nominal cycle cost. `floor` is inclusive, `ceiling` exclusive.
 * These are read straight off the same {@link PlatformProfile.buckets} the timing
 * model uses, so the "why division leaks" number line never diverges from the
 * cycle counts the attack actually sees.
 */
export interface LatencyBand {
  floor: number;
  ceiling: number;
  cycles: number;
  label: string;
}

/**
 * The udiv latency bands for a platform, as (magnitude range -> cycle cost).
 * Used only for on-screen teaching; the numbers come from the model's buckets.
 */
export function getLatencyBands(platform: Platform = activePlatform): LatencyBand[] {
  const profile = PLATFORM_PROFILES[platform];
  const bands: LatencyBand[] = [];
  let floor = 0;
  for (const bucket of profile.buckets) {
    const finite = Number.isFinite(bucket.ceiling);
    bands.push({
      floor,
      ceiling: bucket.ceiling,
      cycles: bucket.baseCycles,
      label: finite ? `${floor}–${bucket.ceiling - 1}` : `${floor}+`,
    });
    floor = finite ? bucket.ceiling : floor;
  }
  return bands;
}

/**
 * Which latency band a given dividend magnitude falls into (0-based index into
 * {@link getLatencyBands}). Pure lookup, mirrors {@link bucketedCycles}.
 */
export function latencyBandIndex(dividend: number, platform: Platform = activePlatform): number {
  const magnitude = Math.abs(Math.trunc(dividend));
  const profile = PLATFORM_PROFILES[platform];
  for (let index = 0; index < profile.buckets.length; index += 1) {
    if (magnitude < profile.buckets[index].ceiling) {
      return index;
    }
  }
  return profile.buckets.length - 1;
}

let activePlatform: Platform = 'cortex-a7';

export function setActivePlatform(platform: Platform): void {
  activePlatform = platform;
}

export function getActivePlatform(): Platform {
  return activePlatform;
}

export function getPlatformProfile(platform: Platform = activePlatform): PlatformProfile {
  return PLATFORM_PROFILES[platform];
}

export const PLATFORM_LABELS: Record<Platform, string> = {
  'cortex-a7': PLATFORM_PROFILES['cortex-a7'].label,
  'cortex-m4': PLATFORM_PROFILES['cortex-m4'].label,
};

export const TIMING_MODEL = PLATFORM_PROFILES['cortex-a7'];

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
  return (normalized * 2 - 1) * getPlatformProfile().noiseAmplitude;
}

function bucketedCycles(dividend: number): number {
  const magnitude = Math.abs(Math.trunc(dividend));
  const profile = getPlatformProfile();

  for (let index = 0; index < profile.buckets.length; index += 1) {
    const bucket = profile.buckets[index];
    if (magnitude < bucket.ceiling) {
      if (!Number.isFinite(bucket.ceiling)) {
        return (
          bucket.baseCycles +
          clamp(Math.log2(magnitude / bucket.rangeWidth + 1), 0, 1) * bucket.rangeScale
        );
      }
      const previousCeiling = index === 0 ? 0 : profile.buckets[index - 1].ceiling;
      return bucket.baseCycles + ((magnitude - previousCeiling) / bucket.rangeWidth) * bucket.rangeScale;
    }
  }

  const last = profile.buckets[profile.buckets.length - 1];
  return last.baseCycles + last.rangeScale;
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