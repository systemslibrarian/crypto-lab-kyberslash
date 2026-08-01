const KYBER_Q = 3329;

/**
 * ILLUSTRATIVE. Everything in a decapsulation that is not one of the 256
 * modelled divisions, lumped into a constant. The paper does not report a
 * per-target decapsulation baseline for the Raspberry Pi 2, so this number is a
 * scale marker only — it never affects the attack, which reads *differences*.
 */
const DECAPSULATION_BASE_CYCLES = 1024;

export type Platform = 'cortex-a7' | 'cortex-m4';

/**
 * The vulnerable KyberSlash1 line in `poly_tomsg` is
 *
 *     t = (((t << 1) + KYBER_Q/2) / KYBER_Q) & 1;
 *
 * so the value handed to the divider for coefficient `t` is `2t + 1664`.
 * With `t` ranging over 0…3328 the numerator ranges over 1664…8320 — the
 * "range of interest" the paper profiles (KyberSlash paper §5.1.1, and the
 * project FAQ: "the numerator for attacker-chosen ciphertexts can be any even
 * number between 1664 and 8320").
 */
export const KYBERSLASH1_NUMERATOR_MIN = 1664;
export const KYBERSLASH1_NUMERATOR_MAX = 8320;

/** One step in the division cost as the numerator grows. */
export interface DivisionStep {
  /** Inclusive numerator at which the cost changes. */
  numerator: number;
  /** Cost from this numerator up to the next step, in cycles. */
  cycles: number;
}

export interface PlatformProfile {
  platform: Platform;
  label: string;
  /** Short name for the target board/CPU. */
  device: string;
  /** What actually performs the division on this target. */
  divisionOp: string;
  /** One sentence naming the mechanism, for on-screen prose. */
  mechanism: string;
  /** Where the step numbers come from. Rendered on screen. */
  source: string;
  /** What in this profile is NOT sourced from the paper. Rendered on screen. */
  illustrative: string;
  /** Cost when the numerator is below every step. */
  baseCycles: number;
  /** Steps, ascending by numerator. */
  steps: readonly DivisionStep[];
  /** Are `baseCycles`/`steps` absolute measurements, or a sourced delta on an
   *  illustrative base? Drives how the UI labels the numbers. */
  cycleBasis: 'absolute' | 'sourced-steps-on-illustrative-base';
  /** ILLUSTRATIVE measurement jitter amplitude for the simulated oscilloscope. */
  noiseAmplitude: number;
  /** ILLUSTRATIVE fixed cost of the patched (Barrett) path on this target.
   *  The paper does not benchmark the patch; all that matters pedagogically is
   *  that it is a single number that does not move with the operand. */
  patchedCycles: number;
  /** Numerator window the band graphic draws (log scale). */
  display: { min: number; max: number };
}

/**
 * Cortex-A7 / Raspberry Pi 2 — the paper's headline KyberSlash1 experiment.
 *
 * KyberSlash paper §5.1.1 ("Soft divisions"), on the Raspberry Pi 2 (BCM2836,
 * quad-core Cortex-A7 at 900MHz) running the Nov-2023 Kyber512 reference code
 * under Raspbian with gcc 8.3.0:
 *
 *   "On this platform, gcc -Os converts each division into a call to a division
 *    subroutine divsi3. The CPU includes a hardware division instruction, but by
 *    default gcc compiles for an ABI that does not guarantee division
 *    instructions. Checking the cost of the divsi3 subroutine for divisions of n
 *    by 3329 … shows that there is a jump by 20 cycles when the numerator n
 *    reaches 3329, a further jump by 2 cycles when n reaches 4096, and a further
 *    jump by 1 cycle when n reaches 8192."
 *
 * So on THIS target no `udiv` instruction executes at all. The 2048 boundary
 * that an earlier version of this lab used is a *hardware* `udiv` crossover
 * (2^11), which belongs to the Cortex-M4 profile below (paper Table 4), not
 * here.
 *
 * §5.1.2 restates the same steps in coefficient terms, which is what the attack
 * actually probes: "there is a big jump in division cost on this platform when
 * t reaches 833, and there are smaller jumps when t reaches 1216 and 3264."
 *
 * The paper reports the *steps*, not `__divsi3`'s absolute cost, so
 * `baseCycles` below is illustrative and flagged as such on screen. Every
 * difference the attack or the oscilloscope reads is sourced.
 *
 * Two naming notes. The paper's prose writes the routine `divsi3`; the symbol
 * gcc actually emits is `__divsi3`, which is what this lab shows so a reader can
 * grep for it in a real build. And the KyberSlash FAQ supplies the "why":
 * "that function uses branches depending on the inputs" — hence a step function
 * rather than a fixed cost.
 */
const CORTEX_A7: PlatformProfile = {
  platform: 'cortex-a7',
  label: 'Raspberry Pi 2 (BCM2836) · Cortex-A7',
  device: 'Raspberry Pi 2',
  divisionOp: '__divsi3',
  mechanism:
    "gcc -Os compiles for an ABI that does not guarantee a divide instruction, so the division becomes a call to the __divsi3 software routine, whose branches cost more as the numerator grows",
  source: 'KyberSlash, TCHES 2025(2), §5.1.1 and §5.1.2 (Raspberry Pi 2, gcc 8.3.0 -Os)',
  illustrative:
    "the paper reports the +20 / +2 / +1 cycle steps, not __divsi3's absolute cost — the base cost here is illustrative, only the steps are measured",
  baseCycles: 40,
  steps: [
    { numerator: 3329, cycles: 60 }, // +20 cycles
    { numerator: 4096, cycles: 62 }, // +2 cycles
    { numerator: 8192, cycles: 63 }, // +1 cycle
  ],
  cycleBasis: 'sourced-steps-on-illustrative-base',
  noiseAmplitude: 1.5,
  patchedCycles: 12,
  display: { min: 1024, max: 16384 },
};

/**
 * Cortex-M4 / STM32F407VG — the paper's second target.
 *
 * KyberSlash paper Table 4, "Clock cycles of udiv instruction with numerator n
 * and denominator d on Arm Cortex-M4 (STM32F407VG)", reverse engineered by the
 * authors and confirmed by exhaustive search for d = 3329. The d = 3329 column:
 *
 *     n = 0                    ->  2 cycles
 *     1        … 2^11 - 1      ->  3
 *     2^11     … 2^15 - 1      ->  5
 *     2^15     … 2^19 - 1      ->  6
 *     2^19     … 2^23 - 1      ->  7
 *     2^23     … 2^27 - 1      ->  8
 *     2^27     … 2^31 - 1      ->  9
 *     2^31     … 2^32 - 1      -> 10
 *
 * These are absolute measured cycle counts, unlike the A7 profile. Note the
 * consequence for KyberSlash1: inside the 1664…8320 numerator range this line
 * can produce, the ONLY crossover is 2^11 = 2048, worth 2 cycles. That is why
 * this lab treats Cortex-A7 as the primary target — the paper's own Cortex-M4
 * demo attacks KyberSlash2 (poly_compress), whose numerators span a far wider
 * range, not KyberSlash1.
 */
const CORTEX_M4: PlatformProfile = {
  platform: 'cortex-m4',
  label: 'STM32F407VG · Cortex-M4',
  device: 'STM32F407VG',
  divisionOp: 'udiv',
  mechanism:
    'the Cortex-M4 has a hardware udiv instruction whose latency is a step function of the numerator (2-12 cycles)',
  source: 'KyberSlash, TCHES 2025(2), Table 4 (udiv on STM32F407VG, d = 3329)',
  illustrative:
    'cycle counts are the paper’s measurements; the measurement jitter and the patched path’s fixed cost are illustrative',
  baseCycles: 2,
  steps: [
    { numerator: 1, cycles: 3 },
    { numerator: 2048, cycles: 5 },
    { numerator: 32768, cycles: 6 },
    { numerator: 524288, cycles: 7 },
    { numerator: 8388608, cycles: 8 },
    { numerator: 134217728, cycles: 9 },
    { numerator: 2147483648, cycles: 10 },
  ],
  cycleBasis: 'absolute',
  noiseAmplitude: 0.4,
  patchedCycles: 3,
  display: { min: 1024, max: 16384 },
};

const PLATFORM_PROFILES: Record<Platform, PlatformProfile> = {
  'cortex-a7': CORTEX_A7,
  'cortex-m4': CORTEX_M4,
};

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
  'cortex-a7': CORTEX_A7.label,
  'cortex-m4': CORTEX_M4.label,
};

export const TIMING_MODEL = CORTEX_A7;

/**
 * The dividend the vulnerable `poly_tomsg` line feeds to the divider for a
 * decrypted coefficient. `(t << 1) + KYBER_Q/2` == `2t + 1664`.
 */
export function kyberSlash1Dividend(coefficient: number): number {
  return 2 * Math.trunc(coefficient) + Math.floor(KYBER_Q / 2);
}

/**
 * One latency band for teaching visuals: the numerator range that maps to one
 * cycle cost. `floor` inclusive, `ceiling` exclusive. Read straight off the
 * platform profile the model itself uses, so the number line can never diverge
 * from the cycle counts the attack sees.
 */
export interface LatencyBand {
  floor: number;
  ceiling: number;
  cycles: number;
  /** Cycles relative to the platform's base cost (0 for the first band). */
  delta: number;
  label: string;
}

function bandsFor(profile: PlatformProfile): LatencyBand[] {
  const bands: LatencyBand[] = [];
  const boundaries = [{ numerator: 0, cycles: profile.baseCycles }, ...profile.steps];

  for (let index = 0; index < boundaries.length; index += 1) {
    const current = boundaries[index];
    const next = boundaries[index + 1];
    const ceiling = next ? next.numerator : Number.POSITIVE_INFINITY;
    bands.push({
      floor: current.numerator,
      ceiling,
      cycles: current.cycles,
      delta: current.cycles - profile.baseCycles,
      label: next ? `${current.numerator}–${ceiling - 1}` : `${current.numerator}+`,
    });
  }

  return bands;
}

/** Every latency band the platform model defines. */
export function getLatencyBands(platform: Platform = activePlatform): LatencyBand[] {
  return bandsFor(PLATFORM_PROFILES[platform]);
}

/**
 * The bands that actually intersect the window the band graphic draws. On
 * Cortex-M4 that is only two bands, because Table 4's other crossovers sit far
 * outside the 1664…8320 numerators KyberSlash1 can produce — which is exactly
 * the teaching point about auditing per target.
 */
export function getDisplayBands(platform: Platform = activePlatform): LatencyBand[] {
  const profile = PLATFORM_PROFILES[platform];
  return bandsFor(profile).filter(
    (band) => band.ceiling > profile.display.min && band.floor < profile.display.max,
  );
}

function indexIn(bands: LatencyBand[], dividend: number): number {
  const magnitude = Math.abs(Math.trunc(dividend));
  for (let index = bands.length - 1; index >= 0; index -= 1) {
    if (magnitude >= bands[index].floor) {
      return index;
    }
  }
  return 0;
}

/** Which band a dividend falls into (index into {@link getLatencyBands}). */
export function latencyBandIndex(dividend: number, platform: Platform = activePlatform): number {
  return indexIn(bandsFor(PLATFORM_PROFILES[platform]), dividend);
}

/** Which band a dividend falls into (index into {@link getDisplayBands}). */
export function displayBandIndex(dividend: number, platform: Platform = activePlatform): number {
  return indexIn(getDisplayBands(platform), dividend);
}

/**
 * A cost step expressed in the units the attacker controls: the *coefficient*
 * value at which the modelled division gets more expensive.
 *
 * On Cortex-A7 this reproduces the paper's §5.1.2 sentence exactly — the
 * numerator steps 3329 / 4096 / 8192 land at coefficients 833 / 1216 / 3264.
 */
export interface CoefficientStep {
  /** Smallest coefficient whose dividend reaches this step. */
  coefficient: number;
  /** The numerator boundary itself. */
  numerator: number;
  /** Cycle cost below the step. */
  fromCycles: number;
  /** Cycle cost at/above the step. */
  toCycles: number;
  /** toCycles - fromCycles. */
  jump: number;
}

/**
 * The cost steps reachable inside KyberSlash1's numerator range, expressed as
 * coefficient values. Cortex-A7: 833 (+20), 1216 (+2), 3264 (+1).
 * Cortex-M4: 192 (+2), the only Table 4 crossover in range.
 */
export function coefficientSteps(platform: Platform = activePlatform): CoefficientStep[] {
  const profile = PLATFORM_PROFILES[platform];
  const steps: CoefficientStep[] = [];
  let previousCycles = profile.baseCycles;

  for (const step of profile.steps) {
    if (step.numerator > KYBERSLASH1_NUMERATOR_MIN && step.numerator <= KYBERSLASH1_NUMERATOR_MAX) {
      steps.push({
        coefficient: Math.ceil((step.numerator - Math.floor(KYBER_Q / 2)) / 2),
        numerator: step.numerator,
        fromCycles: previousCycles,
        toCycles: step.cycles,
        jump: step.cycles - previousCycles,
      });
    }
    previousCycles = step.cycles;
  }

  return steps;
}

/** The largest in-range step — the one the two-probe attack straddles. */
export function primaryCoefficientStep(platform: Platform = activePlatform): CoefficientStep {
  const steps = coefficientSteps(platform);
  if (steps.length === 0) {
    throw new Error(`platform ${platform} has no cost step inside the KyberSlash1 numerator range`);
  }
  return steps.reduce((best, step) => (step.jump > best.jump ? step : best), steps[0]);
}

/**
 * The two attacker-chosen coefficient offsets that straddle the platform's
 * biggest in-range cost step. `low` is one below the step, `high` is on it, so
 * a secret in {-1, 0, +1} added by the device decides which of them crosses.
 *
 * Cortex-A7: 832 / 833 (the paper's t = 833 jump).
 * Cortex-M4: 191 / 192 (numerator 2048 = 2^11, Table 4).
 */
export function probeOffsets(platform: Platform = activePlatform): { low: number; high: number } {
  const step = primaryCoefficientStep(platform);
  return { low: step.coefficient - 1, high: step.coefficient };
}

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

/**
 * The modelled cost is a pure STEP function of the numerator — no interpolation
 * inside a band. That is what both sources describe: §5.1.1 gives discrete
 * jumps at 3329 / 4096 / 8192, and Table 4 gives one cycle count per range.
 */
function steppedCycles(dividend: number): number {
  const magnitude = Math.abs(Math.trunc(dividend));
  const profile = getPlatformProfile();

  let cycles = profile.baseCycles;
  for (const step of profile.steps) {
    if (magnitude >= step.numerator) {
      cycles = step.cycles;
    } else {
      break;
    }
  }

  return cycles;
}

/** The fixed, operand-independent cost of the patched Barrett path. */
export function patchedDivCycles(platform: Platform = activePlatform): number {
  return PLATFORM_PROFILES[platform].patchedCycles;
}

/**
 * Simulate the cycle count of `dividend / divisor` on the active target.
 * Deterministic step lookup, plus optional jitter to stand in for real
 * measurement noise.
 */
export function simulatedDivCycles(
  dividend: number,
  divisor: number,
  withNoise: boolean = true,
): number {
  if (!Number.isFinite(dividend) || !Number.isFinite(divisor) || divisor === 0) {
    throw new Error('simulatedDivCycles requires finite operands and a non-zero divisor');
  }

  const baseCycles = steppedCycles(dividend);

  if (!withNoise) {
    return Number(baseCycles.toFixed(3));
  }

  const noisyCycles = clamp(
    baseCycles + nextDeterministicNoise(dividend, divisor),
    0.5,
    Number.POSITIVE_INFINITY,
  );
  return Number(noisyCycles.toFixed(3));
}

/**
 * Simulate the total time for a full ML-KEM-768 decapsulation: one modelled
 * division per coefficient, on the `2t + 1664` dividend the real
 * `poly_tomsg` line divides, plus an illustrative fixed overhead.
 */
export function simulatedDecapsulationTime(
  coefficients: Int16Array,
  withNoise: boolean = true,
): number {
  let totalCycles = DECAPSULATION_BASE_CYCLES;

  for (let index = 0; index < coefficients.length; index += 1) {
    const dividend = kyberSlash1Dividend(normalizeCoefficient(coefficients[index]));
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
