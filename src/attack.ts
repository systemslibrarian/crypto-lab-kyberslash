import {
  getPlatformProfile,
  kyberSlash1Dividend,
  primaryCoefficientStep,
  probeOffsets,
  simulatedDivCycles,
} from './timing-model';

/**
 * KyberSlash1 key-recovery oracle.
 *
 * This is a REAL adaptive timing attack against the modelled leak — it does
 * NOT read the secret and look it up in a table. The only place the secret
 * ever enters is inside the *device*, where decryption adds the secret
 * coefficient to the attacker-chosen ciphertext offset before the vulnerable
 * `poly_tomsg` division runs. The attacker sees nothing but a cycle count.
 *
 * How the leak is exploited
 * -------------------------
 * In `poly_tomsg` the device computes, per coefficient,
 *
 *     bit = ((2*w + q/2) / q) & 1        // q = 3329, division on a secret operand
 *
 * where `w = decompress(ciphertext) + secret` is the decrypted coefficient, so
 * the divider sees the dividend `2*w + 1664`. Its cost is a step function of
 * that dividend (see timing-model.ts), and the steps are target-specific:
 *
 *   Cortex-A7 / Raspberry Pi 2 (paper §5.1.1, §5.1.2): gcc -Os emits a call to
 *     the `__divsi3` SOFTWARE routine — no `udiv` runs at all — and its cost
 *     jumps by 20 cycles at numerator 3329, by 2 more at 4096 and 1 more at
 *     8192, i.e. at coefficients w = 833, 1216 and 3264.
 *   Cortex-M4 / STM32F407VG (paper Table 4): the hardware `udiv` instruction
 *     steps at numerator 2^11 = 2048, i.e. at coefficient w = 192. That is the
 *     only Table 4 crossover inside KyberSlash1's 1664…8320 numerator range.
 *
 * The attack straddles whichever step is biggest on the active target. Writing
 * T for that step's coefficient (833 on A7, 192 on M4), the attacker sends two
 * crafted ciphertexts whose decompressed contribution places `w` at T-1 and T.
 * The secret coefficient s in {-1,0,+1}, added by the device, then decides
 * which of them crosses:
 *
 *     probe t = T-1:  w = s + T - 1  -> crosses only when s = +1
 *     probe t = T:    w = s + T      -> crosses when s in {0, +1}
 *
 * So each secret value yields a distinct pair of (fast / slow) outcomes:
 *
 *     s = -1 : (low fast, high fast)
 *     s =  0 : (low fast, high slow)
 *     s = +1 : (low slow, high slow)
 *
 * The attacker averages many noisy measurements per probe, compares each mean
 * against a decision threshold it derives purely from the *public* platform
 * timing model (the paper's step measurements), and reconstructs the secret
 * from which boundaries were crossed. The secret is never indexed.
 *
 * Simplification worth naming: the paper's Pi 2 demo scales the secret by an
 * attacker-chosen coefficient û (e.g. 72), so a single secret value swings the
 * dividend right across the 3329 boundary and a handful of û values separate
 * all of Kyber512's -3…+3 range. This lab uses û = 1 and probes adjacent to the
 * step instead — the same mechanism with the arithmetic minimised, at the cost
 * of only resolving three secret values (see `generateSecretKey`).
 */

const KYBER_Q = 3329;

const MIN_SAMPLES_PER_PROBE = 12;

/**
 * The two attacker-chosen ciphertext offsets that straddle the active target's
 * biggest in-range cost step. Platform-derived, so switching targets moves the
 * probes to that target's real threshold rather than a hardcoded one.
 */
export function activeProbes(): readonly [low: number, high: number] {
  const { low, high } = probeOffsets();
  return [low, high];
}

/**
 * Reference dividends immediately below / at the active target's step. The
 * attacker knows these from the platform's public timing characteristics, not
 * from the secret.
 */
function boundaryDividends(): { below: number; above: number } {
  const [low, high] = activeProbes();
  return { below: kyberSlash1Dividend(low), above: kyberSlash1Dividend(high) };
}

interface AttackMetadata {
  recovered: Int16Array;
  /** Per-coefficient accumulated samples for each probe offset. */
  samples: Map<number, number[]>;
}

const stateMetadata = new WeakMap<AttackState, AttackMetadata>();

function createProbeBuckets(): Map<number, number[]> {
  return new Map(activeProbes().map((probe) => [probe, [] as number[]]));
}

function initializeAttackState(state: AttackState): AttackState {
  stateMetadata.set(state, {
    recovered: new Int16Array(state.targetKey.coeffs.length),
    samples: createProbeBuckets(),
  });

  return state;
}

function collapseCoefficient(value: number): -1 | 0 | 1 {
  if (value > 0) {
    return 1;
  }

  if (value < 0) {
    return -1;
  }

  return 0;
}

function normalizeCoefficient(coefficient: number): number {
  const rounded = Math.trunc(coefficient);
  return rounded < 0 ? rounded + KYBER_Q : rounded;
}

function mean(values: number[]): number {
  if (values.length === 0) {
    return 0;
  }

  return values.reduce((running, value) => running + value, 0) / values.length;
}

/**
 * The DEVICE side. Given the attacker's probe offset, the device decrypts
 * (adds the secret coefficient) and runs the vulnerable division, returning
 * the measured cycle count. The secret only appears here, inside the modelled
 * hardware, exactly as it would on a real Raspberry Pi. When the implementation
 * is patched the division is constant-time, so the offset carries no signal.
 */
export function oracleQueryTime(
  secretCoefficient: number,
  probeOffset: number,
  vulnerableImplementation: boolean,
): number {
  if (!vulnerableImplementation) {
    // Barrett reduction is constant-time: the cost is one fixed number no
    // matter what the secret or the probe is, so no step is ever crossed and
    // the attacker learns nothing. Modelled here as the decision midpoint plus
    // jitter, which makes "learns nothing" literal — the threshold test lands
    // on a coin flip. On a real patched device the constant would sit somewhere
    // definite and the same test would simply return the SAME verdict for every
    // coefficient, which is equally uninformative.
    const { below, above } = boundaryDividends();
    return (
      simulatedDivCycles(above, KYBER_Q, true) / 2 + simulatedDivCycles(below, KYBER_Q, true) / 2
    );
  }

  const w = normalizeCoefficient(secretCoefficient + probeOffset);
  return simulatedDivCycles(kyberSlash1Dividend(w), KYBER_Q, true);
}

/**
 * The decision threshold, derived purely from the attacker's knowledge of the
 * platform timing model — the midpoint of the two cost levels either side of
 * the target's step. Recomputed each call so it tracks whichever platform is
 * active.
 */
function boundaryThreshold(): number {
  const { below, above } = boundaryDividends();
  return (
    (simulatedDivCycles(below, KYBER_Q, false) + simulatedDivCycles(above, KYBER_Q, false)) / 2
  );
}

/**
 * Reconstruct one secret coefficient from the measured per-probe means.
 * `crossedLow` <=> the low probe crossed the step (only s = +1 does that);
 * `crossedHigh` <=> the high probe crossed it (s in {0,+1}). This is pure
 * inference from timing — the true secret is never consulted.
 */
function inferCoefficient(lowMean: number, highMean: number, threshold: number): -1 | 0 | 1 {
  const crossedLow = lowMean >= threshold;
  const crossedHigh = highMean >= threshold;

  if (crossedLow) {
    return 1; // both probes reached the step
  }
  if (crossedHigh) {
    return 0; // only the high probe reached the step
  }
  return -1; // neither probe reached the step
}

/** One probe's outcome in the single-coefficient walkthrough. */
export interface ProbeStep {
  probe: number;
  /** w = s + probe, the decrypted coefficient the device divides on. */
  w: number;
  /** The dividend 2*w + 1664 the divider actually processes. */
  dividend: number;
  /** Noiseless cycle cost from the platform model. */
  cycles: number;
  /** True when this probe's dividend lands at/above the target's step (slow). */
  slow: boolean;
}

export interface CoefficientWalkthrough {
  secret: -1 | 0 | 1;
  threshold: number;
  /** The numerator at which the active target's cost steps up. */
  boundaryNumerator: number;
  /** The coefficient value that boundary corresponds to. */
  boundaryCoefficient: number;
  /** Cycle cost either side of the step, and the jump between them. */
  fastCycles: number;
  slowCycles: number;
  jumpCycles: number;
  /** What performs the division on this target (`__divsi3` or `udiv`). */
  divisionOp: string;
  low: ProbeStep;
  high: ProbeStep;
  inferred: -1 | 0 | 1;
}

/**
 * Hand-crank the two-probe attack for ONE coefficient, exposing every
 * intermediate value so the UI can animate it: the chosen probe offset, the
 * device adding the hidden secret, the resulting dividend, which side of the
 * boundary it lands on, and the fast/slow readout that reconstructs the secret.
 *
 * This is the SAME math the live attack runs (oracleQueryTime + inferCoefficient
 * + boundaryThreshold), just single-stepped and noiseless so the causal chain is
 * legible. Nothing is fabricated — feed it s and it recomputes the honest result.
 */
export function walkthroughCoefficient(secret: -1 | 0 | 1): CoefficientWalkthrough {
  const threshold = boundaryThreshold();
  const boundary = primaryCoefficientStep();
  const [lowProbe, highProbe] = activeProbes();
  const step = (probe: number): ProbeStep => {
    const w = secret + probe;
    const dividend = kyberSlash1Dividend(normalizeCoefficient(w));
    const cycles = simulatedDivCycles(dividend, KYBER_Q, false);
    return { probe, w, dividend, cycles, slow: cycles >= threshold };
  };
  const low = step(lowProbe);
  const high = step(highProbe);
  const inferred = inferCoefficient(low.cycles, high.cycles, threshold);
  return {
    secret,
    threshold,
    boundaryNumerator: boundary.numerator,
    boundaryCoefficient: boundary.coefficient,
    fastCycles: boundary.fromCycles,
    slowCycles: boundary.toCycles,
    jumpCycles: boundary.jump,
    divisionOp: getPlatformProfile().divisionOp,
    low,
    high,
    inferred,
  };
}

/**
 * Simulated secret key. In a real attack, the attacker doesn't
 * know this — they recover it bit by bit.
 */
export interface SecretKey {
  coeffs: Int16Array;
}

/**
 * Generate a random 768-coefficient secret vector shaped like an ML-KEM-768 key.
 *
 * NOTE: a real ML-KEM-768 secret is sampled from CBD with η1 = 2, so its
 * coefficients lie in −2…+2. This demo draws CBD_2 and then collapses the
 * result to {−1, 0, +1} (`collapseCoefficient`) because the two-probe
 * walkthrough distinguishes exactly three values. It is a reduced, toy secret,
 * not a standards-conformant ML-KEM-768 key.
 *
 * The real attack does not need that reduction: the paper's Pi 2 demo scales
 * the secret by an attacker-chosen multiplier û so one coefficient value alone
 * swings the numerator across the 3329 step, and separates Kyber512's full
 * −3…+3 range by varying û — §5.1.2 works through û = 72 ("If s[0][155] happens
 * to be 3, then m′[255] mod 3329 is 3321, producing a slow division. Otherwise
 * m′[255] is between 64 and 424, producing a fast division"), then notes that
 * −72 distinguishes −3, 107 distinguishes {2,3}, "etc.". The Cortex-M4
 * KyberSlash2 attack separates Kyber768's −2…+2 with four (û, v̂) parameter
 * pairs (Table 3). This lab uses û = 1 and two adjacent probes, which is the
 * same mechanism with less bookkeeping and three resolvable values.
 */
export function generateSecretKey(): SecretKey {
  const raw = new Uint8Array(256 * 3);
  crypto.getRandomValues(raw);

  const coeffs = new Int16Array(raw.length);
  for (let index = 0; index < raw.length; index += 1) {
    const sample = raw[index];
    const positive = (sample & 1) + ((sample >> 1) & 1);
    const negative = ((sample >> 2) & 1) + ((sample >> 3) & 1);
    const centered = positive - negative;
    coeffs[index] = collapseCoefficient(centered);
  }

  return { coeffs };
}

export interface AttackState {
  targetKey: SecretKey;
  queries: number;
  recoveredBits: number;
  totalBits: number;
  /** Live timing samples for the coefficient currently under attack. */
  timingProfile: Map<number, number[]>;
  currentCoefficient: number;
}

export function createAttackState(secretKey: SecretKey): AttackState {
  return initializeAttackState({
    targetKey: secretKey,
    queries: 0,
    recoveredBits: 0,
    totalBits: secretKey.coeffs.length * 2,
    timingProfile: createProbeBuckets(),
    currentCoefficient: 0,
  });
}

export function recoveredKeyFromState(state: AttackState): SecretKey | null {
  const metadata = stateMetadata.get(state);
  if (!metadata || state.currentCoefficient !== state.targetKey.coeffs.length) {
    return null;
  }

  return { coeffs: new Int16Array(metadata.recovered) };
}

/**
 * Read a recovered coefficient if the attack has reached it.
 * Returns null when the index has not yet been processed.
 */
export function getRecoveredCoeff(state: AttackState, index: number): number | null {
  if (index < 0 || index >= state.targetKey.coeffs.length) {
    return null;
  }
  if (index >= state.currentCoefficient) {
    return null;
  }
  const metadata = stateMetadata.get(state);
  if (!metadata) {
    return null;
  }
  return metadata.recovered[index];
}

/**
 * Statistical test: can we distinguish the boundary-crossing signal from the
 * measurement noise floor? Operates purely on measured cycle counts.
 */
export function statisticalAnalysis(
  timingSamples: Map<number, number[]>,
): {
  distinguishable: boolean;
  confidenceLevel: number;
  estimatedQueriesNeeded: number;
} {
  // Iterate the caller's own buckets rather than the active platform's probe
  // offsets, so a profile captured on one target can still be analysed after a
  // platform switch (and so the verification scripts can feed synthetic ones).
  const entries = [...timingSamples.entries()].map(([probe, values]) => ({
    probe,
    values,
    mean: mean(values),
  }));

  if (entries.length === 0) {
    return { distinguishable: false, confidenceLevel: 0, estimatedQueriesNeeded: MIN_SAMPLES_PER_PROBE * 2 };
  }

  const sampleCount = entries.reduce((running, entry) => running + entry.values.length, 0);
  if (sampleCount === 0) {
    return {
      distinguishable: false,
      confidenceLevel: 0,
      estimatedQueriesNeeded: MIN_SAMPLES_PER_PROBE * entries.length,
    };
  }

  const pooledVariance =
    entries.reduce((running, entry) => {
      if (entry.values.length === 0) {
        return running;
      }
      const localMean = entry.mean;
      const variance =
        entry.values.reduce((partial, value) => partial + (value - localMean) * (value - localMean), 0) /
        entry.values.length;
      return running + variance;
    }, 0) / entries.length;

  // Signal = how far the probe means sit from the decision threshold. On the
  // vulnerable path every probe lands half a step away (10 cycles on the
  // Cortex-A7 __divsi3 model, 1 cycle on the Cortex-M4 udiv model); on the
  // patched path every probe hugs the threshold, so this is ~0.
  const threshold = boundaryThreshold();
  const spread = Math.max(...entries.map((entry) => Math.abs(entry.mean - threshold)));
  // Proper t-statistic: the standard error of the mean shrinks as sqrt(N), so
  // averaging more noisy queries genuinely raises confidence. On the patched
  // path every probe hugs the threshold, so `spread` (and thus the statistic)
  // stays at the noise floor no matter how many queries are spent.
  const standardError = Math.sqrt(Math.max(pooledVariance, 1e-6) / sampleCount);
  const effectSize = spread / Math.max(standardError, 1e-6);
  const coverage = Math.min(1, sampleCount / (MIN_SAMPLES_PER_PROBE * entries.length * 2));
  const confidenceLevel = Math.max(0, Math.min(0.999, ((effectSize - 0.35) / 1.4) * coverage));
  const distinguishable =
    entries.every((entry) => entry.values.length >= MIN_SAMPLES_PER_PROBE) && effectSize >= 1.35;

  return {
    distinguishable,
    confidenceLevel: Number(confidenceLevel.toFixed(3)),
    estimatedQueriesNeeded: distinguishable
      ? sampleCount
      : Math.max(sampleCount + 3, Math.ceil((1.35 / Math.max(effectSize, 0.05)) * sampleCount)),
  };
}

/**
 * Run one attack iteration: pick the next probe offset, query the device
 * oracle, record the measured cycle count, and — once enough samples have
 * accumulated for BOTH probes on the current coefficient — infer the secret
 * from the timing and advance. Nothing here reads the true secret.
 */
export function attackIteration(
  state: AttackState,
  vulnerableImplementation: boolean,
): {
  queryTime: number;
  bitsRecoveredThisRound: number;
  running: boolean;
} {
  if (state.currentCoefficient >= state.targetKey.coeffs.length) {
    return {
      queryTime: 0,
      bitsRecoveredThisRound: 0,
      running: false,
    };
  }

  const metadata = stateMetadata.get(state);
  if (!metadata) {
    throw new Error('attack state metadata was not initialized');
  }

  const probes = activeProbes();
  const probe = probes[state.queries % probes.length];
  // The device holds the secret; the attacker only supplies `probe`.
  const secretCoefficient = state.targetKey.coeffs[state.currentCoefficient];
  const queryTime = oracleQueryTime(secretCoefficient, probe, vulnerableImplementation);

  const bucket = state.timingProfile.get(probe);
  if (!bucket) {
    throw new Error(`missing timing bucket for probe ${probe}`);
  }

  bucket.push(queryTime);
  state.queries += 1;

  let bitsRecoveredThisRound = 0;
  const analysis = statisticalAnalysis(state.timingProfile);
  if (vulnerableImplementation && analysis.distinguishable) {
    const threshold = boundaryThreshold();
    const lowMean = mean(state.timingProfile.get(probes[0]) ?? []);
    const highMean = mean(state.timingProfile.get(probes[1]) ?? []);
    const recovered = inferCoefficient(lowMean, highMean, threshold);

    metadata.recovered[state.currentCoefficient] = recovered;
    state.currentCoefficient += 1;
    state.recoveredBits += 2;
    state.timingProfile = createProbeBuckets();
    bitsRecoveredThisRound = 2;
  }

  return {
    queryTime,
    bitsRecoveredThisRound,
    running: state.currentCoefficient < state.targetKey.coeffs.length,
  };
}

/**
 * Run the attack to completion (or stop at maxQueries).
 */
export async function runAttack(
  secretKey: SecretKey,
  vulnerableImplementation: boolean,
  maxQueries: number = 100000,
  onProgress?: (state: AttackState) => void,
): Promise<{
  finalState: AttackState;
  recoveredKey: SecretKey | null;
  matches: boolean;
  elapsedSimulatedTime: number;
}> {
  const state = createAttackState(secretKey);

  while (state.queries < maxQueries && state.currentCoefficient < secretKey.coeffs.length) {
    const result = attackIteration(state, vulnerableImplementation);

    if (onProgress && (result.bitsRecoveredThisRound > 0 || state.queries % 250 === 0)) {
      onProgress(state);
    }

    if (state.queries % 2000 === 0) {
      await Promise.resolve();
    }

    if (!result.running) {
      break;
    }
  }

  const metadata = stateMetadata.get(state);
  if (!metadata) {
    throw new Error('attack state metadata missing at completion');
  }

  const recoveredKey = vulnerableImplementation ? recoveredKeyFromState(state) : null;

  const matches =
    recoveredKey !== null &&
    recoveredKey.coeffs.every(
      (value, index) => value === collapseCoefficient(secretKey.coeffs[index]),
    );

  return {
    finalState: state,
    recoveredKey,
    matches,
    elapsedSimulatedTime: Number((state.queries * (1 / 1500)).toFixed(2)),
  };
}
