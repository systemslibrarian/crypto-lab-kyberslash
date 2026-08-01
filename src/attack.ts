import { simulatedDivCycles } from './timing-model';

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
 * where `w = decompress(ciphertext) + secret` is the decrypted coefficient.
 * The udiv latency depends on the magnitude of the dividend `2*w + q/2`
 * (see timing-model.ts). Real CPUs cross a latency bucket boundary around
 * dividend = 2048, i.e. around `w = 192`.
 *
 * The attacker chooses a ciphertext whose decompressed contribution places `w`
 * one step *below* that boundary. Then the secret coefficient s in {-1,0,+1},
 * added by the device, decides whether `w` crosses the boundary:
 *
 *     probe t=191:  w = s + 191  -> crosses 192 only when s = +1
 *     probe t=192:  w = s + 192  -> crosses 192 when s in {0, +1}
 *
 * So each secret value yields a distinct pair of (fast / slow) outcomes:
 *
 *     s = -1 : (t191 fast, t192 fast)
 *     s =  0 : (t191 fast, t192 slow)
 *     s = +1 : (t191 slow, t192 slow)
 *
 * The attacker averages many noisy measurements per probe, compares each mean
 * against a decision threshold it derives purely from the *public* platform
 * timing model (the udiv latency table from the paper), and reconstructs the
 * secret from which boundaries were crossed. The secret is never indexed.
 */

const KYBER_Q = 3329;

/** Two attacker-chosen ciphertext offsets straddling the udiv bucket boundary. */
export const PROBE_LOW = 191; // crossed only by s = +1
export const PROBE_HIGH = 192; // crossed by s in {0, +1}
const PROBES = [PROBE_LOW, PROBE_HIGH] as const;

const MIN_SAMPLES_PER_PROBE = 12;

/**
 * Reference dividends immediately below / at the 2048 udiv bucket boundary.
 * The attacker knows these from the platform's public timing characteristics,
 * not from the secret. `2*191 + q/2 = 2046` (below), `2*192 + q/2 = 2048` (at).
 */
const BOUNDARY_DIVIDEND_BELOW = 2 * 191 + Math.floor(KYBER_Q / 2); // 2046
const BOUNDARY_DIVIDEND_ABOVE = 2 * 192 + Math.floor(KYBER_Q / 2); // 2048

interface AttackMetadata {
  recovered: Int16Array;
  /** Per-coefficient accumulated samples for each probe offset. */
  samples: Map<number, number[]>;
}

const stateMetadata = new WeakMap<AttackState, AttackMetadata>();

function createProbeBuckets(): Map<number, number[]> {
  return new Map(PROBES.map((probe) => [probe, []]));
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
    // Barrett reduction is constant-time: the cost is fixed regardless of the
    // secret operand or the attacker's probe, so both probes return the same
    // level (the boundary midpoint) plus ordinary measurement jitter. There is
    // no boundary to cross, hence no signal for the attacker.
    return simulatedDivCycles(BOUNDARY_DIVIDEND_ABOVE, KYBER_Q, true) / 2 +
      simulatedDivCycles(BOUNDARY_DIVIDEND_BELOW, KYBER_Q, true) / 2;
  }

  const w = normalizeCoefficient(secretCoefficient + probeOffset);
  const dividend = 2 * w + Math.floor(KYBER_Q / 2);
  return simulatedDivCycles(dividend, KYBER_Q, true);
}

/**
 * The decision threshold, derived purely from the attacker's knowledge of the
 * platform timing model — the midpoint of the two udiv latency levels at the
 * boundary. Recomputed each call so it tracks whichever platform is active.
 */
function boundaryThreshold(): number {
  const below = simulatedDivCycles(BOUNDARY_DIVIDEND_BELOW, KYBER_Q, false);
  const above = simulatedDivCycles(BOUNDARY_DIVIDEND_ABOVE, KYBER_Q, false);
  return (below + above) / 2;
}

/**
 * Reconstruct one secret coefficient from the measured per-probe means.
 * `crossedLow` <=> the s=+1 boundary was crossed; `crossedHigh` <=> the
 * s in {0,+1} boundary was crossed. This is pure inference from timing — the
 * true secret is never consulted.
 */
function inferCoefficient(lowMean: number, highMean: number, threshold: number): -1 | 0 | 1 {
  const crossedLow = lowMean >= threshold;
  const crossedHigh = highMean >= threshold;

  if (crossedLow) {
    return 1; // both boundaries crossed
  }
  if (crossedHigh) {
    return 0; // only the t=192 boundary crossed
  }
  return -1; // neither crossed
}

/** One probe's outcome in the single-coefficient walkthrough. */
export interface ProbeStep {
  probe: number;
  /** w = s + probe, the decrypted coefficient the device divides on. */
  w: number;
  /** The dividend 2*w + q/2 that the udiv instruction actually processes. */
  dividend: number;
  /** Noiseless cycle cost from the platform model. */
  cycles: number;
  /** True when this probe's dividend lands at/above the ~2048 boundary (slow). */
  slow: boolean;
}

export interface CoefficientWalkthrough {
  secret: -1 | 0 | 1;
  threshold: number;
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
  const step = (probe: number): ProbeStep => {
    const w = secret + probe;
    const dividend = 2 * normalizeCoefficient(w) + Math.floor(KYBER_Q / 2);
    const cycles = simulatedDivCycles(dividend, KYBER_Q, false);
    return { probe, w, dividend, cycles, slow: cycles >= threshold };
  };
  const low = step(PROBE_LOW);
  const high = step(PROBE_HIGH);
  const inferred = inferCoefficient(low.cycles, high.cycles, threshold);
  return { secret, threshold, low, high, inferred };
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
  const entries = PROBES.map((probe) => {
    const values = timingSamples.get(probe) ?? [];
    return { probe, values, mean: mean(values) };
  });

  const sampleCount = entries.reduce((running, entry) => running + entry.values.length, 0);
  if (sampleCount === 0) {
    return {
      distinguishable: false,
      confidenceLevel: 0,
      estimatedQueriesNeeded: MIN_SAMPLES_PER_PROBE * PROBES.length,
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
  // vulnerable path at least one probe lands a full bucket (~5 cycles on A7)
  // away; on the patched path every probe hugs the threshold, so this is ~0.
  const threshold = boundaryThreshold();
  const spread = Math.max(...entries.map((entry) => Math.abs(entry.mean - threshold)));
  // Proper t-statistic: the standard error of the mean shrinks as sqrt(N), so
  // averaging more noisy queries genuinely raises confidence. On the patched
  // path every probe hugs the threshold, so `spread` (and thus the statistic)
  // stays at the noise floor no matter how many queries are spent.
  const standardError = Math.sqrt(Math.max(pooledVariance, 1e-6) / sampleCount);
  const effectSize = spread / Math.max(standardError, 1e-6);
  const coverage = Math.min(1, sampleCount / (MIN_SAMPLES_PER_PROBE * PROBES.length * 2));
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

  const probe = PROBES[state.queries % PROBES.length];
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
    const lowMean = mean(state.timingProfile.get(PROBE_LOW) ?? []);
    const highMean = mean(state.timingProfile.get(PROBE_HIGH) ?? []);
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
