const PROBE_VALUES = [-1, 0, 1] as const;
const MIN_SAMPLES_PER_PROBE = 6;
const TARGET_QUERY_MINUTES = 1 / 1500;
const SIGNAL_MATRIX: Record<-1 | 0 | 1, Record<-1 | 0 | 1, number>> = {
  '-1': { '-1': 96, '0': 48, '1': 12 },
  '0': { '-1': 40, '0': 92, '1': 40 },
  '1': { '-1': 12, '0': 48, '1': 96 },
};

interface AttackMetadata {
  recovered: Int16Array;
}

const stateMetadata = new WeakMap<AttackState, AttackMetadata>();

function createTimingProfile(): Map<number, number[]> {
  return new Map(PROBE_VALUES.map((probe) => [probe, []]));
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

function deterministicNoise(seed: number): number {
  let state = (seed ^ 0xa511e9b3) >>> 0;
  state ^= state << 13;
  state ^= state >>> 17;
  state ^= state << 5;
  return ((state >>> 0) / 0xffffffff) * 24 - 12;
}

function mean(values: number[]): number {
  if (values.length === 0) {
    return 0;
  }

  return values.reduce((running, value) => running + value, 0) / values.length;
}

function simulateQueryTime(
  coefficientIndex: number,
  secret: -1 | 0 | 1,
  probe: -1 | 0 | 1,
  vulnerableImplementation: boolean,
  queryIndex: number,
): number {
  const baseline = 2875 + coefficientIndex * 0.25;
  const signal = vulnerableImplementation ? SIGNAL_MATRIX[secret][probe] : 52;
  const noise = deterministicNoise(queryIndex * 131 + coefficientIndex * 17 + probe * 19);
  return Number((baseline + signal + noise).toFixed(3));
}

function bestProbe(profile: Map<number, number[]>): -1 | 0 | 1 {
  let winner: -1 | 0 | 1 = 0;
  let bestMean = Number.NEGATIVE_INFINITY;

  for (const probe of PROBE_VALUES) {
    const candidateMean = mean(profile.get(probe) ?? []);
    if (candidateMean > bestMean) {
      bestMean = candidateMean;
      winner = probe;
    }
  }

  return winner;
}

/**
 * Simulated secret key. In a real attack, the attacker doesn't
 * know this — they recover it bit by bit.
 */
export interface SecretKey {
  coeffs: Int16Array;
}

/**
 * Generate a random ML-KEM-768 secret key (centered binomial dist).
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

/**
 * THE ATTACKER: Craft a ciphertext and submit to the victim.
 * Observe the decapsulation timing. Repeat many times.
 * Build a timing profile that correlates with secret key bits.
 */
export interface AttackState {
  targetKey: SecretKey;
  queries: number;
  recoveredBits: number;
  totalBits: number;
  timingProfile: Map<number, number[]>;
  currentCoefficient: number;
}

/**
 * Statistical test: can we distinguish the secret key bits from the
 * timing measurements?
 */
export function statisticalAnalysis(
  timingSamples: Map<number, number[]>,
): {
  distinguishable: boolean;
  confidenceLevel: number;
  estimatedQueriesNeeded: number;
} {
  const means = PROBE_VALUES.map((probe) => ({
    probe,
    values: timingSamples.get(probe) ?? [],
    mean: mean(timingSamples.get(probe) ?? []),
  })).sort((left, right) => right.mean - left.mean);

  const sampleCount = means.reduce((running, entry) => running + entry.values.length, 0);
  if (sampleCount === 0) {
    return {
      distinguishable: false,
      confidenceLevel: 0,
      estimatedQueriesNeeded: MIN_SAMPLES_PER_PROBE * PROBE_VALUES.length,
    };
  }

  const pooledVariance =
    means.reduce((running, entry) => {
      if (entry.values.length === 0) {
        return running;
      }

      const localMean = entry.mean;
      const variance =
        entry.values.reduce((partial, value) => partial + (value - localMean) * (value - localMean), 0) /
        entry.values.length;

      return running + variance;
    }, 0) / means.length;

  const spread = means[0].mean - means[1].mean;
  const effectSize = spread / Math.max(Math.sqrt(pooledVariance), 1);
  const coverage = Math.min(1, sampleCount / (MIN_SAMPLES_PER_PROBE * PROBE_VALUES.length * 2));
  const confidenceLevel = Math.max(0, Math.min(0.999, ((effectSize - 0.35) / 1.4) * coverage));
  const distinguishable =
    means.every((entry) => entry.values.length >= MIN_SAMPLES_PER_PROBE) && effectSize >= 1.35;

  return {
    distinguishable,
    confidenceLevel: Number(confidenceLevel.toFixed(3)),
    estimatedQueriesNeeded: distinguishable
      ? sampleCount
      : Math.max(sampleCount + 3, Math.ceil((1.35 / Math.max(effectSize, 0.05)) * sampleCount)),
  };
}

/**
 * Run one attack iteration: craft ciphertext, observe timing, update state.
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

  const probe = PROBE_VALUES[state.queries % PROBE_VALUES.length];
  const secret = collapseCoefficient(state.targetKey.coeffs[state.currentCoefficient]);
  const queryTime = simulateQueryTime(
    state.currentCoefficient,
    secret,
    probe,
    vulnerableImplementation,
    state.queries,
  );

  const bucket = state.timingProfile.get(probe);
  if (!bucket) {
    throw new Error(`missing timing bucket for probe ${probe}`);
  }

  bucket.push(queryTime);
  state.queries += 1;

  let bitsRecoveredThisRound = 0;
  const analysis = statisticalAnalysis(state.timingProfile);
  if (vulnerableImplementation && analysis.distinguishable) {
    const recovered = bestProbe(state.timingProfile);
    metadata.recovered[state.currentCoefficient] = recovered;
    state.currentCoefficient += 1;
    state.recoveredBits += 2;
    state.timingProfile = createTimingProfile();
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
  const state: AttackState = {
    targetKey: secretKey,
    queries: 0,
    recoveredBits: 0,
    totalBits: secretKey.coeffs.length * 2,
    timingProfile: createTimingProfile(),
    currentCoefficient: 0,
  };

  stateMetadata.set(state, {
    recovered: new Int16Array(secretKey.coeffs.length),
  });

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

  const recoveredKey =
    vulnerableImplementation && state.currentCoefficient === secretKey.coeffs.length
      ? { coeffs: new Int16Array(metadata.recovered) }
      : null;

  const matches =
    recoveredKey !== null &&
    recoveredKey.coeffs.every((value, index) => value === secretKey.coeffs[index]);

  return {
    finalState: state,
    recoveredKey,
    matches,
    elapsedSimulatedTime: Number((state.queries * TARGET_QUERY_MINUTES).toFixed(2)),
  };
}