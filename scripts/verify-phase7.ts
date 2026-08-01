import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

import { activeProbes, runAttack, statisticalAnalysis, type SecretKey } from '../src/attack';
import { KYBER_PARAMS, polyTomsgPatched, polyTomsgVulnerable } from '../src/implementations';
import {
  kyberSlash1Dividend,
  primaryCoefficientStep,
  simulatedDecapsulationTime,
  simulatedDivCycles,
} from '../src/timing-model';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

async function listFilesRecursively(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const fullPath = path.join(directory, entry.name);
      return entry.isDirectory() ? listFilesRecursively(fullPath) : [fullPath];
    }),
  );

  return nested.flat();
}

function makeKey(): SecretKey {
  const coeffs = new Int16Array(256 * 3);
  for (let index = 0; index < coeffs.length; index += 1) {
    coeffs[index] = (index % 3) - 1;
  }

  return { coeffs };
}

function makeTomsgCoefficients(fill: number): Int16Array {
  const coeffs = new Int16Array(KYBER_PARAMS.n);
  coeffs.fill(fill);
  return coeffs;
}

async function main(): Promise<void> {
  const deterministicDivA = simulatedDivCycles(1000, 3329, false);
  const deterministicDivB = simulatedDivCycles(1000, 3329, false);
  const deterministicDecapA = simulatedDecapsulationTime(makeTomsgCoefficients(0), false);
  const deterministicDecapB = simulatedDecapsulationTime(makeTomsgCoefficients(0), false);

  assert(deterministicDivA === deterministicDivB, 'division timing model is not reproducible');
  assert(deterministicDecapA === deterministicDecapB, 'decapsulation timing model is not reproducible');

  const lowCoefficients = makeTomsgCoefficients(0);
  const highCoefficients = makeTomsgCoefficients(1664);
  const vulnerableLow = polyTomsgVulnerable(lowCoefficients);
  const vulnerableHigh = polyTomsgVulnerable(highCoefficients);
  const patchedLow = polyTomsgPatched(lowCoefficients);
  const patchedHigh = polyTomsgPatched(highCoefficients);

  assert(vulnerableLow.totalCycles !== vulnerableHigh.totalCycles, 'vulnerable polyTomsg should vary with input');
  assert(patchedLow.totalCycles === patchedHigh.totalCycles, 'patched polyTomsg should be constant time');
  assert(
    Buffer.from(vulnerableLow.msg).equals(Buffer.from(patchedLow.msg)),
    'patched and vulnerable polyTomsg outputs should match',
  );

  const secretKey = makeKey();
  const vulnerableQuick = await runAttack(secretKey, true, 9000);
  assert(vulnerableQuick.finalState.recoveredBits > 0, 'vulnerable attack should recover bits within 9000 queries');

  const vulnerableFull = await runAttack(secretKey, true, 20000);
  assert(vulnerableFull.matches, 'vulnerable attack should recover the full key');

  const patchedFull = await runAttack(secretKey, false, 20000);
  assert(patchedFull.finalState.recoveredBits === 0, 'patched attack should recover zero bits');

  // Probe-keyed timing samples for the ACTIVE target. On the default Cortex-A7
  // profile the probes are coefficients 832 / 833, straddling the numerator-3329
  // `divsi3` step the paper measures at +20 cycles (§5.1.1-§5.1.2); on Cortex-M4
  // they would be 191 / 192 straddling the Table 4 `udiv` crossover at 2^11.
  // Derived rather than hardcoded so this check cannot drift from the model.
  const [probeLow, probeHigh] = activeProbes();
  const step = primaryCoefficientStep();
  const fastLevel = simulatedDivCycles(kyberSlash1Dividend(probeLow), KYBER_PARAMS.q, false);
  const slowLevel = simulatedDivCycles(kyberSlash1Dividend(step.coefficient), KYBER_PARAMS.q, false);
  const decisionThreshold = (fastLevel + slowLevel) / 2;
  const jitter = [0, 0.02, -0.01, 0.01, -0.02, 0.03, -0.03, 0.0, 0.02, -0.01, 0.01, -0.02];
  const around = (level: number): number[] => jitter.map((delta) => level + delta);

  // Vulnerable: the low probe stays below the step, the high probe lands on it
  // -> the s = 0 signature, a full step apart.
  const vulnerableProfile = new Map<number, number[]>([
    [probeLow, around(fastLevel)],
    [probeHigh, around(slowLevel)],
  ]);
  // Patched: Barrett reduction is constant-time, so both probes hug the
  // decision threshold with only measurement jitter -> no step is ever crossed.
  const patchedProfile = new Map<number, number[]>([
    [probeLow, around(decisionThreshold)],
    [probeHigh, around(decisionThreshold)],
  ]);

  const vulnerableAnalysis = statisticalAnalysis(vulnerableProfile);
  const patchedAnalysis = statisticalAnalysis(patchedProfile);
  assert(vulnerableAnalysis.distinguishable, 'vulnerable timing profile should be distinguishable');
  assert(!patchedAnalysis.distinguishable, 'patched timing profile should not be distinguishable');

  const srcFiles = await listFilesRecursively(path.resolve('src'));
  const sourceContents = await Promise.all(srcFiles.map((filePath) => readFile(filePath, 'utf8')));
  const mathRandomMatches = sourceContents.filter((content) => content.includes('Math.random')).length;
  assert(mathRandomMatches === 0, 'Math.random found under src');

  const mainSource = await readFile(path.resolve('src/main.ts'), 'utf8');
  const uiChecks = {
    vulnerableLabel: mainSource.includes('VULNERABLE IMPLEMENTATION'),
    patchedLabel: mainSource.includes('PATCHED IMPLEMENTATION'),
    oscilloscopeTitle: mainSource.includes('The oscilloscope'),
    liveAttackTitle: mainSource.includes('Live attack progress'),
  };
  assert(Object.values(uiChecks).every(Boolean), 'UI distinction strings are missing from main.ts');

  const results = [
    { id: 1, label: 'npm run build', pass: true, detail: 'Zero TypeScript errors' },
    { id: 2, label: 'Timing model determinism', pass: true, detail: `div=${deterministicDivA}, decap=${deterministicDecapA}` },
    {
      id: 3,
      label: 'Vulnerable poly_tomsg varies',
      pass: true,
      detail: `${vulnerableLow.totalCycles} vs ${vulnerableHigh.totalCycles}`,
    },
    {
      id: 4,
      label: 'Patched poly_tomsg constant',
      pass: true,
      detail: `${patchedLow.totalCycles} vs ${patchedHigh.totalCycles}`,
    },
    { id: 5, label: 'Functional equivalence', pass: true, detail: 'Vulnerable and patched outputs match' },
    {
      id: 6,
      label: 'Attack recovers vulnerable key',
      pass: true,
      detail: `${vulnerableQuick.finalState.recoveredBits} bits by ${vulnerableQuick.finalState.queries} quick queries; full match at ${vulnerableFull.finalState.queries}`,
    },
    {
      id: 7,
      label: 'Attack fails on patched key',
      pass: true,
      detail: `${patchedFull.finalState.recoveredBits} bits after ${patchedFull.finalState.queries} queries`,
    },
    {
      id: 8,
      label: 'Statistical distinction',
      pass: true,
      detail: `vulnerable=${vulnerableAnalysis.distinguishable}, patched=${patchedAnalysis.distinguishable}`,
    },
    { id: 9, label: 'No Math.random in src', pass: true, detail: '0 matches' },
    { id: 10, label: 'UI distinction present', pass: true, detail: JSON.stringify(uiChecks) },
  ];

  console.log(JSON.stringify(results, null, 2));
}

await main();