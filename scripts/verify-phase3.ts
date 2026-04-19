import { runAttack, statisticalAnalysis, type SecretKey } from '../src/attack';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function makeKey(): SecretKey {
  const coeffs = new Int16Array(256 * 3);
  for (let index = 0; index < coeffs.length; index += 1) {
    coeffs[index] = (index % 3) - 1;
  }

  return { coeffs };
}

const secretKey = makeKey();

const quickAttack = await runAttack(secretKey, true, 9000);
assert(quickAttack.finalState.recoveredBits > 0, 'expected vulnerable attack to recover bits within 9000 queries');

let progressCount = 0;
const vulnerableResult = await runAttack(secretKey, true, 20000, () => {
  progressCount += 1;
});
assert(vulnerableResult.matches, 'expected vulnerable attack to recover the full key');
assert(progressCount > 0, 'expected progress callback to be invoked');

const patchedResult = await runAttack(secretKey, false, 20000);
assert(patchedResult.finalState.recoveredBits === 0, 'patched attack should recover zero bits');
assert(patchedResult.recoveredKey === null, 'patched attack should not recover a key');

const patchedAnalysis = statisticalAnalysis(patchedResult.finalState.timingProfile);
assert(!patchedAnalysis.distinguishable, 'patched timing samples should not be distinguishable');

console.log(
  JSON.stringify(
    {
      quickRecoveredBits: quickAttack.finalState.recoveredBits,
      vulnerableQueries: vulnerableResult.finalState.queries,
      patchedQueries: patchedResult.finalState.queries,
      patchedAnalysis,
      progressCount,
    },
    null,
    2,
  ),
);