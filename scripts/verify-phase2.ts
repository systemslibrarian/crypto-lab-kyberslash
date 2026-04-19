import {
  BARRETT_INV_Q,
  KYBER_PARAMS,
  polyCompressPatched,
  polyCompressVulnerable,
  polyTomsgPatched,
  polyTomsgVulnerable,
} from '../src/implementations';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const baseCoefficients = new Int16Array(KYBER_PARAMS.n);
for (let index = 0; index < KYBER_PARAMS.n; index += 1) {
  baseCoefficients[index] = ((index * 37) % KYBER_PARAMS.q) - 1664;
}

const shiftedCoefficients = new Int16Array(KYBER_PARAMS.n);
shiftedCoefficients.fill(1664);

const vulnerableTomsgA = polyTomsgVulnerable(baseCoefficients);
const vulnerableTomsgB = polyTomsgVulnerable(shiftedCoefficients);
const patchedTomsgA = polyTomsgPatched(baseCoefficients);
const patchedTomsgB = polyTomsgPatched(shiftedCoefficients);

const vulnerableCompressA = polyCompressVulnerable(baseCoefficients, KYBER_PARAMS.dv);
const vulnerableCompressB = polyCompressVulnerable(shiftedCoefficients, KYBER_PARAMS.dv);
const patchedCompressA = polyCompressPatched(baseCoefficients, KYBER_PARAMS.dv);
const patchedCompressB = polyCompressPatched(shiftedCoefficients, KYBER_PARAMS.dv);

assert(
  Buffer.from(vulnerableTomsgA.msg).equals(Buffer.from(patchedTomsgA.msg)),
  'polyTomsg vulnerable and patched outputs differ',
);
assert(
  Buffer.from(vulnerableCompressA.compressed).equals(Buffer.from(patchedCompressA.compressed)),
  'polyCompress vulnerable and patched outputs differ',
);
assert(
  vulnerableTomsgA.totalCycles !== vulnerableTomsgB.totalCycles,
  'vulnerable polyTomsg should have input-dependent cycle counts',
);
assert(
  vulnerableCompressA.totalCycles !== vulnerableCompressB.totalCycles,
  'vulnerable polyCompress should have input-dependent cycle counts',
);
assert(
  patchedTomsgA.totalCycles === patchedTomsgB.totalCycles,
  'patched polyTomsg should have constant cycle counts',
);
assert(
  patchedCompressA.totalCycles === patchedCompressB.totalCycles,
  'patched polyCompress should have constant cycle counts',
);
assert(
  Math.floor((BARRETT_INV_Q * KYBER_PARAMS.q) / 2 ** 32) === 1,
  'expected Barrett reciprocal check to evaluate to 1',
);

console.log(
  JSON.stringify(
    {
      barrettInvQ: BARRETT_INV_Q,
      vulnerableTomsgA: vulnerableTomsgA.totalCycles,
      vulnerableTomsgB: vulnerableTomsgB.totalCycles,
      patchedTomsg: patchedTomsgA.totalCycles,
      vulnerableCompressA: vulnerableCompressA.totalCycles,
      vulnerableCompressB: vulnerableCompressB.totalCycles,
      patchedCompress: patchedCompressA.totalCycles,
    },
    null,
    2,
  ),
);