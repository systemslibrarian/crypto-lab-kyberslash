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

// Exhaustive check behind two on-screen claims in Exhibit 1: that the lab's own
// 2^32 Barrett form AND the constant pq-crystals actually shipped (commit
// dda29cc: t <<= 1; t += 1665; t *= 80635; t >>= 28; t &= 1) both reproduce
// `(((t << 1) + KYBER_Q/2) / KYBER_Q) & 1` for every coefficient poly_tomsg can
// see. The screen says "checked exhaustively over all 3,329 coefficient values";
// this is that check.
let barrettMismatches = 0;
let upstreamMismatches = 0;
for (let t = 0; t < KYBER_PARAMS.q; t += 1) {
  const numerator = (t << 1) + Math.floor(KYBER_PARAMS.q / 2);
  const reference = Math.floor(numerator / KYBER_PARAMS.q) & 1;
  const labBarrett = Math.floor((numerator * BARRETT_INV_Q) / 2 ** 32) & 1;
  const upstream = (Math.imul((t << 1) + 1665, 80635) >>> 28) & 1;
  if (labBarrett !== reference) barrettMismatches += 1;
  if (upstream !== reference) upstreamMismatches += 1;
}
assert(barrettMismatches === 0, `lab Barrett form disagrees with / q on ${barrettMismatches} coefficients`);
assert(
  upstreamMismatches === 0,
  `upstream 80635 >> 28 form disagrees with / q on ${upstreamMismatches} coefficients`,
);

console.log(
  JSON.stringify(
    {
      barrettInvQ: BARRETT_INV_Q,
      barrettMismatches,
      upstreamMismatches,
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