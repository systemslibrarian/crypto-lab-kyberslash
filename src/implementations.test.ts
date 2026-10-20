import { describe, expect, it } from 'vitest';

import {
  BARRETT_INV_Q,
  KYBER_PARAMS,
  polyCompressPatched,
  polyCompressVulnerable,
  polyTomsgPatched,
  polyTomsgVulnerable,
} from './implementations';

/**
 * A SECOND COPY of the implementation's arithmetic, not an independent reference.
 * It was labelled "Independent reference" until 2026-10-20; the rename is the whole
 * correction, because the label was the thing doing the damage.
 *
 *     t = ((normalize(x) << 1) + q/2) / q   (integer div)   ->   bit = t & 1
 *
 * That is character-for-character what `implementations.ts` computes. As a differential
 * it is worth keeping — mutate one copy and the other disagrees, so it catches a typo
 * in either — but it cannot see a mutation applied to BOTH, which is what a misreading
 * of the standard looks like. Measured, by making the same wrong rounding constant in
 * both copies: the two "matches the reference" tests below stayed GREEN.
 *
 * Ground truth for these functions lives in the FIPS 203 block at the end of this file.
 *
 * bit = 1 exactly when the coefficient sits near q/2 (i.e. normalize(x) in
 * [833, 2496] for q = 3329). This is the functional contract the vulnerable
 * and patched implementations must BOTH satisfy — the patch only changes the
 * timing, never the output.
 */
const KYBER_Q = KYBER_PARAMS.q;

function normalize(x: number): number {
  const r = Math.trunc(x) % KYBER_Q;
  return r < 0 ? r + KYBER_Q : r;
}

function referenceTomsgBit(x: number): number {
  const t = normalize(x);
  return Math.floor(((t << 1) + Math.floor(KYBER_Q / 2)) / KYBER_Q) & 1;
}

function referenceMessage(coeffs: Int16Array): Uint8Array {
  const msg = new Uint8Array(KYBER_PARAMS.n / 8);
  for (let outer = 0; outer < msg.length; outer += 1) {
    let byte = 0;
    for (let inner = 0; inner < 8; inner += 1) {
      byte |= referenceTomsgBit(coeffs[outer * 8 + inner]) << inner;
    }
    msg[outer] = byte;
  }
  return msg;
}

function referenceCompress(coeffs: Int16Array, d: number): Uint8Array {
  const out = new Uint8Array(coeffs.length * 2);
  const mask = (1 << d) - 1;
  for (let index = 0; index < coeffs.length; index += 1) {
    const t = normalize(coeffs[index]);
    const value = (Math.floor(((t << d) + Math.floor(KYBER_Q / 2)) / KYBER_Q) & mask) >>> 0;
    out[index * 2] = value & 0xff;
    out[index * 2 + 1] = (value >>> 8) & 0xff;
  }
  return out;
}

describe('poly_tomsg known-answer vectors', () => {
  it('decodes single coefficients to the reference message bit', () => {
    // (coefficient, expected bit) known-answer pairs across the decode window.
    const cases: [number, number][] = [
      [0, 0],
      [1, 0],
      [832, 0],
      [833, 1],
      [1664, 1], // q/2 rounded -> center of the "1" window
      [2496, 1],
      [2497, 0],
      [3328, 0],
      [-1, 0], // normalizes to 3328
      [-1664, 1], // normalizes to 1665
    ];

    for (const [coeff, expectedBit] of cases) {
      const coeffs = new Int16Array(KYBER_PARAMS.n);
      coeffs[0] = coeff;
      const { msg } = polyTomsgVulnerable(coeffs);
      expect(msg[0] & 1, `coefficient ${coeff}`).toBe(expectedBit);
      expect(referenceTomsgBit(coeff)).toBe(expectedBit);
    }
  });

  it('matches the transcribed formula over pseudo-random coefficient vectors', () => {
    for (let seed = 0; seed < 40; seed += 1) {
      const coeffs = new Int16Array(KYBER_PARAMS.n);
      for (let index = 0; index < coeffs.length; index += 1) {
        coeffs[index] = ((seed * 131 + index * 37 + 7) % KYBER_Q) - 1664;
      }
      const expected = referenceMessage(coeffs);
      expect(Array.from(polyTomsgVulnerable(coeffs).msg)).toEqual(Array.from(expected));
      expect(Array.from(polyTomsgPatched(coeffs).msg)).toEqual(Array.from(expected));
    }
  });
});

/* NOT known-answer vectors, and titled as such until 2026-10-20. `poly_tomsg` above
   really does carry ten hardcoded (coefficient, bit) pairs — ground truth somebody
   worked out and wrote down, and the reason the shared-constant mutation was caught
   there. This block has no hardcoded value anywhere in it: its only comparison was
   against the transcription above, so KyberSlash2's compression had no ground truth at
   all while sitting under a heading that said it did. The FIPS 203 block at the end of
   this file is what supplies it; this stays as the differential it actually is. */
describe('poly_compress differential against the transcribed formula', () => {
  it('matches the transcribed formula for d = dv and d = du bit widths', () => {
    for (const d of [KYBER_PARAMS.dv, KYBER_PARAMS.du]) {
      for (let seed = 0; seed < 20; seed += 1) {
        const coeffs = new Int16Array(KYBER_PARAMS.n);
        for (let index = 0; index < coeffs.length; index += 1) {
          coeffs[index] = ((seed * 97 + index * 53 + 3) % KYBER_Q) - 1664;
        }
        const expected = referenceCompress(coeffs, d);
        expect(Array.from(polyCompressVulnerable(coeffs, d).compressed)).toEqual(
          Array.from(expected),
        );
        expect(Array.from(polyCompressPatched(coeffs, d).compressed)).toEqual(Array.from(expected));
      }
    }
  });
});

describe('patch preserves function, changes only timing', () => {
  it('vulnerable and patched produce byte-identical output', () => {
    const coeffs = new Int16Array(KYBER_PARAMS.n);
    for (let index = 0; index < coeffs.length; index += 1) {
      coeffs[index] = ((index * 173) % KYBER_Q) - 1664;
    }
    expect(Array.from(polyTomsgVulnerable(coeffs).msg)).toEqual(
      Array.from(polyTomsgPatched(coeffs).msg),
    );
    expect(Array.from(polyCompressVulnerable(coeffs, KYBER_PARAMS.dv).compressed)).toEqual(
      Array.from(polyCompressPatched(coeffs, KYBER_PARAMS.dv).compressed),
    );
  });

  it('vulnerable timing depends on the secret input, patched timing does not', () => {
    const low = new Int16Array(KYBER_PARAMS.n); // all zeros -> small dividends
    const high = new Int16Array(KYBER_PARAMS.n);
    high.fill(1664); // near q/2 -> large dividends

    expect(polyTomsgVulnerable(low).totalCycles).not.toBe(polyTomsgVulnerable(high).totalCycles);
    expect(polyTomsgPatched(low).totalCycles).toBe(polyTomsgPatched(high).totalCycles);

    expect(polyCompressVulnerable(low, KYBER_PARAMS.dv).totalCycles).not.toBe(
      polyCompressVulnerable(high, KYBER_PARAMS.dv).totalCycles,
    );
    expect(polyCompressPatched(low, KYBER_PARAMS.dv).totalCycles).toBe(
      polyCompressPatched(high, KYBER_PARAMS.dv).totalCycles,
    );
  });

  it('Barrett reciprocal satisfies floor(BARRETT_INV * q / 2^32) == 1', () => {
    expect(Math.floor((BARRETT_INV_Q * KYBER_Q) / 2 ** 32)).toBe(1);
  });
});

/**
 * FIPS 203 CONFORMANCE — the published definition, not a transcription of the code.
 *
 * The `reference*` helpers above are a differential against a SECOND COPY of the
 * implementation's own arithmetic: both sides compute
 * `floor(((x << d) + floor(q/2)) / q) & mask`. That catches a typo in one copy, which
 * is worth having, and it cannot catch a shared misreading of the standard — if the
 * integer form itself were wrong, both sides would move together and stay green. The
 * reference is a reproduction; ground truth has to come from the publication.
 *
 * So this block asserts the lab against FIPS 203 §4.2.1 (eq. 4.7):
 *
 *     Compress_d(x) = round((2^d / q) * x) mod 2^d
 *
 * written as the rounding expression the standard actually states, which is a
 * structurally DIFFERENT computation from the integer-division form the implementation
 * uses — no shift, no `floor(q/2)` addend, floating-point rounding rather than integer
 * truncation. The equivalence of the two is a real property of q = 3329, not a
 * restatement, and it is asserted over the COMPLETE coefficient domain [0, q) rather
 * than over samples: 3329 values at every bit width this lab uses, so there is no
 * coefficient where the two could disagree unobserved.
 *
 * Asserted THROUGH the lab's own exported functions. An assertion that recomputed
 * compression locally and compared it to a second local computation would test this
 * file and not the lab — the mistake that let a SHA-1 mutation pass in
 * crypto-lab-bike-vault, where the test called `subtle.digest` directly.
 */
function fips203Compress(x: number, d: number): number {
  const twoD = 2 ** d;
  /* round-half-up, as the standard's notation specifies for ties. */
  const rounded = Math.floor((x * twoD) / KYBER_Q + 0.5);
  return ((rounded % twoD) + twoD) % twoD;
}

/** FIPS 203 §4.2.1: Decompress_d(y) = round((q / 2^d) * y). */
function fips203Decompress(y: number, d: number): number {
  return Math.floor((y * KYBER_Q) / 2 ** d + 0.5);
}

/** Every coefficient in the field, which is what makes this a proof rather than a sample. */
const ALL_COEFFICIENTS = Int16Array.from({ length: KYBER_Q }, (_unused, x) => x);

describe('FIPS 203 conformance over the complete coefficient domain', () => {
  it.each([
    ['dv', KYBER_PARAMS.dv],
    ['du', KYBER_PARAMS.du],
  ])('poly_compress matches round((2^d/q)x) mod 2^d for d = %s', (_label, d) => {
    const { compressed } = polyCompressVulnerable(ALL_COEFFICIENTS, d);
    const patched = polyCompressPatched(ALL_COEFFICIENTS, d).compressed;

    const disagreements: string[] = [];
    for (let x = 0; x < KYBER_Q; x += 1) {
      const fromLab = compressed[x * 2] | (compressed[x * 2 + 1] << 8);
      const expected = fips203Compress(x, d);
      if (fromLab !== expected) disagreements.push(`x=${x}: lab ${fromLab} vs FIPS 203 ${expected}`);
    }

    expect(disagreements.slice(0, 5)).toEqual([]);
    expect(disagreements).toHaveLength(0);
    /* The patch may not change a single output byte, over the whole domain. */
    expect(patched).toEqual(compressed);
  });

  it('poly_tomsg matches Compress_1 for every coefficient in [0, q)', () => {
    const blockSize = KYBER_PARAMS.n;
    const disagreements: string[] = [];

    for (let base = 0; base < KYBER_Q; base += blockSize) {
      /* polyTomsg always reads exactly n coefficients, so the final short block is
         padded and only its real coefficients are read back. */
      const block = new Int16Array(blockSize);
      const count = Math.min(blockSize, KYBER_Q - base);
      for (let i = 0; i < count; i += 1) block[i] = base + i;

      const { msg } = polyTomsgVulnerable(block);
      const patchedMsg = polyTomsgPatched(block).msg;
      expect(patchedMsg).toEqual(msg);

      for (let i = 0; i < count; i += 1) {
        const fromLab = (msg[i >> 3] >> (i & 7)) & 1;
        const expected = fips203Compress(base + i, 1);
        if (fromLab !== expected) {
          disagreements.push(`x=${base + i}: lab ${fromLab} vs FIPS 203 ${expected}`);
        }
      }
    }

    expect(disagreements.slice(0, 5)).toEqual([]);
    expect(disagreements).toHaveLength(0);
  });

  it.each([
    ['dv', KYBER_PARAMS.dv],
    ['du', KYBER_PARAMS.du],
  ])('compression error stays inside the FIPS 203 bound for d = %s', (_label, d) => {
    /* FIPS 203 states the point of the bound: decompressing a compressed coefficient
       returns something within round(q / 2^(d+1)) of the original. A compressor that
       agreed with the formula on every input would still be wrong if the formula were
       misread, so this checks the PROPERTY the standard gives the formula for. */
    const bound = Math.floor(KYBER_Q / 2 ** (d + 1) + 0.5);
    const { compressed } = polyCompressVulnerable(ALL_COEFFICIENTS, d);
    let worst = 0;

    for (let x = 0; x < KYBER_Q; x += 1) {
      const y = compressed[x * 2] | (compressed[x * 2 + 1] << 8);
      const back = fips203Decompress(y, d) % KYBER_Q;
      /* Centred distance: compression wraps, so q-1 is one away from 0, not q-1 away. */
      const raw = Math.abs(back - x);
      worst = Math.max(worst, Math.min(raw, KYBER_Q - raw));
    }

    expect(worst).toBeLessThanOrEqual(bound);
  });
});
