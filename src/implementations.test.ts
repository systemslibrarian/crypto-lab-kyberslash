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
 * Independent reference for the Kyber `poly_tomsg` message-decode bit:
 *
 *     t = ((normalize(x) << 1) + q/2) / q   (integer div)   ->   bit = t & 1
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

  it('matches the independent reference over pseudo-random coefficient vectors', () => {
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

describe('poly_compress known-answer vectors', () => {
  it('matches the independent reference for d = dv and d = du bit widths', () => {
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
