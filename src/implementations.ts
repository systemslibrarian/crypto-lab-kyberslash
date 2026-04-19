import { simulatedDivCycles } from './timing-model';

/**
 * ML-KEM-768 parameters (Kyber768 / NIST security level 3).
 */
export const KYBER_PARAMS = {
  n: 256,
  k: 3,
  q: 3329,
  eta1: 2,
  eta2: 2,
  du: 10,
  dv: 4,
} as const;

const POLY_TOMSG_FIXED_OVERHEAD = 1056;
const POLY_COMPRESS_FIXED_OVERHEAD = 640;
const BARRETT_DIV_CYCLES = 8;

/**
 * Precomputed Barrett constants for q=3329.
 */
export const BARRETT_INV_Q = Math.floor(2 ** 32 / KYBER_PARAMS.q) + 1;

function normalizeCoefficient(coefficient: number): number {
  const rounded = Math.trunc(coefficient);
  return rounded < 0 ? rounded + KYBER_PARAMS.q : rounded;
}

function divideByQ(dividend: number): number {
  return Math.floor(dividend / KYBER_PARAMS.q);
}

function divideByQBarrett(dividend: number): number {
  return Math.floor((dividend * BARRETT_INV_Q) / 2 ** 32);
}

function createCompressionBuffer(coeffCount: number): Uint8Array {
  return new Uint8Array(coeffCount * 2);
}

/**
 * VULNERABLE: poly_tomsg using integer division.
 * This is the KyberSlash1 pattern.
 *
 * Each call simulates the cycle count based on secret-dependent
 * coefficient magnitudes.
 */
export function polyTomsgVulnerable(
  coeffs: Int16Array,
): {
  msg: Uint8Array;
  totalCycles: number;
} {
  const msg = new Uint8Array(KYBER_PARAMS.n / 8);
  let totalCycles = POLY_TOMSG_FIXED_OVERHEAD;

  for (let outer = 0; outer < KYBER_PARAMS.n / 8; outer += 1) {
    let byte = 0;

    for (let inner = 0; inner < 8; inner += 1) {
      const index = outer * 8 + inner;
      const normalized = normalizeCoefficient(coeffs[index]);
      const dividend = (normalized << 1) + Math.floor(KYBER_PARAMS.q / 2);
      const bit = divideByQ(dividend) & 1;

      totalCycles += simulatedDivCycles(dividend, KYBER_PARAMS.q, true);
      byte |= bit << inner;
    }

    msg[outer] = byte;
  }

  return {
    msg,
    totalCycles: Number(totalCycles.toFixed(3)),
  };
}

/**
 * VULNERABLE: poly_compress using integer division.
 * This is the KyberSlash2 pattern.
 */
export function polyCompressVulnerable(
  coeffs: Int16Array,
  d: number,
): {
  compressed: Uint8Array;
  totalCycles: number;
} {
  const compressed = createCompressionBuffer(coeffs.length);
  const mask = (1 << d) - 1;
  let totalCycles = POLY_COMPRESS_FIXED_OVERHEAD;

  for (let index = 0; index < coeffs.length; index += 1) {
    const normalized = normalizeCoefficient(coeffs[index]);
    const dividend = (normalized << d) + Math.floor(KYBER_PARAMS.q / 2);
    const compressedValue = divideByQ(dividend) & mask;

    totalCycles += simulatedDivCycles(dividend, KYBER_PARAMS.q, true);
    compressed[index * 2] = compressedValue & 0xff;
    compressed[index * 2 + 1] = (compressedValue >>> 8) & 0xff;
  }

  return {
    compressed,
    totalCycles: Number(totalCycles.toFixed(3)),
  };
}

/**
 * PATCHED: poly_tomsg using Barrett reduction (constant-time).
 * Replaces `x / q` with `(x * BARRETT_INV) >> 32`.
 * Cycle count is FIXED regardless of input.
 */
export function polyTomsgPatched(
  coeffs: Int16Array,
): {
  msg: Uint8Array;
  totalCycles: number;
} {
  const msg = new Uint8Array(KYBER_PARAMS.n / 8);

  for (let outer = 0; outer < KYBER_PARAMS.n / 8; outer += 1) {
    let byte = 0;

    for (let inner = 0; inner < 8; inner += 1) {
      const index = outer * 8 + inner;
      const normalized = normalizeCoefficient(coeffs[index]);
      const dividend = (normalized << 1) + Math.floor(KYBER_PARAMS.q / 2);
      const bit = divideByQBarrett(dividend) & 1;
      byte |= bit << inner;
    }

    msg[outer] = byte;
  }

  return {
    msg,
    totalCycles: POLY_TOMSG_FIXED_OVERHEAD + KYBER_PARAMS.n * BARRETT_DIV_CYCLES,
  };
}

/**
 * PATCHED: poly_compress with Barrett reduction.
 */
export function polyCompressPatched(
  coeffs: Int16Array,
  d: number,
): {
  compressed: Uint8Array;
  totalCycles: number;
} {
  const compressed = createCompressionBuffer(coeffs.length);
  const mask = (1 << d) - 1;

  for (let index = 0; index < coeffs.length; index += 1) {
    const normalized = normalizeCoefficient(coeffs[index]);
    const dividend = (normalized << d) + Math.floor(KYBER_PARAMS.q / 2);
    const compressedValue = divideByQBarrett(dividend) & mask;

    compressed[index * 2] = compressedValue & 0xff;
    compressed[index * 2 + 1] = (compressedValue >>> 8) & 0xff;
  }

  return {
    compressed,
    totalCycles: POLY_COMPRESS_FIXED_OVERHEAD + coeffs.length * BARRETT_DIV_CYCLES,
  };
}