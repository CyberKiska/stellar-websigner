import { performance } from 'node:perf_hooks';

import { bytesToHexLower } from '../src/core/bytes.js';
import { sha3_512 } from '../src/core/hash.js';

const LEGACY_MASK_64 = (1n << 64n) - 1n;
const LEGACY_ROUND_CONSTANTS = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];

const LEGACY_ROTATION_OFFSETS = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const SHA3_512_RATE_BYTES = 72;
const SHA3_512_OUTPUT_BYTES = 64;

function parsePositiveInt(value, fallback) {
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`Expected a positive integer, got ${value}.`);
  }
  return parsed;
}

async function main() {
  const blocks = parsePositiveInt(process.argv[2], 4096);
  const iterations = parsePositiveInt(process.argv[3], 8);
  const input = new Uint8Array(SHA3_512_RATE_BYTES * blocks).fill(0x41);

  await withForcedSha3Fallback(async () => {
    const currentHex = bytesToHexLower(await sha3_512(input));
    const legacyHex = bytesToHexLower(sha3_512_bigint(input));
    if (currentHex !== legacyHex) {
      throw new Error('Uint32 and legacy BigInt SHA3-512 digests differ.');
    }

    await sha3_512(input);
    sha3_512_bigint(input);

    const uint32Ms = await timeAsync(iterations, () => sha3_512(input));
    const bigintMs = timeSync(iterations, () => sha3_512_bigint(input));
    const speedup = bigintMs / uint32Ms;
    const mib = (input.length * iterations) / 1024 / 1024;

    console.log('SHA3-512 fallback benchmark');
    console.log(`Input: ${input.length} bytes (${SHA3_512_RATE_BYTES} x ${blocks} ASCII "A" blocks)`);
    console.log(`Iterations: ${iterations}`);
    console.log(`Digest: ${currentHex}`);
    console.log(`Uint32 hi/lo lanes: ${uint32Ms.toFixed(2)} ms (${(mib / (uint32Ms / 1000)).toFixed(2)} MiB/s)`);
    console.log(`Legacy BigInt lanes: ${bigintMs.toFixed(2)} ms (${(mib / (bigintMs / 1000)).toFixed(2)} MiB/s)`);
    console.log(`Speedup: ${speedup.toFixed(2)}x`);
  });
}

async function withForcedSha3Fallback(fn) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.digest) {
    throw new Error('WebCrypto subtle API is unavailable.');
  }

  const originalDigest = subtle.digest;
  subtle.digest = function digestWithForcedSha3Fallback(algorithm, data) {
    const name = typeof algorithm === 'string' ? algorithm : algorithm?.name;
    if (String(name).toUpperCase() === 'SHA-3-512') {
      return Promise.reject(new Error('forced SHA3-512 fallback'));
    }
    return originalDigest.call(this, algorithm, data);
  };

  try {
    return await fn();
  } finally {
    subtle.digest = originalDigest;
  }
}

async function timeAsync(iterations, fn) {
  const started = performance.now();
  for (let i = 0; i < iterations; i += 1) {
    await fn();
  }
  return performance.now() - started;
}

function timeSync(iterations, fn) {
  const started = performance.now();
  for (let i = 0; i < iterations; i += 1) {
    fn();
  }
  return performance.now() - started;
}

function sha3_512_bigint(input) {
  const state = new Array(25).fill(0n);

  let offset = 0;
  while (offset + SHA3_512_RATE_BYTES <= input.length) {
    legacyAbsorbBlock(state, input.subarray(offset, offset + SHA3_512_RATE_BYTES));
    legacyKeccakF1600(state);
    offset += SHA3_512_RATE_BYTES;
  }

  const lastBlock = new Uint8Array(SHA3_512_RATE_BYTES);
  lastBlock.set(input.subarray(offset));
  lastBlock[input.length - offset] ^= 0x06;
  lastBlock[SHA3_512_RATE_BYTES - 1] ^= 0x80;

  legacyAbsorbBlock(state, lastBlock);
  legacyKeccakF1600(state);

  const out = new Uint8Array(SHA3_512_OUTPUT_BYTES);
  let outOffset = 0;
  for (let lane = 0; lane < SHA3_512_RATE_BYTES / 8 && outOffset < SHA3_512_OUTPUT_BYTES; lane += 1) {
    const value = state[lane];
    for (let i = 0; i < 8 && outOffset < SHA3_512_OUTPUT_BYTES; i += 1) {
      out[outOffset] = Number((value >> BigInt(8 * i)) & 0xffn);
      outOffset += 1;
    }
  }

  return out;
}

function legacyAbsorbBlock(state, block) {
  const lanes = SHA3_512_RATE_BYTES / 8;
  for (let lane = 0; lane < lanes; lane += 1) {
    let value = 0n;
    const laneOffset = lane * 8;
    for (let i = 0; i < 8; i += 1) {
      value |= BigInt(block[laneOffset + i]) << BigInt(i * 8);
    }
    state[lane] ^= value;
  }
}

function legacyRotl64(value, shift) {
  const s = BigInt(shift % 64);
  if (s === 0n) {
    return value & LEGACY_MASK_64;
  }
  return ((value << s) | (value >> (64n - s))) & LEGACY_MASK_64;
}

function legacyKeccakF1600(state) {
  const b = new Array(25).fill(0n);
  const c = new Array(5).fill(0n);
  const d = new Array(5).fill(0n);

  for (let round = 0; round < 24; round += 1) {
    for (let x = 0; x < 5; x += 1) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }

    for (let x = 0; x < 5; x += 1) {
      d[x] = c[(x + 4) % 5] ^ legacyRotl64(c[(x + 1) % 5], 1);
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[x + 5 * y] ^= d[x];
      }
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const src = x + 5 * y;
        const dst = y + 5 * ((2 * x + 3 * y) % 5);
        b[dst] = legacyRotl64(state[src], LEGACY_ROTATION_OFFSETS[src]);
      }
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const idx = x + 5 * y;
        const b1 = b[((x + 1) % 5) + 5 * y];
        const b2 = b[((x + 2) % 5) + 5 * y];
        state[idx] = b[idx] ^ ((~b1 & LEGACY_MASK_64) & b2);
      }
    }

    state[0] ^= LEGACY_ROUND_CONSTANTS[round];
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
