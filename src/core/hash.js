import { bytesToBase64, bytesToHexLower } from './bytes.js';

const MASK_64 = (1n << 64n) - 1n;
const KECCAK_ROUND_CONSTANTS = [
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

const KECCAK_ROTATION_OFFSETS = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

export async function sha256(bytes) {
  ensureSubtle();
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

export async function sha3_512(bytes) {
  ensureSubtle();
  try {
    const digest = await globalThis.crypto.subtle.digest('SHA-3-512', bytes);
    return new Uint8Array(digest);
  } catch {
    return sha3_512_fallback(bytes);
  }
}

export async function computeDigests(bytes) {
  const [sha256Bytes, sha3512Bytes] = await Promise.all([sha256(bytes), sha3_512(bytes)]);
  return {
    sha256: {
      alg: 'SHA-256',
      bytes: sha256Bytes,
      hex: bytesToHexLower(sha256Bytes),
      base64: bytesToBase64(sha256Bytes),
    },
    sha3_512: {
      alg: 'SHA3-512',
      bytes: sha3512Bytes,
      hex: bytesToHexLower(sha3512Bytes),
      base64: bytesToBase64(sha3512Bytes),
    },
  };
}

function ensureSubtle() {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto subtle API is unavailable.');
  }
}

function sha3_512_fallback(input) {
  const rateInBytes = 72;
  const outputLength = 64;
  const state = new Array(25).fill(0n);

  let offset = 0;
  while (offset + rateInBytes <= input.length) {
    absorbBlock(state, input.subarray(offset, offset + rateInBytes), rateInBytes);
    keccakF1600(state);
    offset += rateInBytes;
  }

  const lastBlock = new Uint8Array(rateInBytes);
  lastBlock.set(input.subarray(offset));
  lastBlock[input.length - offset] ^= 0x06;
  lastBlock[rateInBytes - 1] ^= 0x80;

  absorbBlock(state, lastBlock, rateInBytes);
  keccakF1600(state);

  const out = new Uint8Array(outputLength);
  let outOffset = 0;
  for (let lane = 0; lane < rateInBytes / 8 && outOffset < outputLength; lane += 1) {
    const value = state[lane];
    for (let i = 0; i < 8 && outOffset < outputLength; i += 1) {
      out[outOffset] = Number((value >> BigInt(8 * i)) & 0xffn);
      outOffset += 1;
    }
  }

  return out;
}

function absorbBlock(state, block, rateInBytes) {
  const lanes = rateInBytes / 8;
  for (let lane = 0; lane < lanes; lane += 1) {
    let value = 0n;
    const laneOffset = lane * 8;
    for (let i = 0; i < 8; i += 1) {
      value |= BigInt(block[laneOffset + i]) << BigInt(i * 8);
    }
    state[lane] ^= value;
  }
}

function rotl64(value, shift) {
  const s = BigInt(shift % 64);
  if (s === 0n) {
    return value & MASK_64;
  }
  return ((value << s) | (value >> (64n - s))) & MASK_64;
}

function keccakF1600(state) {
  const b = new Array(25).fill(0n);
  const c = new Array(5).fill(0n);
  const d = new Array(5).fill(0n);

  for (let round = 0; round < 24; round += 1) {
    for (let x = 0; x < 5; x += 1) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }

    for (let x = 0; x < 5; x += 1) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
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
        b[dst] = rotl64(state[src], KECCAK_ROTATION_OFFSETS[src]);
      }
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const idx = x + 5 * y;
        const b1 = b[((x + 1) % 5) + 5 * y];
        const b2 = b[((x + 2) % 5) + 5 * y];
        state[idx] = b[idx] ^ ((~b1 & MASK_64) & b2);
      }
    }

    state[0] ^= KECCAK_ROUND_CONSTANTS[round];
  }
}
