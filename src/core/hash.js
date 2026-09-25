import { bytesToBase64, bytesToHexLower } from './bytes.js';

const SHA3_512_RATE_BYTES = 72;
const SHA3_512_OUTPUT_BYTES = 64;

const KECCAK_ROUND_CONSTANTS_LO = new Uint32Array([
  0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
  0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
  0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008,
]);

const KECCAK_ROUND_CONSTANTS_HI = new Uint32Array([
  0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000,
  0x80000000, 0x80000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000,
]);

const KECCAK_ROTATION_OFFSETS = new Uint8Array([
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
]);

// SHA-256 always uses the platform provider; Web Crypto has no incremental digest, so callers hash the
// assembled input once. SHA3-512 is not available in browser Web Crypto and is streamed below.
export async function sha256(bytes) {
  assertBytes(bytes, 'SHA-256 input');
  return new Uint8Array(await getSubtle().digest('SHA-256', bytes));
}

export async function sha3_512(bytes, options = {}) {
  assertBytes(bytes, 'SHA3-512 input');
  const implementation = options.implementation || 'auto';
  if (!['auto', 'native', 'fallback'].includes(implementation)) {
    throw new Error(`Unsupported SHA3-512 implementation policy: ${implementation}.`);
  }
  if (implementation === 'fallback') {
    return sha3_512_fallback(bytes);
  }

  const subtle = options.subtle || getSubtle();
  try {
    const digest = new Uint8Array(await subtle.digest('SHA3-512', bytes));
    if (digest.length !== SHA3_512_OUTPUT_BYTES) {
      throw new Error(`Native SHA3-512 returned ${digest.length} bytes; expected ${SHA3_512_OUTPUT_BYTES}.`);
    }
    return digest;
  } catch (err) {
    if (implementation === 'native' || !isNotSupportedError(err)) throw err;
    return sha3_512_fallback(bytes);
  }
}

export async function computeDigests(bytes) {
  const [sha256Bytes, sha3512Bytes] = await Promise.all([sha256(bytes), sha3_512(bytes)]);
  return digestSet(sha256Bytes, sha3512Bytes);
}

export function digestSet(sha256Bytes, sha3512Bytes) {
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

export function createSha3_512Stream() {
  return createSha3_512StreamingState();
}

function getSubtle() {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto subtle API is unavailable.');
  }
  return globalThis.crypto.subtle;
}

function isNotSupportedError(err) {
  return err?.name === 'NotSupportedError';
}

function sha3_512_fallback(input) {
  const stream = createSha3_512StreamingState();
  stream.update(input);
  return stream.finishSync();
}

function assertBytes(value, label) {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must be Uint8Array.`);
  }
}


function createSha3_512StreamingState() {
  const stateLo = new Uint32Array(25);
  const stateHi = new Uint32Array(25);
  const bLo = new Uint32Array(25);
  const bHi = new Uint32Array(25);
  const cLo = new Uint32Array(5);
  const cHi = new Uint32Array(5);
  const dLo = new Uint32Array(5);
  const dHi = new Uint32Array(5);
  const block = new Uint8Array(SHA3_512_RATE_BYTES);
  let blockLength = 0;
  let finished = false;

  function update(chunk) {
    if (finished) throw new Error('SHA3-512 stream is already finished.');
    assertBytes(chunk, 'SHA3-512 chunk');
    if (chunk.length === 0) return;

    let offset = 0;
    if (blockLength > 0) {
      const needed = SHA3_512_RATE_BYTES - blockLength;
      const take = Math.min(needed, chunk.length);
      block.set(chunk.subarray(0, take), blockLength);
      blockLength += take;
      offset = take;
      if (blockLength === SHA3_512_RATE_BYTES) {
        absorbBlock(stateLo, stateHi, block, 0);
        keccakF1600(stateLo, stateHi, bLo, bHi, cLo, cHi, dLo, dHi);
        block.fill(0);
        blockLength = 0;
      }
    }

    while (offset + SHA3_512_RATE_BYTES <= chunk.length) {
      absorbBlock(stateLo, stateHi, chunk, offset);
      keccakF1600(stateLo, stateHi, bLo, bHi, cLo, cHi, dLo, dHi);
      offset += SHA3_512_RATE_BYTES;
    }

    if (offset < chunk.length) {
      block.set(chunk.subarray(offset), 0);
      blockLength = chunk.length - offset;
    }
  }

  function finishSync() {
    if (finished) throw new Error('SHA3-512 stream is already finished.');
    finished = true;

    block[blockLength] ^= 0x06;
    block[SHA3_512_RATE_BYTES - 1] ^= 0x80;
    absorbBlock(stateLo, stateHi, block, 0);
    keccakF1600(stateLo, stateHi, bLo, bHi, cLo, cHi, dLo, dHi);

    const out = new Uint8Array(SHA3_512_OUTPUT_BYTES);
    for (let lane = 0; lane < SHA3_512_OUTPUT_BYTES / 8; lane += 1) {
      const laneOffset = lane * 8;
      const lo = stateLo[lane];
      const hi = stateHi[lane];
      out[laneOffset] = lo;
      out[laneOffset + 1] = lo >>> 8;
      out[laneOffset + 2] = lo >>> 16;
      out[laneOffset + 3] = lo >>> 24;
      out[laneOffset + 4] = hi;
      out[laneOffset + 5] = hi >>> 8;
      out[laneOffset + 6] = hi >>> 16;
      out[laneOffset + 7] = hi >>> 24;
    }

    stateLo.fill(0);
    stateHi.fill(0);
    bLo.fill(0);
    bHi.fill(0);
    cLo.fill(0);
    cHi.fill(0);
    dLo.fill(0);
    dHi.fill(0);
    block.fill(0);
    return out;
  }

  return {
    update,
    finish() {
      return Promise.resolve(finishSync());
    },
    finishSync,
  };
}

function absorbBlock(stateLo, stateHi, block, offset) {
  const lanes = SHA3_512_RATE_BYTES / 8;
  for (let lane = 0; lane < lanes; lane += 1) {
    const laneOffset = offset + lane * 8;
    stateLo[lane] ^=
      (block[laneOffset] |
        (block[laneOffset + 1] << 8) |
        (block[laneOffset + 2] << 16) |
        (block[laneOffset + 3] << 24)) >>>
      0;
    stateHi[lane] ^=
      (block[laneOffset + 4] |
        (block[laneOffset + 5] << 8) |
        (block[laneOffset + 6] << 16) |
        (block[laneOffset + 7] << 24)) >>>
      0;
  }
}

function rotl64Into(lo, hi, shift, outLo, outHi, lane) {
  if (shift === 0) {
    outLo[lane] = lo;
    outHi[lane] = hi;
  } else if (shift < 32) {
    outLo[lane] = (lo << shift) | (hi >>> (32 - shift));
    outHi[lane] = (hi << shift) | (lo >>> (32 - shift));
  } else if (shift === 32) {
    outLo[lane] = hi;
    outHi[lane] = lo;
  } else {
    const s = shift - 32;
    outLo[lane] = (hi << s) | (lo >>> (32 - s));
    outHi[lane] = (lo << s) | (hi >>> (32 - s));
  }
}

function keccakF1600(stateLo, stateHi, bLo, bHi, cLo, cHi, dLo, dHi) {
  for (let round = 0; round < 24; round += 1) {
    for (let x = 0; x < 5; x += 1) {
      cLo[x] = stateLo[x] ^ stateLo[x + 5] ^ stateLo[x + 10] ^ stateLo[x + 15] ^ stateLo[x + 20];
      cHi[x] = stateHi[x] ^ stateHi[x + 5] ^ stateHi[x + 10] ^ stateHi[x + 15] ^ stateHi[x + 20];
    }

    for (let x = 0; x < 5; x += 1) {
      const x1 = (x + 1) % 5;
      const x4 = (x + 4) % 5;
      dLo[x] = cLo[x4] ^ ((cLo[x1] << 1) | (cHi[x1] >>> 31));
      dHi[x] = cHi[x4] ^ ((cHi[x1] << 1) | (cLo[x1] >>> 31));
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const idx = x + 5 * y;
        stateLo[idx] ^= dLo[x];
        stateHi[idx] ^= dHi[x];
      }
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const src = x + 5 * y;
        const dst = y + 5 * ((2 * x + 3 * y) % 5);
        rotl64Into(stateLo[src], stateHi[src], KECCAK_ROTATION_OFFSETS[src], bLo, bHi, dst);
      }
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const idx = x + 5 * y;
        const b1 = ((x + 1) % 5) + 5 * y;
        const b2 = ((x + 2) % 5) + 5 * y;
        stateLo[idx] = bLo[idx] ^ (~bLo[b1] & bLo[b2]);
        stateHi[idx] = bHi[idx] ^ (~bHi[b1] & bHi[b2]);
      }
    }

    stateLo[0] ^= KECCAK_ROUND_CONSTANTS_LO[round];
    stateHi[0] ^= KECCAK_ROUND_CONSTANTS_HI[round];
  }
}
