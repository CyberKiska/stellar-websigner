import { bytesToBase64, bytesToHexLower } from './bytes.js';

const SHA256_BLOCK_BYTES = 64;
const SHA256_OUTPUT_BYTES = 32;
const SHA256_NATIVE_THRESHOLD_BYTES = 4 * 1024 * 1024;
const SHA3_512_RATE_BYTES = 72;
const SHA3_512_OUTPUT_BYTES = 64;

const SHA256_INITIAL_STATE = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const SHA256_ROUND_CONSTANTS = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

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

export function createSha256Stream() {
  ensureSubtle();

  let chunks = [];
  let bufferedLength = 0;
  let streaming = null;
  let finished = false;

  function switchToStreaming() {
    if (!streaming) {
      streaming = createSha256StreamingState();
      for (const chunk of chunks) {
        streaming.update(chunk);
      }
      chunks = [];
    }
  }

  return {
    update(chunk) {
      if (finished) throw new Error('SHA-256 stream is already finished.');
      assertBytes(chunk, 'SHA-256 chunk');
      if (chunk.length === 0) return;

      if (streaming) {
        streaming.update(chunk);
        return;
      }

      const nextLength = bufferedLength + chunk.length;
      if (nextLength <= SHA256_NATIVE_THRESHOLD_BYTES) {
        chunks.push(chunk.slice());
        bufferedLength = nextLength;
        return;
      }

      switchToStreaming();
      streaming.update(chunk);
      bufferedLength = nextLength;
    },

    async finish() {
      if (finished) throw new Error('SHA-256 stream is already finished.');
      finished = true;

      if (!streaming && (await hasNativeSha3_512())) {
        const input = concatBufferedChunks(chunks, bufferedLength);
        chunks = [];
        try {
          const digest = await globalThis.crypto.subtle.digest('SHA-256', input);
          return new Uint8Array(digest);
        } finally {
          input.fill(0);
        }
      }

      switchToStreaming();
      chunks = [];
      return streaming.finish();
    },
  };
}

export function createSha3_512Stream() {
  ensureSubtle();
  return createSha3_512StreamingState();
}

function ensureSubtle() {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto subtle API is unavailable.');
  }
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

let nativeSha3_512Probe;

async function hasNativeSha3_512() {
  if (!nativeSha3_512Probe) {
    nativeSha3_512Probe = globalThis.crypto.subtle
      .digest('SHA-3-512', new Uint8Array(0))
      .then(() => true)
      .catch(() => false);
  }
  return nativeSha3_512Probe;
}

function concatBufferedChunks(chunks, totalLength) {
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function createSha256StreamingState() {
  const h = new Uint32Array(SHA256_INITIAL_STATE);
  const w = new Uint32Array(64);
  const block = new Uint8Array(SHA256_BLOCK_BYTES);
  let blockLength = 0;
  let bytesHashed = 0;

  return {
    update(chunk) {
      bytesHashed += chunk.length;

      let offset = 0;
      if (blockLength > 0) {
        const needed = SHA256_BLOCK_BYTES - blockLength;
        const take = Math.min(needed, chunk.length);
        block.set(chunk.subarray(0, take), blockLength);
        blockLength += take;
        offset = take;
        if (blockLength === SHA256_BLOCK_BYTES) {
          sha256Compress(h, w, block, 0);
          blockLength = 0;
        }
      }

      while (offset + SHA256_BLOCK_BYTES <= chunk.length) {
        sha256Compress(h, w, chunk, offset);
        offset += SHA256_BLOCK_BYTES;
      }

      if (offset < chunk.length) {
        block.set(chunk.subarray(offset), 0);
        blockLength = chunk.length - offset;
      }
    },

    finish() {
      const out = this.finishSync();
      return Promise.resolve(out);
    },

    finishSync() {
      block[blockLength] = 0x80;
      block.fill(0, blockLength + 1);

      if (blockLength >= 56) {
        sha256Compress(h, w, block, 0);
        block.fill(0);
      }

      const bitLengthHi = Math.floor(bytesHashed / 0x20000000);
      const bitLengthLo = (bytesHashed % 0x20000000) * 8;
      block[56] = bitLengthHi >>> 24;
      block[57] = bitLengthHi >>> 16;
      block[58] = bitLengthHi >>> 8;
      block[59] = bitLengthHi;
      block[60] = bitLengthLo >>> 24;
      block[61] = bitLengthLo >>> 16;
      block[62] = bitLengthLo >>> 8;
      block[63] = bitLengthLo;
      sha256Compress(h, w, block, 0);

      const out = new Uint8Array(SHA256_OUTPUT_BYTES);
      for (let i = 0; i < h.length; i += 1) {
        const offset = i * 4;
        out[offset] = h[i] >>> 24;
        out[offset + 1] = h[i] >>> 16;
        out[offset + 2] = h[i] >>> 8;
        out[offset + 3] = h[i];
      }

      h.fill(0);
      w.fill(0);
      block.fill(0);
      return out;
    },
  };
}

function sha256Compress(h, w, block, offset) {
  for (let i = 0; i < 16; i += 1) {
    const j = offset + i * 4;
    w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
  }

  for (let i = 16; i < 64; i += 1) {
    const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
    const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }

  let a = h[0];
  let b = h[1];
  let c = h[2];
  let d = h[3];
  let e = h[4];
  let f = h[5];
  let g = h[6];
  let hh = h[7];

  for (let i = 0; i < 64; i += 1) {
    const s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    const ch = (e & f) ^ (~e & g);
    const t1 = (hh + s1 + ch + SHA256_ROUND_CONSTANTS[i] + w[i]) >>> 0;
    const s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (s0 + maj) >>> 0;

    hh = g;
    g = f;
    f = e;
    e = (d + t1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) >>> 0;
  }

  h[0] = (h[0] + a) >>> 0;
  h[1] = (h[1] + b) >>> 0;
  h[2] = (h[2] + c) >>> 0;
  h[3] = (h[3] + d) >>> 0;
  h[4] = (h[4] + e) >>> 0;
  h[5] = (h[5] + f) >>> 0;
  h[6] = (h[6] + g) >>> 0;
  h[7] = (h[7] + hh) >>> 0;
}

function rotr32(value, shift) {
  return (value >>> shift) | (value << (32 - shift));
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
