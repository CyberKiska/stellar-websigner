import { wipeBytes } from './bytes.js';

const CSPRNG_SAMPLE_COUNT = 4;
const CSPRNG_SAMPLE_BYTES = 32;
const CSPRNG_MIN_ONE_RATIO = 0.35;
const CSPRNG_MAX_ONE_RATIO = 0.65;

// Startup smoke test only: this catches gross platform RNG failures and is not
// a substitute for NIST SP 800-90B entropy-source validation.
const POPCOUNT_8 = new Uint8Array(256);
for (let i = 1; i < POPCOUNT_8.length; i += 1) {
  POPCOUNT_8[i] = POPCOUNT_8[i >> 1] + (i & 1);
}

export function assertRuntimeCryptoHealth(options = {}) {
  const cryptoApi = options.cryptoApi || globalThis.crypto;
  if (!cryptoApi?.getRandomValues) {
    throw new Error('WebCrypto getRandomValues() is unavailable.');
  }
  if (!cryptoApi.subtle) {
    throw new Error('WebCrypto subtle API is unavailable.');
  }

  const samples = Array.from({ length: CSPRNG_SAMPLE_COUNT }, () => new Uint8Array(CSPRNG_SAMPLE_BYTES));

  try {
    for (const sample of samples) {
      cryptoApi.getRandomValues(sample);
    }

    for (let i = 0; i < samples.length; i += 1) {
      for (let j = i + 1; j < samples.length; j += 1) {
        if (bytesEqual(samples[i], samples[j])) {
          throw new Error('CSPRNG health check failed: repeated outputs are identical.');
        }
      }
    }

    const oneBits = samples.reduce((total, sample) => total + countOneBits(sample), 0);
    const oneRatio = oneBits / (CSPRNG_SAMPLE_COUNT * CSPRNG_SAMPLE_BYTES * 8);
    if (oneRatio < CSPRNG_MIN_ONE_RATIO || oneRatio > CSPRNG_MAX_ONE_RATIO) {
      throw new Error('CSPRNG health check failed: bit balance is outside the expected sanity range.');
    }
  } finally {
    for (const sample of samples) {
      wipeBytes(sample);
    }
  }
}

function bytesEqual(a, b) {
  let diff = a.length ^ b.length;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function countOneBits(bytes) {
  let total = 0;
  for (const value of bytes) {
    total += POPCOUNT_8[value];
  }
  return total;
}
