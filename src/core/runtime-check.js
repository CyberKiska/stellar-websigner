import { wipeBytes } from './bytes.js';

export function assertRuntimeCryptoHealth() {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.getRandomValues) {
    throw new Error('WebCrypto getRandomValues() is unavailable.');
  }
  if (!cryptoApi.subtle) {
    throw new Error('WebCrypto subtle API is unavailable.');
  }

  const first = new Uint8Array(32);
  const second = new Uint8Array(32);

  try {
    cryptoApi.getRandomValues(first);
    cryptoApi.getRandomValues(second);

    let identical = true;
    for (let i = 0; i < first.length; i += 1) {
      if (first[i] !== second[i]) {
        identical = false;
        break;
      }
    }

    if (identical) {
      throw new Error('CSPRNG health check failed: consecutive outputs are identical.');
    }
  } finally {
    wipeBytes(first);
    wipeBytes(second);
  }
}
