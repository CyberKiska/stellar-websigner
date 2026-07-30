import { hexToBytes, wipeBytes } from './bytes.js';
import { signBytesWithSeed, verifyBytesWithPublic } from './ed25519.js';

export function assertRuntimeCryptoHealth(options = {}) {
  const cryptoApi = options.cryptoApi || globalThis.crypto;
  if (!cryptoApi?.subtle) {
    throw new Error('WebCrypto subtle API is unavailable.');
  }

  // Deliberately no output-distribution test here. Browser JavaScript cannot
  // observe the raw entropy source or establish SP 800-90B assurance.
}

export async function assertEd25519RuntimeHealth() {
  // RFC 8032, section 7.1, TEST 1. This probes the actual provider and the
  // application's strict point/scalar pre-validation at startup.
  const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  const publicKey = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  const expected = hexToBytes(
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
      '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
  );
  const message = new Uint8Array(0);
  try {
    const signature = await signBytesWithSeed(seed, message);
    if (!bytesEqual(signature, expected)) throw new Error('Ed25519 startup signing KAT failed.');
    if (!(await verifyBytesWithPublic(publicKey, message, expected))) {
      throw new Error('Ed25519 startup verification KAT failed.');
    }
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const forged = new Uint8Array(64);
    forged[0] = 1;
    if (await verifyBytesWithPublic(identity, new Uint8Array([1]), forged)) {
      throw new Error('Ed25519 strict identity-point rejection failed.');
    }
  } finally {
    wipeBytes(seed);
    wipeBytes(expected);
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
