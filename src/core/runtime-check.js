import { bytesEqual, hexToBytes, utf8ToBytes, wipeBytes } from './bytes.js';
import { signBytesWithSeed, verifyBytesWithPublic } from './ed25519.js';
import { createSha256Stream, sha256, sha3_512 } from './hash.js';

export function assertWebCryptoAvailable(options = {}) {
  const cryptoApi = options.cryptoApi || globalThis.crypto;
  if (!cryptoApi?.subtle) {
    throw new Error('WebCrypto subtle API is unavailable.');
  }

  // Deliberately no output-distribution test here. Browser JavaScript cannot
  // observe the raw entropy source or establish SP 800-90B assurance.
}

export async function assertHashRuntimeHealth() {
  const message = utf8ToBytes('abc');
  const expectedSha256 = hexToBytes('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  const expectedSha3 = hexToBytes(
    'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e' +
      '10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'
  );
  try {
    const sha256Stream = createSha256Stream({ nativeThreshold: 0 });
    sha256Stream.update(message);
    const [sha256Actual, sha256Fallback, sha3Actual, sha3Fallback] = await Promise.all([
      sha256(message),
      sha256Stream.finish(),
      sha3_512(message),
      sha3_512(message, { implementation: 'fallback' }),
    ]);
    if (!bytesEqual(sha256Actual, expectedSha256)) throw new Error('SHA-256 startup KAT failed.');
    if (!bytesEqual(sha256Fallback, expectedSha256)) throw new Error('Bundled SHA-256 startup KAT failed.');
    if (!bytesEqual(sha3Actual, expectedSha3)) throw new Error('SHA3-512 startup provider/fallback KAT failed.');
    if (!bytesEqual(sha3Fallback, expectedSha3)) throw new Error('Bundled SHA3-512 startup KAT failed.');
  } finally {
    wipeBytes(message);
    wipeBytes(expectedSha256);
    wipeBytes(expectedSha3);
  }
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
