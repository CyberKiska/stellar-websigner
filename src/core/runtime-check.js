import { bytesEqual, hexToBytes, utf8ToBytes, wipeBytes } from './bytes.js';
import { signBytesWithSeed, verifyBytesWithPublic } from './ed25519.js';
import { createSha3_512Stream, sha256, sha3_512 } from './hash.js';

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
    const [sha256Actual, sha3Actual, sha3Fallback] = await Promise.all([
      sha256(message),
      sha3_512(message),
      sha3_512(message, { implementation: 'fallback' }),
    ]);
    if (!bytesEqual(sha256Actual, expectedSha256)) throw new Error('SHA-256 startup KAT failed.');
    if (!bytesEqual(sha3Actual, expectedSha3)) throw new Error('SHA3-512 startup provider/fallback KAT failed.');
    if (!bytesEqual(sha3Fallback, expectedSha3)) throw new Error('Bundled SHA3-512 startup KAT failed.');

    // FIPS 202 example (1600-bit 0xa3 message) through the streaming path used for content, split
    // across a partial block and a multi-block remainder.
    const sha3Stream = createSha3_512Stream();
    const a3 = new Uint8Array(200).fill(0xa3);
    sha3Stream.update(a3.subarray(0, 71));
    sha3Stream.update(a3.subarray(71));
    const expectedStreamed = hexToBytes(
      'e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8' +
        '1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00'
    );
    if (!bytesEqual(await sha3Stream.finish(), expectedStreamed)) {
      throw new Error('Streaming SHA3-512 startup KAT failed.');
    }
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
    // Provider-negative cases: R and A are valid prime-order points and S stays canonical, so the
    // application's strict pre-validation passes and only a conformant provider rejects them.
    if (await verifyBytesWithPublic(publicKey, new Uint8Array([1]), expected)) {
      throw new Error('Ed25519 startup verification accepted a signature for a different message.');
    }
    const tamperedS = expected.slice();
    tamperedS[32] ^= 0x01;
    if (await verifyBytesWithPublic(publicKey, message, tamperedS)) {
      throw new Error('Ed25519 startup verification accepted a modified signature scalar.');
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
