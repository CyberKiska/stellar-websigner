import {
  base64ToBytes,
  bytesEqual,
  bytesToBase64,
  bytesToHexLower,
  concatBytes,
  decodeUtf8Strict,
  hexToBytes,
  safeJsonParse,
  utf8ToBytes,
} from './bytes.js';
import {
  createSigningKeySession,
  derivePublicKeyFromSeed,
  generateKeypair,
  signatureHint,
  signBytesWithSeed,
  verifyBytesWithPublic,
} from './ed25519.js';
import { assertStrictEd25519PublicKey, assertStrictEd25519Signature } from './ed25519-validation.js';
import { canonicalJsonStringify } from './canonical-json.js';
import { assertTopLevelBrowsingContext, localSecretOperationsAllowed } from './deployment-policy.js';
import { computeDigests, createSha3_512Stream, sha256, sha3_512 } from './hash.js';
import { MANIFEST_DATA_NAME, SIGNATURE_SCHEMA_V3, SIGNATURE_SCHEME, TESTNET_NETWORK_PASSPHRASE } from './constants.js';
import { createLocalSep53MessageSignature } from './signing.js';
import {
  createFileInputContext,
  createTextInputContext,
  MAX_TEXT_INPUT_SIZE_BYTES,
} from './input-context.js';
import { SEP53_CANONICAL_TEST_VECTORS } from './sep53-test-vectors.js';
import { signSep53Message, verifySep53Message } from './sep53.js';
import { createXdrProofDraft, finalizeXdrProof } from './xdr-proof.js';
import { encodeEd25519PublicKey, decodeEd25519PublicKey, decodeEd25519SecretSeed, encodeEd25519SecretSeed } from './strkey.js';
import { verifyDetachedSignature } from './verify.js';
import {
  buildUnsignedManifestEnvelope,
  computeTransactionHash,
  encodeSignedTxEnvelope,
  parseTransactionEnvelope,
} from './xdr.js';
import { assertEd25519RuntimeHealth, assertHashRuntimeHealth, assertWebCryptoAvailable } from './runtime-check.js';

function createResult(name, fn) {
  return { name, fn };
}

async function makeFileContext(name, bytes, options = {}) {
  const digests = await computeDigests(bytes);
  return {
    type: 'file',
    fileName: name,
    fileSize: bytes.length,
    mediaType: options.mediaType || '',
    bytes,
    digests,
  };
}

async function makeTextContext(text) {
  const bytes = utf8ToBytes(text);
  const digests = await computeDigests(bytes);
  return {
    type: 'text',
    fileName: '',
    fileSize: bytes.length,
    bytes,
    digests,
  };
}

async function makeXdrFixture(seedHex, inputContext) {
  const seed = hexToBytes(seedHex);
  const publicBytes = await derivePublicKeyFromSeed(seed);
  const signer = encodeEd25519PublicKey(publicBytes);
  const draft = await createXdrProofDraft({
    inputContext,
    signerAddress: signer,
    networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
  });
  const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
  const signature = await signBytesWithSeed(seed, txHash);
  const hint = signatureHint(publicBytes);
  const signedXdr = bytesToBase64(
    encodeSignedTxEnvelope({ txXdr: draft.txXdr, signatures: [{ hint, signature }] })
  );
  return { seed, publicBytes, signer, draft, signature, hint, signedXdr };
}

function uint32Bytes(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function encodeEnvelopeWithOpaqueSignature({ txXdr, hint, signature }) {
  const padding = new Uint8Array((4 - (signature.length % 4)) % 4);
  return concatBytes(
    uint32Bytes(2),
    txXdr,
    uint32Bytes(1),
    hint,
    uint32Bytes(signature.length),
    signature,
    padding
  );
}

function indexOfBytes(haystack, needle) {
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

async function makeCanonicalSep53Context(vector) {
  if (vector.type === 'text') {
    return makeTextContext(vector.message);
  }
  if (vector.type === 'binary') {
    return makeFileContext('sep53-canonical-binary.bin', base64ToBytes(vector.messageB64));
  }
  throw new Error(`Unsupported SEP-53 vector type: ${vector.type}`);
}

async function makeSignedTextFixture(text) {
  const seed = hexToBytes('1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a');
  const inputContext = await makeTextContext(text);
  const signResult = await createLocalSep53MessageSignature({
    inputContext,
    seedBytes: seed,
    signerAddress: '',
  });
  return {
    doc: signResult.doc,
    inputContext,
  };
}

async function assertFileSignVerifyForSize(size) {
  const seed = hexToBytes('1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b');
  const bytes = new Uint8Array(size);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = (i * 17 + size) & 0xff;
  }
  const fileContext = await makeFileContext(`boundary-${size}.bin`, bytes);
  const signResult = await createLocalSep53MessageSignature({
    inputContext: fileContext,
    seedBytes: seed,
    signerAddress: '',
  });
  const verify = await verifyDetachedSignature({
    signatureDoc: signResult.doc,
    inputContext: fileContext,
    expectedSigner: signResult.signer,
  });

  if (!verify.valid) {
    throw new Error(`Expected VALID for ${size}-byte file, got ${verify.summary}.`);
  }
}

async function assertSha3_512Hex(name, bytes, expectedHex, options = {}) {
  const actualHex = bytesToHexLower(await sha3_512(bytes, options));
  if (actualHex !== expectedHex) {
    throw new Error(`${name}: expected ${expectedHex}, got ${actualHex}.`);
  }
}

async function digestWithChunks(createStream, bytes, chunkSizes) {
  const stream = createStream();
  let offset = 0;
  let chunkIndex = 0;
  while (offset < bytes.length) {
    const size = chunkSizes[chunkIndex % chunkSizes.length];
    const end = Math.min(bytes.length, offset + size);
    stream.update(bytes.subarray(offset, end));
    offset = end;
    chunkIndex += 1;
  }
  return stream.finish();
}

function makeDeterministicBytes(size, seed) {
  const out = new Uint8Array(size);
  let value = seed >>> 0;
  for (let i = 0; i < out.length; i += 1) {
    value = (Math.imul(value, 1664525) + 1013904223) >>> 0;
    out[i] = value >>> 24;
  }
  return out;
}

export async function runSelfTest() {
  const results = [];

  const tests = [
    createResult('runtime WebCrypto capability probe avoids entropy claims', async () => {
      assertThrows(() => assertWebCryptoAvailable({ cryptoApi: {} }), 'subtle API is unavailable');
      assertWebCryptoAvailable({ cryptoApi: { subtle: {} } });
      await assertHashRuntimeHealth();
      await assertEd25519RuntimeHealth();
    }),

    createResult('startup Ed25519 KAT rejects a provider that accepts every signature', async () => {
      const subtle = globalThis.crypto.subtle;
      const hadOwnVerify = Object.prototype.hasOwnProperty.call(subtle, 'verify');
      const ownVerifyDescriptor = Object.getOwnPropertyDescriptor(subtle, 'verify');
      try {
        Object.defineProperty(subtle, 'verify', { configurable: true, writable: true, value: async () => true });
        await assertRejects(() => assertEd25519RuntimeHealth(), 'Ed25519 startup verification accepted');
      } finally {
        if (hadOwnVerify) Object.defineProperty(subtle, 'verify', ownVerifyDescriptor);
        else delete subtle.verify;
      }
      await assertEd25519RuntimeHealth();
    }),

    createResult('deployment policy disables local secrets on shared or insecure origins', async () => {
      if (localSecretOperationsAllowed({ hostname: 'user.github.io', isSecureContext: true })) {
        throw new Error('Shared GitHub Pages origin must not allow local secret operations.');
      }
      if (localSecretOperationsAllowed({ hostname: 'signer.example', isSecureContext: false })) {
        throw new Error('Insecure origin must not allow local secret operations.');
      }
      if (localSecretOperationsAllowed({ hostname: 'signer.example', isSecureContext: true, buildPolicy: 'disabled' })) {
        throw new Error('External-wallet-only build must not allow local secret operations.');
      }
      if (!localSecretOperationsAllowed({ hostname: 'signer.example', isSecureContext: true })) {
        throw new Error('Dedicated secure origin should allow local secret operations.');
      }
      const topLevel = {};
      assertTopLevelBrowsingContext({ topWindow: topLevel, selfWindow: topLevel });
      assertThrows(
        () => assertTopLevelBrowsingContext({ topWindow: {}, selfWindow: {} }),
        'Framing is not permitted'
      );
    }),

    createResult('sha3-512 fallback vectors', async () => {
      const vectors = [
        [
          'empty',
          new Uint8Array(0),
          'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
        ],
        [
          'abc',
          utf8ToBytes('abc'),
          'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
        ],
        [
          '71-byte rate boundary',
          new Uint8Array(71).fill(0x41),
          'e9e7f1016227a4d58c3a2c597adc2f58de10b6e78f17ff079624fede5eb8341bf0ebeda4f8296d5a070751ab3b7ffa48d35950f793e21f9c16c095b3b354da5e',
        ],
        [
          '72-byte rate boundary',
          new Uint8Array(72).fill(0x41),
          'dbbb35fbed5f380b3c29bf4a42ad47a0f9d77ca8622f2a64b1ef0655a2bb978542bc579167647de0903e454dd45316c8c4878aade59e9f663df4d9327b333eef',
        ],
        [
          '73-byte rate boundary',
          new Uint8Array(73).fill(0x41),
          'a4d32577ac925077aacdc65964041ba05d9058596f6157937f8748e4a1833aa7c954a4e45c4e1132a52737c675d3f9edae3018c51ba388f540bcc4590b4e293d',
        ],
      ];

      for (const [name, bytes, expectedHex] of vectors) {
        await assertSha3_512Hex(name, bytes, expectedHex, { implementation: 'fallback' });
      }
    }),

    createResult('sha3-512 native policy uses proposed name and narrows fallback errors', async () => {
      const bytes = utf8ToBytes('native SHA3 provider policy');
      const expected = await sha3_512(bytes, { implementation: 'fallback' });
      let observedAlgorithm = '';
      const nativeProvider = {
        async digest(algorithm) {
          observedAlgorithm = algorithm;
          return expected.slice().buffer;
        },
      };
      const native = await sha3_512(bytes, {
        implementation: 'native',
        subtle: nativeProvider,
      });
      if (observedAlgorithm !== 'SHA3-512') {
        throw new Error(`Expected SHA3-512 provider name, got ${observedAlgorithm || '(none)'}.`);
      }
      if (!bytesEqual(native, expected)) {
        throw new Error('Native SHA3-512 provider result mismatch.');
      }

      const notSupported = new Error('unsupported');
      notSupported.name = 'NotSupportedError';
      const fallback = await sha3_512(bytes, {
        subtle: {
          async digest() {
            throw notSupported;
          },
        },
      });
      if (!bytesEqual(fallback, expected)) {
        throw new Error('SHA3-512 did not fall back after NotSupportedError.');
      }

      await assertRejects(
        () =>
          sha3_512(bytes, {
            subtle: {
              async digest() {
                throw new Error('provider failure');
              },
            },
          }),
        'provider failure'
      );
    }),

    createResult('SHA-256 provider vectors and SHA3-512 streaming corpus', async () => {
      const sha256Vectors = [
        ['empty', new Uint8Array(0), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
        ['abc', utf8ToBytes('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
        [
          'FIPS 180-4 448-bit two-block',
          utf8ToBytes('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
          '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
        ],
      ];
      for (const [name, bytes, expectedHex] of sha256Vectors) {
        const actualHex = bytesToHexLower(await sha256(bytes));
        if (actualHex !== expectedHex) {
          throw new Error(`SHA-256 ${name}: expected ${expectedHex}, got ${actualHex}.`);
        }
      }

      const sha3Boundary = new Uint8Array(73).fill(0x41);
      const sha3Expected =
        'a4d32577ac925077aacdc65964041ba05d9058596f6157937f8748e4a1833aa7c954a4e45c4e1132a52737c675d3f9edae3018c51ba388f540bcc4590b4e293d';
      const sha3Actual = bytesToHexLower(await digestWithChunks(createSha3_512Stream, sha3Boundary, [1, 71, 1]));
      if (sha3Actual !== sha3Expected) {
        throw new Error(`SHA3-512 stream boundary: expected ${sha3Expected}, got ${sha3Actual}.`);
      }

      let sizeState = 0xdecafbad;
      for (let i = 0; i < 100; i += 1) {
        sizeState = (Math.imul(sizeState, 1103515245) + 12345) >>> 0;
        const size = sizeState % 16385;
        const bytes = makeDeterministicBytes(size, i + 1);
        const chunkSizes = [1 + (i % 17), 31 + (i % 97), 255 + (i % 251), 4096];
        const oneShot = bytesToHexLower(await sha3_512(bytes, { implementation: 'fallback' }));
        const streamed = bytesToHexLower(await digestWithChunks(createSha3_512Stream, bytes, chunkSizes));
        if (streamed !== oneShot) {
          throw new Error(`SHA3-512 stream corpus mismatch at size ${size}.`);
        }
      }
    }),

    createResult('file input context streams digests by chunk', async () => {
      const bytes = makeDeterministicBytes(8193, 0x12345678);
      const file = {
        name: 'chunked-stream.bin',
        size: bytes.length,
        lastModified: 1700000000000,
        slice(start, end) {
          return new Blob([bytes.subarray(start, end)]);
        },
      };

      const progress = [];
      const streamed = await createFileInputContext(file, {
        chunkSize: 71,
        onProgress(item) {
          progress.push(item.phase);
        },
      });
      const expected = await computeDigests(bytes);

      if ('bytes' in streamed) {
        throw new Error('File input context must not retain input bytes.');
      }
      if (streamed.digests.sha256.hex !== expected.sha256.hex) {
        throw new Error('Streamed file SHA-256 digest mismatch.');
      }
      if (streamed.digests.sha3_512.hex !== expected.sha3_512.hex) {
        throw new Error('Streamed file SHA3-512 digest mismatch.');
      }
      if (!progress.includes('read') || !progress.includes('digest') || progress.at(-1) !== 'done') {
        throw new Error(`Unexpected streamed file progress phases: ${progress.join(',')}.`);
      }

    }),

    createResult('file input context abort wipes active chunk', async () => {
      const bytes = makeDeterministicBytes(4096, 0x87654321);
      const chunkCopies = [];
      const controller = new AbortController();
      const file = {
        name: 'abort-stream.bin',
        size: bytes.length,
        lastModified: 1700000000001,
        slice(start, end) {
          return {
            async arrayBuffer() {
              const copy = bytes.slice(start, end);
              chunkCopies.push(copy);
              return copy.buffer;
            },
          };
        },
      };

      let thrown = null;
      try {
        await createFileInputContext(file, {
          chunkSize: 1024,
          signal: controller.signal,
          onProgress(item) {
            if (item.phase === 'read') controller.abort();
          },
        });
      } catch (err) {
        thrown = err;
      }

      if (!thrown || thrown.name !== 'AbortError') {
        throw new Error(`Expected AbortError, got ${thrown?.name || 'none'}.`);
      }
      if (chunkCopies.length === 0) {
        throw new Error('Expected at least one chunk allocation before abort.');
      }
      for (const chunk of chunkCopies) {
        for (const value of chunk) {
          if (value !== 0) {
            throw new Error('Aborted file chunk was not wiped.');
          }
        }
      }
    }),

    createResult('file input context rejects short, empty, overlong, and changing reads', async () => {
      const bytes = makeDeterministicBytes(64, 0x13572468);
      for (const returnedLength of [0, 31, 33]) {
        const file = {
          name: `invalid-read-${returnedLength}.bin`,
          size: bytes.length,
          lastModified: 1700000000002,
          slice(start, end) {
            const expectedLength = end - start;
            const out = new Uint8Array(returnedLength === 33 ? expectedLength + 1 : returnedLength);
            out.set(bytes.subarray(start, Math.min(end, start + out.length)));
            return { async arrayBuffer() { return out.buffer; } };
          },
        };
        await assertRejects(
          () => createFileInputContext(file, { chunkSize: 32 }),
          'File read returned'
        );
      }

      let sizeReads = 0;
      const changingFile = {
        name: 'changing-size.bin',
        get size() {
          sizeReads += 1;
          return sizeReads === 1 ? bytes.length : bytes.length - 1;
        },
        lastModified: 1700000000003,
        slice(start, end) {
          return new Blob([bytes.subarray(start, end)]);
        },
      };
      await assertRejects(() => createFileInputContext(changingFile), 'File changed while it was being read');
    }),

    createResult('text input enforces UTF-8 byte limit and cooperative cancellation', async () => {
      const atLimit = 'a'.repeat(MAX_TEXT_INPUT_SIZE_BYTES);
      const context = await createTextInputContext(atLimit, { chunkSize: 64 * 1024 });
      if (context.fileSize !== MAX_TEXT_INPUT_SIZE_BYTES) {
        throw new Error(`Expected ${MAX_TEXT_INPUT_SIZE_BYTES}-byte text context, got ${context.fileSize}.`);
      }

      await assertRejects(
        () => createTextInputContext(`${atLimit}a`),
        `Maximum supported UTF-8 size is ${MAX_TEXT_INPUT_SIZE_BYTES} bytes`
      );
      const multibyteOverflow = '\u20ac'.repeat(Math.floor(MAX_TEXT_INPUT_SIZE_BYTES / 3) + 1);
      await assertRejects(
        () => createTextInputContext(multibyteOverflow),
        `Maximum supported UTF-8 size is ${MAX_TEXT_INPUT_SIZE_BYTES} bytes`
      );

      const controller = new AbortController();
      const pending = createTextInputContext('b'.repeat(256 * 1024), {
        chunkSize: 64,
        signal: controller.signal,
      });
      setTimeout(() => controller.abort(), 0);
      await assertRejects(() => pending, 'aborted');
    }),

    createResult('strkey roundtrip', async () => {
      const seed = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      const encoded = encodeEd25519SecretSeed(seed);
      const decoded = decodeEd25519SecretSeed(encoded);
      if (decoded.length !== 32) throw new Error('Decoded seed length mismatch.');
      for (let i = 0; i < 32; i += 1) {
        if (decoded[i] !== seed[i]) throw new Error('Roundtrip mismatch.');
      }
    }),

    createResult('strkey shape validation', async () => {
      const seed = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
      const encodedSeed = encodeEd25519SecretSeed(seed);
      const signer = encodeEd25519PublicKey(await derivePublicKeyFromSeed(seed));

      assertThrows(() => decodeEd25519PublicKey(signer.toLowerCase()), 'must start with "G"');
      assertThrows(() => decodeEd25519PublicKey(`S${signer.slice(1)}`), 'must start with "G"');
      assertThrows(() => decodeEd25519PublicKey(`G0${signer.slice(2)}`), 'base32 charset');
      assertThrows(() => decodeEd25519PublicKey(signer.slice(0, 55)), 'exactly 56 characters');

      assertThrows(() => decodeEd25519SecretSeed(encodedSeed.toLowerCase()), 'must start with "S"');
      assertThrows(() => decodeEd25519SecretSeed(`G${encodedSeed.slice(1)}`), 'must start with "S"');
      assertThrows(() => decodeEd25519SecretSeed(`S0${encodedSeed.slice(2)}`), 'base32 charset');
      assertThrows(() => decodeEd25519SecretSeed(encodedSeed.slice(0, 55)), 'exactly 56 characters');
    }),

    createResult('address generation + import roundtrip', async () => {
      const kp = await generateKeypair();
      if (!(kp.seedBytes instanceof Uint8Array) || kp.seedBytes.length !== 32) {
        throw new Error('Generated seedBytes are invalid.');
      }
      if (!(kp.publicBytes instanceof Uint8Array) || kp.publicBytes.length !== 32) {
        throw new Error('Generated publicBytes are invalid.');
      }

      const seedStr = encodeEd25519SecretSeed(kp.seedBytes);
      const signerStr = encodeEd25519PublicKey(kp.publicBytes);
      const importedSeed = decodeEd25519SecretSeed(seedStr);
      const importedSigner = decodeEd25519PublicKey(signerStr);
      const derivedFromImportedSeed = await derivePublicKeyFromSeed(importedSeed);

      if (importedSigner.length !== derivedFromImportedSeed.length) {
        throw new Error('Imported signer length mismatch.');
      }
      for (let i = 0; i < importedSigner.length; i += 1) {
        if (importedSigner[i] !== derivedFromImportedSeed[i]) {
          throw new Error('Imported address does not match seed-derived public key.');
        }
      }
    }),

    createResult('ed25519 public derivation prefers provider and explicitly tests JWK fallback', async () => {
      const subtle = globalThis.crypto.subtle;
      const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
      const expected = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');

      let providerCalled = false;
      const providerSubtle = {
        importKey: subtle.importKey.bind(subtle),
        exportKey: subtle.exportKey.bind(subtle),
        async getPublicKey(privateKey, usages) {
          providerCalled = true;
          if (privateKey.extractable) throw new Error('Provider path received an extractable private key.');
          return subtle.importKey('raw', expected, { name: 'Ed25519' }, true, usages);
        },
      };
      const providerDerived = await derivePublicKeyFromSeed(seed, { subtle: providerSubtle });
      if (!providerCalled || !bytesEqual(providerDerived, expected)) {
        throw new Error('Provider Ed25519 public-key derivation path mismatch.');
      }

      let sawExtractableImport = false;
      const jwkSubtle = {
        importKey(...args) {
          if (args[0] === 'pkcs8' && args[3] === true) sawExtractableImport = true;
          return subtle.importKey(...args);
        },
        exportKey: subtle.exportKey.bind(subtle),
      };
      const jwkDerived = await derivePublicKeyFromSeed(seed, { subtle: jwkSubtle });
      if (!sawExtractableImport || !bytesEqual(jwkDerived, expected)) {
        throw new Error('JWK fallback Ed25519 public-key derivation path mismatch.');
      }

      await assertRejects(
        () =>
          derivePublicKeyFromSeed(seed, {
            subtle: {
              importKey: subtle.importKey.bind(subtle),
              async getPublicKey() {
                throw new Error('public-key provider failure');
              },
            },
          }),
        'public-key provider failure'
      );
    }),

    createResult('core copies never alias or wipe caller buffers (Node Buffer inputs)', async () => {
      if (typeof Buffer === 'undefined') return;
      const seed = Buffer.alloc(32, 0x42);
      await derivePublicKeyFromSeed(seed);
      (await createSigningKeySession(seed)).destroy();
      if (seed.some((byte) => byte !== 0x42)) throw new Error('Caller seed buffer was modified.');
      const publicKey = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
      const original = Buffer.from(publicKey);
      assertStrictEd25519PublicKey(publicKey);
      const hint = signatureHint(publicKey);
      hint.fill(0);
      if (!publicKey.equals(original)) throw new Error('Caller public key buffer was modified.');
    }),

    createResult('seed import with the matching public key never exports the private key', async () => {
      const subtle = globalThis.crypto.subtle;
      const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
      const publicBytes = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
      const observed = [];
      const auditingSubtle = {
        importKey(format, keyData, algorithm, extractable, usages) {
          if (format === 'pkcs8' && extractable) observed.push('extractable private import');
          return subtle.importKey(format, keyData, algorithm, extractable, usages);
        },
        exportKey(format, key) {
          observed.push(`export ${format}`);
          return subtle.exportKey(format, key);
        },
        sign: subtle.sign.bind(subtle),
        verify: subtle.verify.bind(subtle),
      };
      const session = await createSigningKeySession(seed, { publicBytes, subtle: auditingSubtle });
      session.destroy();
      if (observed.length) throw new Error(`Private key material left the provider: ${observed.join(', ')}.`);
    }),

    createResult('generated signing session rejects a mismatched supplied public key', async () => {
      const seedA = hexToBytes('0303030303030303030303030303030303030303030303030303030303030303');
      const seedB = hexToBytes('0404040404040404040404040404040404040404040404040404040404040404');
      const wrongPublic = await derivePublicKeyFromSeed(seedB);
      await assertRejects(
        () => createSigningKeySession(seedA, { publicBytes: wrongPublic }),
        'does not match the private seed'
      );
    }),

    createResult('ed25519 signing key is non-extractable', async () => {
      const seed = hexToBytes('0202020202020202020202020202020202020202020202020202020202020202');
      const signingKey = await captureSigningKeyUsedBySign(seed, utf8ToBytes('non-extractable signing path'));
      if (signingKey.extractable !== false) {
        throw new Error('Expected sign() CryptoKey to be non-extractable.');
      }
      await assertExportKeyRejected(signingKey);
      const signature = await signBytesWithSeed(seed, utf8ToBytes('non-extractable signing path'));
      if (signature.length !== 64) {
        throw new Error(`Expected 64-byte signature, got ${signature.length}.`);
      }
    }),

    createResult('strict Ed25519 rejects identity-point universal forgery', async () => {
      const identity = new Uint8Array(32);
      identity[0] = 1;
      const forged = new Uint8Array(64);
      forged[0] = 1;
      if (await verifyBytesWithPublic(identity, utf8ToBytes('arbitrary message'), forged)) {
        throw new Error('Identity-point forgery was accepted.');
      }
    }),

    createResult('strict Ed25519 policy rejects mixed-order public key and signature R with explicit diagnostics', async () => {
      // Canonical encoding of the Ed25519 base point plus the order-2 point.
      // It is on-curve and mixed-order, but not in the prime-order subgroup.
      const mixedOrderPoint = hexToBytes('9599999999999999999999999999999999999999999999999999999999999999');
      assertThrows(
        () => assertStrictEd25519PublicKey(mixedOrderPoint),
        'strict Ed25519 policy rejects public key'
      );
      const signature = new Uint8Array(64);
      signature.set(mixedOrderPoint, 0);
      assertThrows(
        () => assertStrictEd25519Signature(signature),
        'strict Ed25519 policy rejects signature R'
      );
    }),

    createResult('strict signature policy rejections are reported with their reason', async () => {
      const { doc, inputContext } = await makeSignedTextFixture('explicit strict-policy diagnostics');
      const signature = base64ToBytes(doc.signatureB64);
      const mixedOrderR = signature.slice();
      mixedOrderR.set(hexToBytes('9599999999999999999999999999999999999999999999999999999999999999'), 0);
      const nonCanonicalS = signature.slice();
      nonCanonicalS.set(hexToBytes('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010'), 32);
      for (const [bytes, reason] of [[mixedOrderR, 'rejects signature R'], [nonCanonicalS, 'scalar S is not canonical']]) {
        const verify = await verifyDetachedSignature({
          signatureDoc: { ...doc, signatureB64: bytesToBase64(bytes) },
          inputContext,
          expectedSigner: doc.signer,
        });
        if (verify.signatureValid || !verify.errors.some((line) => line.includes(reason))) {
          throw new Error(`Expected explicit "${reason}" diagnostic, got: ${verify.errors.join(' | ')}`);
        }
      }
    }),

    createResult('canonical JSON rejects non-I-JSON values', async () => {
      assertThrows(() => canonicalJsonStringify({ value: Number.NaN }), 'non-finite');
      assertThrows(() => canonicalJsonStringify({ value: '\ud800' }), 'unpaired UTF-16 surrogate');
    }),

    createResult('canonical SEP-53 test vectors', async () => {
      for (const vector of SEP53_CANONICAL_TEST_VECTORS) {
        const seedBytes = decodeEd25519SecretSeed(vector.seed);
        const inputContext = await makeCanonicalSep53Context(vector);
        const signResult = await signSep53Message({ seedBytes, messageBytes: inputContext.bytes });
        if (signResult.signatureB64 !== vector.signatureB64) {
          throw new Error(`${vector.id}: signature base64 mismatch.`);
        }

        const expectedHexFromB64 = bytesToHexLower(base64ToBytes(vector.signatureB64));
        if (expectedHexFromB64 !== vector.signatureHex) {
          throw new Error(`${vector.id}: fixture base64/hex mismatch.`);
        }

        const signatureHex = bytesToHexLower(signResult.signature);
        if (signatureHex !== vector.signatureHex) {
          throw new Error(`${vector.id}: signature hex mismatch.`);
        }

        const verify = await verifySep53Message({
          publicKeyBytes: decodeEd25519PublicKey(vector.address),
          messageBytes: inputContext.bytes,
          signatureBytes: signResult.signature,
        });
        if (!verify) throw new Error(`${vector.id}: canonical SEP-53 verification failed.`);
      }
    }),

    createResult('v3 protected manifest sign/verify text', async () => {
      const seed = hexToBytes('1212121212121212121212121212121212121212121212121212121212121212');
      const textContext = await makeTextContext('Strict SEP-53 text payload');

      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
      });

      if (signResult.doc.schema !== SIGNATURE_SCHEMA_V3) {
        throw new Error(`Expected ${SIGNATURE_SCHEMA_V3}, got ${signResult.doc.schema}`);
      }

      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: textContext,
        expectedSigner: signResult.signer,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID, got ${verify.summary}`);
      }
    }),

    createResult('v3 protected manifest binds exact filename', async () => {
      const seed = hexToBytes('1313131313131313131313131313131313131313131313131313131313131313');
      const fileContext = await makeFileContext('proof.bin', utf8ToBytes('Strict SEP-53 raw file bytes'));

      const signResult = await createLocalSep53MessageSignature({
        inputContext: fileContext,
        seedBytes: seed,
        signerAddress: '',
      });

      const verifyContext = await makeFileContext('renamed-proof.bin', utf8ToBytes('Strict SEP-53 raw file bytes'));
      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: verifyContext,
        expectedSigner: signResult.signer,
      });

      if (verify.valid || !verify.errors.some((line) => line.includes('filename mismatch'))) {
        throw new Error(`Expected filename-bound INVALID result, got: ${verify.errors.join(' | ')}`);
      }
      if (!verify.signatureValid || verify.inputMatches !== false || verify.contextMatches !== true || verify.summary !== 'MISMATCH') {
        throw new Error(`Expected valid-signature/input-mismatch outcome, got ${JSON.stringify(verify)}`);
      }
    }),

    createResult('v3 without an expected signer reports the signer as unverified, not valid', async () => {
      const { doc, inputContext } = await makeSignedTextFixture('self-asserted signer regression');
      for (const expectedSigner of ['', '   ']) {
        const verify = await verifyDetachedSignature({ signatureDoc: doc, inputContext, expectedSigner });
        if (verify.valid || verify.summary !== 'SIGNER_UNVERIFIED' || !verify.signatureValid) {
          throw new Error(`Expected SIGNER_UNVERIFIED without an expected signer, got ${verify.summary}.`);
        }
        if (verify.inputMatches !== true || verify.contextMatches !== null) {
          throw new Error('Signer identity must be NOT CHECKED when no expectation is supplied.');
        }
      }
      const anchored = await verifyDetachedSignature({ signatureDoc: doc, inputContext, expectedSigner: doc.signer });
      if (!anchored.valid || anchored.summary !== 'VALID') throw new Error(`Expected VALID, got ${anchored.summary}.`);
    }),

    createResult('v3 treats browser file media type as signed advisory metadata', async () => {
      const seed = hexToBytes('2323232323232323232323232323232323232323232323232323232323232323');
      const bytes = utf8ToBytes('{"portable":true}');
      const signingContext = await makeFileContext('portable.json', bytes, { mediaType: 'application/json' });
      const verifyingContext = await makeFileContext('portable.json', bytes, { mediaType: 'application/octet-stream' });
      const signResult = await createLocalSep53MessageSignature({
        inputContext: signingContext,
        seedBytes: seed,
        signerAddress: '',
      });
      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: verifyingContext,
        expectedSigner: signResult.signer,
      });

      if (!verify.valid || !verify.signatureValid || !verify.inputMatches || verify.summary !== 'VALID_WITH_WARNINGS') {
        throw new Error(`Expected valid advisory media-type warning, got: ${verify.details.join(' | ')}`);
      }
      if (!verify.warnings.some((line) => line.includes('Advisory media type differs'))) {
        throw new Error(`Expected explicit advisory media-type diagnostic, got: ${verify.warnings.join(' | ')}`);
      }
    }),

    createResult('v3 strict schema rejects unknown top-level key', async () => {
      const seed = hexToBytes('1616161616161616161616161616161616161616161616161616161616161616');
      const textContext = await makeTextContext('unknown top-level key warning');
      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
      });
      const verify = await verifyDetachedSignature({
        signatureDoc: {
          ...signResult.doc,
          unknownTopLevelKey: 'ignored',
        },
        inputContext: textContext,
      });

      if (verify.valid || !verify.errors.some((line) => line.includes('missing or unknown fields'))) {
        throw new Error(`Expected unknown-key rejection, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v3 verify fails when protected input descriptor is missing', async () => {
      const seed = hexToBytes('1717171717171717171717171717171717171717171717171717171717171717');
      const textContext = await makeTextContext('missing descriptor regression');
      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
      });
      const badDoc = { ...signResult.doc, protected: { ...signResult.doc.protected } };
      delete badDoc.protected.input;

      const verify = await verifyDetachedSignature({
        signatureDoc: badDoc,
        inputContext: textContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID when SEP-53 input descriptor is missing.');
      }
      if (!verify.errors.some((line) => line.includes('missing or unknown fields'))) {
        throw new Error(`Expected missing input descriptor failure, got: ${verify.errors.join(' | ')}`);
      }
    }),

    ...[63, 65, 127].map((size) =>
      createResult(`v3 verify rejects ${size}-byte SEP-53 signature`, async () => {
        const { doc, inputContext } = await makeSignedTextFixture('malformed signature length regression');
        const badDoc = {
          ...doc,
          signatureB64: bytesToBase64(new Uint8Array(size).fill(0xa5)),
        };
        const verify = await verifyDetachedSignature({
          signatureDoc: badDoc,
          inputContext,
        });

        if (verify.valid) {
          throw new Error(`Expected INVALID for ${size}-byte signature.`);
        }
        if (!verify.errors.some((line) => line.includes(size === 63 ? 'Expected 64-byte signature' : 'exceeds 64 bytes'))) {
          throw new Error(`Expected signature length diagnostic, got: ${verify.errors.join(' | ')}`);
        }
      })
    ),

    createResult('v3 authenticates the manifest before comparing selected input or signer context', async () => {
      const { doc } = await makeSignedTextFixture('authenticated manifest ordering');
      const signature = base64ToBytes(doc.signatureB64);
      signature[0] ^= 0x01;
      const wrongContext = await makeTextContext('different selected input');
      const verify = await verifyDetachedSignature({
        signatureDoc: { ...doc, signatureB64: bytesToBase64(signature) },
        inputContext: wrongContext,
        expectedSigner: doc.signer,
      });

      if (verify.signatureValid || verify.inputMatches !== null || verify.contextMatches !== null) {
        throw new Error('Unauthenticated manifest metadata must not drive input or expected-signer comparison results.');
      }
      if (verify.summary !== 'INVALID') throw new Error(`Expected INVALID, got ${verify.summary}.`);
    }),

    ...['', 'stellar-signature/v1', 'stellar-signature/v2', 'stellar-signature/v3 ', 'STELLAR-SIGNATURE/V3'].map((schema) =>
      createResult(`strict verifier rejects schema ${JSON.stringify(schema)}`, async () => {
        const { doc, inputContext } = await makeSignedTextFixture('schema strictness regression');
        const verify = await verifyDetachedSignature({
          signatureDoc: {
            ...doc,
            schema,
          },
          inputContext,
        });

        if (verify.valid) {
          throw new Error(`Expected INVALID for schema ${JSON.stringify(schema)}.`);
        }
        if (!verify.errors.some((line) => line.includes('Unsupported schema'))) {
          throw new Error(`Expected unsupported schema diagnostic, got: ${verify.errors.join(' | ')}`);
        }
      })
    ),

    createResult('strict JSON parser rejects duplicate keys', async () => {
      assertThrows(
        () => safeJsonParse('{"schema":"stellar-signature/v1","schema":"stellar-signature/v3"}'),
        'Duplicate JSON member: schema'
      );
      assertThrows(() => safeJsonParse('{"value":1e400}'), 'non-finite');
      safeJsonParse(`${'['.repeat(16)}${']'.repeat(16)}`, { maxDepth: 16 });
      assertThrows(() => safeJsonParse(`${'['.repeat(17)}${']'.repeat(17)}`, { maxDepth: 16 }), 'nesting exceeds 16');
      assertThrows(() => safeJsonParse(`{"a":${'{"a":'.repeat(16)}1${'}'.repeat(16)}}`, { maxDepth: 16 }), 'nesting exceeds 16');
    }),

    createResult('signature container text must be strict UTF-8 without BOM', async () => {
      if (decodeUtf8Strict(utf8ToBytes('{"a":"\u00e9"}')) !== '{"a":"\u00e9"}') throw new Error('Valid UTF-8 was not decoded.');
      assertThrows(() => decodeUtf8Strict(concatBytes(new Uint8Array([0xef, 0xbb, 0xbf]), utf8ToBytes('{}'))), 'byte-order mark');
      assertThrows(() => decodeUtf8Strict(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d])), 'not valid UTF-8');
      assertThrows(() => decodeUtf8Strict(new Uint8Array([0xed, 0xa0, 0x80])), 'not valid UTF-8');
    }),

    createResult('v3 protected manifest sign/verify empty text', async () => {
      const seed = hexToBytes('1818181818181818181818181818181818181818181818181818181818181818');
      const textContext = await makeTextContext('');
      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
      });
      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: textContext,
        expectedSigner: signResult.signer,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID for empty text, got ${verify.summary}.`);
      }
    }),

    createResult('v3 protected manifest sign/verify zero-byte file', async () => {
      const seed = hexToBytes('1919191919191919191919191919191919191919191919191919191919191919');
      const fileContext = await makeFileContext('empty.bin', new Uint8Array(0));
      const signResult = await createLocalSep53MessageSignature({
        inputContext: fileContext,
        seedBytes: seed,
        signerAddress: '',
      });
      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: fileContext,
        expectedSigner: signResult.signer,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID for zero-byte file, got ${verify.summary}.`);
      }
    }),

    ...[63, 64, 65].map((size) =>
      createResult(`v3 protected manifest sign/verify SHA-256 boundary file ${size} bytes`, async () => {
        await assertFileSignVerifyForSize(size);
      })
    ),

    ...[71, 72, 73].map((size) =>
      createResult(`v3 protected manifest sign/verify SHA3-512 boundary file ${size} bytes`, async () => {
        await assertFileSignVerifyForSize(size);
      })
    ),

    createResult('v3 protected manifest verify fails with modified file bytes', async () => {
      const seed = hexToBytes('1414141414141414141414141414141414141414141414141414141414141414');
      const goodFileContext = await makeFileContext('proof.bin', utf8ToBytes('Strict SEP-53 original file bytes'));
      const badFileContext = await makeFileContext('proof.bin', utf8ToBytes('Strict SEP-53 tampered file bytes'));

      const signResult = await createLocalSep53MessageSignature({
        inputContext: goodFileContext,
        seedBytes: seed,
        signerAddress: '',
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: badFileContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID for modified file bytes.');
      }
      if (!verify.errors.some((line) => line.includes('Protected SHA-256 digest'))) {
        throw new Error(`Expected strict SEP-53 verification failure, got: ${verify.errors.join(' | ')}`);
      }
      if (!verify.signatureValid || verify.inputMatches !== false || verify.summary !== 'MISMATCH') {
        throw new Error('Modified input must not be conflated with an invalid cryptographic signature.');
      }
    }),

    createResult('v3 local content signature serializes as RFC 8785 JSON', async () => {
      const seed = hexToBytes('1515151515151515151515151515151515151515151515151515151515151515');
      const textContext = await makeTextContext('canonical json payload');

      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
      });

      if (signResult.json.endsWith('\n')) {
        throw new Error('Canonical JSON must not include trailing whitespace.');
      }
      if (signResult.json.includes('  "')) {
        throw new Error('Expected canonical json output to be minified.');
      }
      if (!signResult.displayJson.includes('\n  "')) {
        throw new Error('Expected display json output to be pretty-printed.');
      }
    }),

    createResult('v3 protected manifest verify fails with wrong signer', async () => {
      const seedA = hexToBytes('6666666666666666666666666666666666666666666666666666666666666666');
      const seedB = hexToBytes('7777777777777777777777777777777777777777777777777777777777777777');
      const textContext = await makeTextContext('wrong signer test text');

      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seedA,
        signerAddress: '',
      });

      const wrongSigner = encodeEd25519PublicKey(await derivePublicKeyFromSeed(seedB));
      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: textContext,
        expectedSigner: wrongSigner,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID when expected signer does not match signature signer.');
      }
      if (!verify.errors.some((line) => line.includes('Wrong signer'))) {
        throw new Error(`Expected wrong signer diagnostic, got: ${verify.errors.join(' | ')}`);
      }
      if (!verify.signatureValid || verify.contextMatches !== false || verify.inputMatches !== true || verify.summary !== 'MISMATCH') {
        throw new Error('Expected-signer mismatch must remain distinct from cryptographic signature validity.');
      }
    }),

    createResult('v3 protected manifest verify fails with wrong text input', async () => {
      const seed = hexToBytes('8888888888888888888888888888888888888888888888888888888888888888');
      const goodTextContext = await makeTextContext('original text payload');
      const badTextContext = await makeTextContext('tampered text payload');

      const signResult = await createLocalSep53MessageSignature({
        inputContext: goodTextContext,
        seedBytes: seed,
        signerAddress: '',
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: badTextContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID for wrong text input.');
      }
      if (!verify.errors.some((line) => line.includes('Protected SHA-256 digest'))) {
        throw new Error(`Expected SEP-53 verification failure for text, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v3 protected manifest verify fails with wrong file input', async () => {
      const seed = hexToBytes('9999999999999999999999999999999999999999999999999999999999999999');
      const goodFileContext = await makeFileContext('doc.txt', utf8ToBytes('original file bytes'));
      const badFileContext = await makeFileContext('doc.txt', utf8ToBytes('modified file bytes'));

      const signResult = await createLocalSep53MessageSignature({
        inputContext: goodFileContext,
        seedBytes: seed,
        signerAddress: '',
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: badFileContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID for wrong file input.');
      }
      if (!verify.errors.some((line) => line.includes('Protected SHA-256 digest'))) {
        throw new Error(`Expected SEP-53 verification failure for file, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v3 XDR protected-manifest proof sign/verify', async () => {
      const seed = hexToBytes('3333333333333333333333333333333333333333333333333333333333333333');
      const fileContext = await makeFileContext('image.bin', utf8ToBytes('binary-like-content'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = await createXdrProofDraft({
        inputContext: fileContext,
        signerAddress: signer,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
      });

      const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
      const signature = await signBytesWithSeed(seed, txHash);
      const hint = signatureHint(decodeEd25519PublicKey(signer));

      const signedEnvelope = encodeSignedTxEnvelope({
        txXdr: draft.txXdr,
        signatures: [{ hint, signature }],
      });

      const signedXdr = bytesToBase64(signedEnvelope);
      const xdrDoc = await finalizeXdrProof({
        inputContext: fileContext,
        signedXdr,
        draft,
        expectedSigner: signer,
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: xdrDoc.doc,
        inputContext: fileContext,
        expectedSigner: signer,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID, got ${verify.summary}`);
      }
    }),

    createResult('XDR hyper sequence uses signed two-complement int64 semantics', async () => {
      const sourcePublicKey = new Uint8Array(32);
      const dataValue = new Uint8Array(32);
      const build = (sequence) => buildUnsignedManifestEnvelope({ sourcePublicKey, sequence, manifestDigest: dataValue });

      for (const sequence of [-(1n << 63n), -1n, 0n, (1n << 63n) - 1n]) {
        const parsed = parseTransactionEnvelope(build(sequence).envelopeXdr);
        if (parsed.transaction.sequence !== sequence) {
          throw new Error(`Signed int64 round-trip mismatch: expected ${sequence}, got ${parsed.transaction.sequence}.`);
        }
      }
      assertThrows(() => build(-(1n << 63n) - 1n), 'int64 out of range');
      assertThrows(() => build(1n << 63n), 'int64 out of range');
    }),

    createResult('XDR finalization rejects identical-metadata stale content', async () => {
      const original = await makeFileContext('same.bin', utf8ToBytes('content-A'));
      const replacement = await makeFileContext('same.bin', utf8ToBytes('content-B'));
      const fixture = await makeXdrFixture(
        '3030303030303030303030303030303030303030303030303030303030303030',
        original
      );
      await assertRejects(
        () =>
          finalizeXdrProof({
            inputContext: replacement,
            signedXdr: fixture.signedXdr,
            draft: fixture.draft,
            expectedSigner: fixture.signer,
          }),
        'Selected input or protected metadata changed'
      );
    }),

    createResult('XDR finalization requires exact unsigned draft transaction bytes', async () => {
      const context = await makeTextContext('exact unsigned XDR binding');
      const fixture = await makeXdrFixture(
        '3131313131313131313131313131313131313131313131313131313131313131',
        context
      );
      const modifiedTx = fixture.draft.txXdr.slice();
      new DataView(modifiedTx.buffer, modifiedTx.byteOffset, modifiedTx.byteLength).setUint32(36, 99999, false);
      const modifiedHash = await computeTransactionHash(modifiedTx, TESTNET_NETWORK_PASSPHRASE);
      const modifiedSignature = await signBytesWithSeed(fixture.seed, modifiedHash);
      const modifiedXdr = bytesToBase64(
        encodeSignedTxEnvelope({
          txXdr: modifiedTx,
          signatures: [{ hint: fixture.hint, signature: modifiedSignature }],
        })
      );
      await assertRejects(
        () =>
          finalizeXdrProof({
            inputContext: context,
            signedXdr: modifiedXdr,
            draft: fixture.draft,
            expectedSigner: fixture.signer,
          }),
        'differs from the exact unsigned draft'
      );
    }),

    createResult('XDR proof rejects extra or oversized decorated signatures', async () => {
      const context = await makeTextContext('strict signature vector bounds');
      const fixture = await makeXdrFixture(
        '3232323232323232323232323232323232323232323232323232323232323232',
        context
      );
      const extraXdr = bytesToBase64(
        encodeSignedTxEnvelope({
          txXdr: fixture.draft.txXdr,
          signatures: [
            { hint: fixture.hint, signature: fixture.signature },
            { hint: fixture.hint, signature: fixture.signature },
          ],
        })
      );
      await assertRejects(
        () =>
          finalizeXdrProof({
            inputContext: context,
            signedXdr: extraXdr,
            draft: fixture.draft,
            expectedSigner: fixture.signer,
          }),
        'requires exactly one decorated signature'
      );

      const oversized = new Uint8Array(65);
      const oversizedXdr = bytesToBase64(
        encodeEnvelopeWithOpaqueSignature({ txXdr: fixture.draft.txXdr, hint: fixture.hint, signature: oversized })
      );
      await assertRejects(
        () =>
          finalizeXdrProof({
            inputContext: context,
            signedXdr: oversizedXdr,
            draft: fixture.draft,
            expectedSigner: fixture.signer,
          }),
        'Invalid opaque length'
      );
    }),

    createResult('XDR parser rejects non-zero RFC 4506 padding', async () => {
      const context = await makeTextContext('strict XDR padding');
      const fixture = await makeXdrFixture(
        '3434343434343434343434343434343434343434343434343434343434343434',
        context
      );
      const malformedTx = fixture.draft.txXdr.slice();
      const nameBytes = utf8ToBytes(MANIFEST_DATA_NAME);
      const nameOffset = indexOfBytes(malformedTx, nameBytes);
      if (nameOffset < 0) throw new Error('ManageData name not found in test transaction.');
      const padLength = (4 - (nameBytes.length % 4)) % 4;
      if (padLength === 0) throw new Error('Test ManageData name unexpectedly has no XDR padding.');
      malformedTx[nameOffset + nameBytes.length] = 0x7f;
      const malformedHash = await computeTransactionHash(malformedTx, TESTNET_NETWORK_PASSPHRASE);
      const malformedSignature = await signBytesWithSeed(fixture.seed, malformedHash);
      const malformedXdr = bytesToBase64(
        encodeSignedTxEnvelope({
          txXdr: malformedTx,
          signatures: [{ hint: fixture.hint, signature: malformedSignature }],
        })
      );
      await assertRejects(
        () =>
          finalizeXdrProof({
            inputContext: context,
            signedXdr: malformedXdr,
            draft: fixture.draft,
            expectedSigner: fixture.signer,
          }),
        'padding bytes must be zero'
      );
    }),

    createResult('XDR ManageData names must be printable ASCII (BOM, UTF-8, controls rejected)', async () => {
      const context = await makeTextContext('ascii data name');
      const fixture = await makeXdrFixture(
        '3636363636363636363636363636363636363636363636363636363636363636',
        context
      );
      const name = utf8ToBytes(MANIFEST_DATA_NAME);
      const withName = (nameBytes) => {
        const tx = fixture.draft.txXdr;
        const offset = indexOfBytes(tx, name);
        const pad = (bytes) => new Uint8Array((4 - (bytes.length % 4)) % 4);
        return concatBytes(
          tx.subarray(0, offset - 4),
          uint32Bytes(nameBytes.length),
          nameBytes,
          pad(nameBytes),
          tx.subarray(offset + name.length + pad(name).length)
        );
      };
      const variants = [
        concatBytes(new Uint8Array([0xef, 0xbb, 0xbf]), name), // UTF-8 BOM, previously stripped by the decoder
        concatBytes(name, new Uint8Array([0x7f])),
        concatBytes(name, new Uint8Array([0x0a])),
        concatBytes(name, utf8ToBytes('\u00e9')),
      ];
      for (const variant of variants) {
        const tx = withName(variant);
        assertThrows(() => parseTransactionEnvelope(concatBytes(uint32Bytes(2), tx, uint32Bytes(0))), 'printable ASCII');
      }

      // End to end: a correctly signed proof whose data name carries a BOM must not verify.
      const bomTx = withName(variants[0]);
      const bomHash = await computeTransactionHash(bomTx, TESTNET_NETWORK_PASSPHRASE);
      const bomXdr = bytesToBase64(
        encodeSignedTxEnvelope({ txXdr: bomTx, signatures: [{ hint: fixture.hint, signature: await signBytesWithSeed(fixture.seed, bomHash) }] })
      );
      const verify = await verifyDetachedSignature({
        signatureDoc: { schema: SIGNATURE_SCHEMA_V3, signer: fixture.signer, protected: fixture.draft.protectedManifest, signedXdr: bomXdr },
        inputContext: context,
        expectedSigner: fixture.signer,
      });
      if (verify.signatureValid || !verify.errors.some((line) => line.includes('printable ASCII'))) {
        throw new Error(`BOM-prefixed ManageData name was not rejected: ${verify.summary}`);
      }
    }),

    createResult('XDR parser rejects non-canonical base64 whitespace', async () => {
      const context = await makeTextContext('strict base64 XDR');
      const fixture = await makeXdrFixture(
        '3535353535353535353535353535353535353535353535353535353535353535',
        context
      );
      const withWhitespace = `${fixture.signedXdr.slice(0, 16)}\n${fixture.signedXdr.slice(16)}`;
      await assertRejects(
        () =>
          finalizeXdrProof({
            inputContext: context,
            signedXdr: withWhitespace,
            draft: fixture.draft,
            expectedSigner: fixture.signer,
          }),
        'canonical padding'
      );
    }),

    createResult('v3 XDR proof binds network passphrase in protected manifest', async () => {
      const seed = hexToBytes('4444444444444444444444444444444444444444444444444444444444444444');
      const fileContext = await makeFileContext('a.bin', utf8ToBytes('wallet mode network mismatch test'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = await createXdrProofDraft({
        inputContext: fileContext,
        signerAddress: signer,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
      });

      const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
      const signature = await signBytesWithSeed(seed, txHash);
      const hint = signatureHint(signerPublic);

      const signedEnvelope = encodeSignedTxEnvelope({
        txXdr: draft.txXdr,
        signatures: [{ hint, signature }],
      });

      const signedXdr = bytesToBase64(signedEnvelope);
      const xdrDoc = await finalizeXdrProof({
        inputContext: fileContext,
        signedXdr,
        draft,
        expectedSigner: signer,
      });

      const badDoc = {
        ...xdrDoc.doc,
        protected: {
          ...xdrDoc.doc.protected,
          network: {
            passphrase: 'Public Global Stellar Network ; September 2015',
            hint: 'pubnet',
          },
        },
      };

      const verify = await verifyDetachedSignature({
        signatureDoc: badDoc,
        inputContext: fileContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID for wrong network passphrase.');
      }

      const joined = verify.errors.join(' | ');
      if (!joined.includes('ManageData value mismatch')) {
        throw new Error(`Expected protected network binding failure, got: ${joined}`);
      }
    }),

    createResult('v3 XDR proof rejects incomplete protected hash coverage', async () => {
      const seed = hexToBytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      const textContext = await makeTextContext('incomplete coverage regression');

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = await createXdrProofDraft({
        inputContext: textContext,
        signerAddress: signer,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
      });

      const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
      const signature = await signBytesWithSeed(seed, txHash);
      const hint = signatureHint(signerPublic);
      const signedEnvelope = encodeSignedTxEnvelope({
        txXdr: draft.txXdr,
        signatures: [{ hint, signature }],
      });
      const signedXdr = bytesToBase64(signedEnvelope);

      const xdrDoc = await finalizeXdrProof({
        inputContext: textContext,
        signedXdr,
        draft,
        expectedSigner: signer,
      });

      const tamperedDoc = {
        ...xdrDoc.doc,
        protected: {
          ...xdrDoc.doc.protected,
          hashes: xdrDoc.doc.protected.hashes.slice(0, 1),
        },
      };

      const verify = await verifyDetachedSignature({
        signatureDoc: tamperedDoc,
        inputContext: textContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID for incomplete ManageData/hash coverage.');
      }
      if (!verify.errors.some((line) => line.includes('exactly SHA-256 and SHA3-512'))) {
        throw new Error(`Expected exact-count mismatch diagnostic, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v3 XDR proof requires protected manifest', async () => {
      const seed = hexToBytes('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
      const fileContext = await makeFileContext('strict.json', utf8ToBytes('strict manageData section'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = await createXdrProofDraft({
        inputContext: fileContext,
        signerAddress: signer,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
      });

      const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
      const signature = await signBytesWithSeed(seed, txHash);
      const hint = signatureHint(signerPublic);
      const signedEnvelope = encodeSignedTxEnvelope({
        txXdr: draft.txXdr,
        signatures: [{ hint, signature }],
      });
      const signedXdr = bytesToBase64(signedEnvelope);

      const xdrDoc = await finalizeXdrProof({
        inputContext: fileContext,
        signedXdr,
        draft,
        expectedSigner: signer,
      });

      const badDoc = {
        ...xdrDoc.doc,
      };
      delete badDoc.protected;

      const verify = await verifyDetachedSignature({
        signatureDoc: badDoc,
        inputContext: fileContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID when manageData.entries is missing.');
      }
      if (!verify.errors.some((line) => line.includes('proofType'))) {
        throw new Error(`Expected protected manifest diagnostic, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v3 verify rejects unprotected profile metadata', async () => {
      const seed = hexToBytes('cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd');
      const textContext = await makeTextContext('strict profile metadata');

      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
      });

      const tamperedDoc = {
        ...signResult.doc,
        signatureScheme: SIGNATURE_SCHEME.TX_ENVELOPE_ED25519,
      };

      const verify = await verifyDetachedSignature({
        signatureDoc: tamperedDoc,
        inputContext: textContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID for tampered signature profile.');
      }
      if (!verify.errors.some((line) => line.includes('missing or unknown fields'))) {
        throw new Error(`Expected strict profile rejection, got: ${verify.errors.join(' | ')}`);
      }
    }),
  ];

  for (const t of tests) {
    try {
      await t.fn();
      results.push({ name: t.name, ok: true });
    } catch (err) {
      results.push({
        name: t.name,
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const passed = results.filter((r) => r.ok).length;
  return {
    ok: passed === results.length,
    total: results.length,
    passed,
    results,
  };
}

function assertThrows(fn, expectedSubstring) {
  let thrown = null;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }

  if (!thrown) {
    throw new Error('Expected function to throw.');
  }

  const message = thrown instanceof Error ? thrown.message : String(thrown);
  if (!message.includes(expectedSubstring)) {
    throw new Error(`Expected error message to include "${expectedSubstring}", got "${message}".`);
  }
}

async function assertRejects(fn, expectedSubstring) {
  let thrown = null;
  try {
    await fn();
  } catch (err) {
    thrown = err;
  }
  if (!thrown) throw new Error('Expected async function to reject.');
  const message = thrown instanceof Error ? thrown.message : String(thrown);
  if (!message.includes(expectedSubstring)) {
    throw new Error(`Expected error message to include "${expectedSubstring}", got "${message}".`);
  }
}

async function captureSigningKeyUsedBySign(seedBytes, messageBytes) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.sign !== 'function') {
    throw new Error('WebCrypto subtle.sign is unavailable.');
  }

  const hadOwnSign = Object.prototype.hasOwnProperty.call(subtle, 'sign');
  const ownSignDescriptor = Object.getOwnPropertyDescriptor(subtle, 'sign');
  const originalSign = subtle.sign;
  let signingKey = null;
  try {
    subtle.sign = function spySign(algorithm, key, data) {
      signingKey = key;
      return originalSign.call(this, algorithm, key, data);
    };
    const signature = await signBytesWithSeed(seedBytes, messageBytes);
    if (signature.length !== 64) {
      throw new Error(`Expected 64-byte signature, got ${signature.length}.`);
    }
  } finally {
    if (hadOwnSign) Object.defineProperty(subtle, 'sign', ownSignDescriptor);
    else delete subtle.sign;
  }

  if (!signingKey) {
    throw new Error('signBytesWithSeed did not call subtle.sign.');
  }
  return signingKey;
}

async function assertExportKeyRejected(key) {
  let thrown = null;
  try {
    await globalThis.crypto.subtle.exportKey('jwk', key);
  } catch (err) {
    thrown = err;
  }

  if (!thrown) {
    throw new Error('Expected exportKey("jwk") to reject for sign() key.');
  }

  const name = String(thrown.name || '');
  if (name !== 'InvalidAccessError' && name !== 'InvalidAccessException') {
    const message = thrown instanceof Error ? thrown.message : String(thrown);
    throw new Error(`Expected InvalidAccessError from exportKey, got ${name || message}.`);
  }
}
