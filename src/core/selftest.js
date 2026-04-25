import { base64ToBytes, bytesToBase64, bytesToHexLower, hexToBytes, utf8ToBytes } from './bytes.js';
import { derivePublicKeyFromSeed, generateKeypair, signatureHint, signBytesWithSeed } from './ed25519.js';
import { computeDigests, createSha256Stream, createSha3_512Stream, sha256, sha3_512 } from './hash.js';
import { HASH_ALG, SIGNATURE_SCHEMA_V2, SIGNATURE_SCHEME, TESTNET_NETWORK_PASSPHRASE } from './constants.js';
import { createLocalSep53MessageSignature } from './signing.js';
import { createFileInputContext } from './input-context.js';
import { SEP53_CANONICAL_TEST_VECTORS } from './sep53-test-vectors.js';
import { createXdrProofDraft, finalizeXdrProof } from './xdr-proof.js';
import { encodeEd25519PublicKey, decodeEd25519PublicKey, decodeEd25519SecretSeed, encodeEd25519SecretSeed } from './strkey.js';
import { verifyDetachedSignature } from './verify.js';
import { computeTransactionHash, encodeSignedTxEnvelope } from './xdr.js';

function createResult(name, fn) {
  return { name, fn };
}

async function makeFileContext(name, bytes, options = {}) {
  const digests = await computeDigests(bytes);
  return {
    type: 'file',
    fileName: name,
    fileSize: bytes.length,
    bytes: options.keepBytes === false ? new Uint8Array(0) : bytes,
    digests,
  };
}

async function makeTextContext(text, options = {}) {
  const bytes = utf8ToBytes(text);
  const digests = await computeDigests(bytes);
  return {
    type: 'text',
    fileName: '',
    fileSize: bytes.length,
    bytes: options.keepBytes === false ? new Uint8Array(0) : bytes,
    digests,
  };
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
  });

  if (!verify.valid) {
    throw new Error(`Expected VALID for ${size}-byte file, got ${verify.summary}.`);
  }
}

async function assertSha3_512Hex(name, bytes, expectedHex) {
  const actualHex = bytesToHexLower(await sha3_512(bytes));
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

function makePlaceholderDigests() {
  const sha256Bytes = new Uint8Array(32);
  const sha3Bytes = new Uint8Array(64);
  return {
    sha256: {
      alg: HASH_ALG.SHA256,
      bytes: sha256Bytes,
      hex: bytesToHexLower(sha256Bytes),
      base64: bytesToBase64(sha256Bytes),
    },
    sha3_512: {
      alg: HASH_ALG.SHA3_512,
      bytes: sha3Bytes,
      hex: bytesToHexLower(sha3Bytes),
      base64: bytesToBase64(sha3Bytes),
    },
  };
}

export async function runSelfTest() {
  const results = [];

  const tests = [
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
        await assertSha3_512Hex(name, bytes, expectedHex);
      }
    }),

    createResult('streaming digest vectors and corpus', async () => {
      const sha256Vectors = [
        [
          'empty',
          new Uint8Array(0),
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ],
        [
          'abc',
          utf8ToBytes('abc'),
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        ],
        [
          'rfc4634 multi-block',
          utf8ToBytes('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
          '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
        ],
      ];

      for (const [name, bytes, expectedHex] of sha256Vectors) {
        const actualHex = bytesToHexLower(await digestWithChunks(createSha256Stream, bytes, [1, 7, 64, 3]));
        if (actualHex !== expectedHex) {
          throw new Error(`SHA-256 stream ${name}: expected ${expectedHex}, got ${actualHex}.`);
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

        const oneShotSha256 = bytesToHexLower(await sha256(bytes));
        const streamSha256 = bytesToHexLower(await digestWithChunks(createSha256Stream, bytes, chunkSizes));
        if (streamSha256 !== oneShotSha256) {
          throw new Error(`SHA-256 stream corpus mismatch at size ${size}.`);
        }

        const oneShotSha3 = bytesToHexLower(await sha3_512(bytes));
        const streamSha3 = bytesToHexLower(await digestWithChunks(createSha3_512Stream, bytes, chunkSizes));
        if (streamSha3 !== oneShotSha3) {
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
        keepBytes: false,
        onProgress(item) {
          progress.push(item.phase);
        },
      });
      const expected = await computeDigests(bytes);

      if (streamed.bytes.length !== 0) {
        throw new Error('Expected digest-only file context to avoid retaining bytes.');
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

      const buffered = await createFileInputContext(file, { chunkSize: 257, keepBytes: true });
      if (buffered.bytes.length !== bytes.length) {
        throw new Error('Expected buffered file context to retain bytes.');
      }
      for (let i = 0; i < bytes.length; i += 1) {
        if (buffered.bytes[i] !== bytes[i]) {
          throw new Error('Buffered file context byte mismatch.');
        }
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
          keepBytes: true,
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

    createResult('SEP-53 local signing avoids duplicate input buffer', async () => {
      if (typeof process === 'undefined' || typeof process.memoryUsage !== 'function') {
        return;
      }

      const size = 64 * 1024 * 1024;
      const bytes = new Uint8Array(size);
      for (let i = 0; i < bytes.length; i += 4096) {
        bytes[i] = (i >>> 12) & 0xff;
      }

      const seed = hexToBytes('2222222222222222222222222222222222222222222222222222222222222222');
      const inputContext = {
        type: 'file',
        fileName: 'large-sep53-memory.bin',
        fileSize: bytes.length,
        fileLastModified: 0,
        bytes,
        digests: makePlaceholderDigests(),
      };

      globalThis.gc?.();
      const before = process.memoryUsage();
      const result = await createLocalSep53MessageSignature({
        inputContext,
        seedBytes: seed,
        signerAddress: '',
      });
      const after = process.memoryUsage();

      if (!result.signatureB64 || result.signatureB64.length === 0) {
        throw new Error('Expected large SEP-53 signature output.');
      }

      const heapDelta = after.heapUsed - before.heapUsed;
      const heapLimit = 24 * 1024 * 1024;
      if (heapDelta > heapLimit) {
        throw new Error(`SEP-53 signing heap delta too high: ${heapDelta} bytes.`);
      }

      if (Number.isFinite(before.arrayBuffers) && Number.isFinite(after.arrayBuffers)) {
        const arrayBufferDelta = after.arrayBuffers - before.arrayBuffers;
        const arrayBufferLimit = 16 * 1024 * 1024;
        if (arrayBufferDelta > arrayBufferLimit) {
          throw new Error(`SEP-53 signing ArrayBuffer delta too high: ${arrayBufferDelta} bytes.`);
        }
      }
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

    createResult('canonical SEP-53 test vectors', async () => {
      for (const vector of SEP53_CANONICAL_TEST_VECTORS) {
        const seedBytes = decodeEd25519SecretSeed(vector.seed);
        const inputContext = await makeCanonicalSep53Context(vector);
        const signResult = await createLocalSep53MessageSignature({
          inputContext,
          seedBytes,
          signerAddress: vector.address,
        });

        if (signResult.signer !== vector.address) {
          throw new Error(`${vector.id}: expected signer ${vector.address}, got ${signResult.signer}.`);
        }
        if (signResult.doc.signatureB64 !== vector.signatureB64) {
          throw new Error(`${vector.id}: signature base64 mismatch.`);
        }

        const expectedHexFromB64 = bytesToHexLower(base64ToBytes(vector.signatureB64));
        if (expectedHexFromB64 !== vector.signatureHex) {
          throw new Error(`${vector.id}: fixture base64/hex mismatch.`);
        }

        const signatureHex = bytesToHexLower(base64ToBytes(signResult.doc.signatureB64));
        if (signatureHex !== vector.signatureHex) {
          throw new Error(`${vector.id}: signature hex mismatch.`);
        }

        const verify = await verifyDetachedSignature({
          signatureDoc: signResult.doc,
          inputContext,
          expectedSigner: vector.address,
        });
        if (!verify.valid) {
          throw new Error(`${vector.id}: expected VALID, got ${verify.summary}.`);
        }
      }
    }),

    createResult('v2 local content signature sign/verify text', async () => {
      const seed = hexToBytes('1212121212121212121212121212121212121212121212121212121212121212');
      const textContext = await makeTextContext('Strict SEP-53 text payload');

      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
      });

      if (signResult.doc.schema !== SIGNATURE_SCHEMA_V2) {
        throw new Error(`Expected ${SIGNATURE_SCHEMA_V2}, got ${signResult.doc.schema}`);
      }

      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: textContext,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID, got ${verify.summary}`);
      }
    }),

    createResult('v2 local content signature sign/verify file bytes', async () => {
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
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID, got ${verify.summary}`);
      }
    }),

    createResult('v2 verify warns on unknown top-level key', async () => {
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

      if (!verify.valid) {
        throw new Error(`Expected VALID with unknown top-level key warning, got ${verify.summary}.`);
      }
      if (!verify.warnings.some((line) => line.includes('Unknown top-level key ignored: unknownTopLevelKey'))) {
        throw new Error(`Expected unknown-key warning, got: ${verify.warnings.join(' | ')}`);
      }
    }),

    createResult('v2 verify fails when SEP-53 input descriptor is missing', async () => {
      const seed = hexToBytes('1717171717171717171717171717171717171717171717171717171717171717');
      const textContext = await makeTextContext('missing descriptor regression');
      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
      });
      const badDoc = { ...signResult.doc };
      delete badDoc.input;

      const verify = await verifyDetachedSignature({
        signatureDoc: badDoc,
        inputContext: textContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID when SEP-53 input descriptor is missing.');
      }
      if (!verify.errors.some((line) => line.includes('Signature input descriptor is missing'))) {
        throw new Error(`Expected missing input descriptor failure, got: ${verify.errors.join(' | ')}`);
      }
    }),

    ...[63, 65, 127].map((size) =>
      createResult(`v2 verify rejects ${size}-byte SEP-53 signature`, async () => {
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
        const expected = `Expected 64-byte signature, got ${size}`;
        if (!verify.errors.some((line) => line.includes(expected))) {
          throw new Error(`Expected signature length diagnostic "${expected}", got: ${verify.errors.join(' | ')}`);
        }
      })
    ),

    ...['', 'stellar-signature/v1', 'stellar-signature/v2 ', 'STELLAR-SIGNATURE/V2'].map((schema) =>
      createResult(`v2 verify rejects schema ${JSON.stringify(schema)}`, async () => {
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

    createResult('v2 verify documents duplicate JSON key last-wins outcome', async () => {
      const { doc, inputContext } = await makeSignedTextFixture('duplicate key stable outcome');
      const duplicatedJson = `{"schema":"stellar-signature/v1","schema":${JSON.stringify(doc.schema)},"signer":${JSON.stringify(doc.signer)},"proofType":${JSON.stringify(doc.proofType)},"payloadType":${JSON.stringify(doc.payloadType)},"signatureScheme":${JSON.stringify(doc.signatureScheme)},"input":${JSON.stringify(doc.input)},"hashes":${JSON.stringify(doc.hashes)},"signatureB64":${JSON.stringify(doc.signatureB64)}}`;
      const parsed = JSON.parse(duplicatedJson);
      if (parsed.schema !== doc.schema) {
        throw new Error('Expected JSON parser last-wins behavior for duplicate schema key.');
      }
      const verify = await verifyDetachedSignature({
        signatureDoc: parsed,
        inputContext,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID for documented duplicate-key last-wins outcome, got ${verify.summary}.`);
      }
    }),

    createResult('v2 local content signature sign/verify empty text', async () => {
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
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID for empty text, got ${verify.summary}.`);
      }
    }),

    createResult('v2 local content signature sign/verify zero-byte file', async () => {
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
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID for zero-byte file, got ${verify.summary}.`);
      }
    }),

    ...[63, 64, 65].map((size) =>
      createResult(`v2 local content signature sign/verify SHA-256 boundary file ${size} bytes`, async () => {
        await assertFileSignVerifyForSize(size);
      })
    ),

    ...[71, 72, 73].map((size) =>
      createResult(`v2 local content signature sign/verify SHA3-512 boundary file ${size} bytes`, async () => {
        await assertFileSignVerifyForSize(size);
      })
    ),

    createResult('v2 local content signature verify fails with modified file bytes', async () => {
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
      if (!verify.errors.some((line) => line.includes('SEP-53 content signature verification failed'))) {
        throw new Error(`Expected strict SEP-53 verification failure, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v2 local content signature serializes to canonical json', async () => {
      const seed = hexToBytes('1515151515151515151515151515151515151515151515151515151515151515');
      const textContext = await makeTextContext('canonical json payload');

      const signResult = await createLocalSep53MessageSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
      });

      if (!signResult.json.endsWith('\n')) {
        throw new Error('Expected canonical json output to end with newline.');
      }
      if (signResult.json.includes('  "')) {
        throw new Error('Expected canonical json output to be minified.');
      }
      if (!signResult.displayJson.includes('\n  "')) {
        throw new Error('Expected display json output to be pretty-printed.');
      }
    }),

    createResult('v2 local content signature verify fails with wrong signer', async () => {
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
    }),

    createResult('v2 local content signature verify fails with wrong text input', async () => {
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
      if (!verify.errors.some((line) => line.includes('SEP-53 content signature verification failed'))) {
        throw new Error(`Expected SEP-53 verification failure for text, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v2 local content signature verify fails with wrong file input', async () => {
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
      if (!verify.errors.some((line) => line.includes('SEP-53 content signature verification failed'))) {
        throw new Error(`Expected SEP-53 verification failure for file, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v2 xdr proof sign/verify', async () => {
      const seed = hexToBytes('3333333333333333333333333333333333333333333333333333333333333333');
      const fileContext = await makeFileContext('image.bin', utf8ToBytes('binary-like-content'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = createXdrProofDraft({
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
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        expectedSigner: signer,
        expectedManageDataEntries: draft.boundHashes,
        hashSelection: draft.hashSelection,
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: xdrDoc.doc,
        inputContext: fileContext,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID, got ${verify.summary}`);
      }
    }),

    createResult('v2 xdr proof wrong network passphrase detection', async () => {
      const seed = hexToBytes('4444444444444444444444444444444444444444444444444444444444444444');
      const fileContext = await makeFileContext('a.bin', utf8ToBytes('wallet mode network mismatch test'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = createXdrProofDraft({
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
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        expectedSigner: signer,
        expectedManageDataEntries: draft.boundHashes,
        hashSelection: draft.hashSelection,
      });

      const badDoc = {
        ...xdrDoc.doc,
        network: {
          ...xdrDoc.doc.network,
          passphrase: 'Public Global Stellar Network ; September 2015',
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
      if (!joined.includes('Wrong network passphrase')) {
        throw new Error(`Expected wrong-passphrase diagnostic, got: ${joined}`);
      }
    }),

    createResult('v2 xdr proof verify rejects incomplete hash coverage', async () => {
      const seed = hexToBytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      const textContext = await makeTextContext('incomplete coverage regression');

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = createXdrProofDraft({
        inputContext: textContext,
        signerAddress: signer,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        hashSelection: 'sha256',
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
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        expectedSigner: signer,
        expectedManageDataEntries: draft.boundHashes,
        hashSelection: draft.hashSelection,
      });

      const tamperedDoc = {
        ...xdrDoc.doc,
        hashes: [
          ...xdrDoc.doc.hashes,
          {
            alg: HASH_ALG.SHA3_512,
            hex: textContext.digests.sha3_512.hex,
          },
        ],
      };

      const verify = await verifyDetachedSignature({
        signatureDoc: tamperedDoc,
        inputContext: textContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID for incomplete ManageData/hash coverage.');
      }
      if (!verify.errors.some((line) => line.includes('count must exactly match'))) {
        throw new Error(`Expected exact-count mismatch diagnostic, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v2 xdr proof verify requires manageData.entries', async () => {
      const seed = hexToBytes('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
      const fileContext = await makeFileContext('strict.json', utf8ToBytes('strict manageData section'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = createXdrProofDraft({
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
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        expectedSigner: signer,
        expectedManageDataEntries: draft.boundHashes,
        hashSelection: draft.hashSelection,
      });

      const badDoc = {
        ...xdrDoc.doc,
      };
      delete badDoc.manageData;

      const verify = await verifyDetachedSignature({
        signatureDoc: badDoc,
        inputContext: fileContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID when manageData.entries is missing.');
      }
      if (!verify.errors.some((line) => line.includes('manageData.entries'))) {
        throw new Error(`Expected manageData.entries diagnostic, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('v2 verify rejects tampered signature profile metadata', async () => {
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
      if (!verify.errors.some((line) => line.includes('Unsupported signature profile'))) {
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
