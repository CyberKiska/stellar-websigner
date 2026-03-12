import { bytesToBase64, hexToBytes, utf8ToBytes } from './bytes.js';
import { derivePublicKeyFromSeed, generateKeypair, signatureHint, signBytesWithSeed } from './ed25519.js';
import { computeDigests } from './hash.js';
import { HASH_ALG, SIGNATURE_SCHEMA_V2, SIGNATURE_SCHEME, TESTNET_NETWORK_PASSPHRASE } from './constants.js';
import { createLocalSep53MessageSignature } from './signing.js';
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

export async function runSelfTest() {
  const results = [];

  const tests = [
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
