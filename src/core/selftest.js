import { bytesToBase64, hexToBytes, utf8ToBytes } from './bytes.js';
import { derivePublicKeyFromSeed, generateKeypair, signatureHint, signBytesWithSeed } from './ed25519.js';
import { computeDigests } from './hash.js';
import { HASH_ALG, HASH_SELECTION, TESTNET_NETWORK_PASSPHRASE } from './constants.js';
import { createLocalDetachedSignature, createSep7DetachedSignature, createSep7Draft } from './signing.js';
import { encodeEd25519PublicKey, decodeEd25519PublicKey, decodeEd25519SecretSeed, encodeEd25519SecretSeed } from './strkey.js';
import { verifyDetachedSignature } from './verify.js';
import { computeTransactionHash, encodeSignedTxEnvelope } from './xdr.js';

function createResult(name, fn) {
  return { name, fn };
}

async function makeFileContext(name, bytes) {
  const digests = await computeDigests(bytes);
  return {
    type: 'file',
    fileName: name,
    fileSize: bytes.length,
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

    createResult('sep53 sign/verify text (both hashes)', async () => {
      const seed = hexToBytes('1111111111111111111111111111111111111111111111111111111111111111');
      const textContext = await makeTextContext('offline ed25519 test text');
      const signResult = await createLocalDetachedSignature({
        inputContext: textContext,
        seedBytes: seed,
        signerAddress: '',
        hashSelection: HASH_SELECTION.BOTH,
      });
      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: textContext,
      });
      if (!verify.valid) {
        throw new Error(`Expected VALID, got ${verify.summary}`);
      }
    }),

    createResult('sep53 sign/verify file (single hash)', async () => {
      const seed = hexToBytes('2222222222222222222222222222222222222222222222222222222222222222');
      const fileContext = await makeFileContext('doc.txt', utf8ToBytes('FIPS202 + RFC8032 deterministic test'));

      const signResult = await createLocalDetachedSignature({
        inputContext: fileContext,
        seedBytes: seed,
        signerAddress: '',
        hashSelection: HASH_SELECTION.SHA3_512,
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: fileContext,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID, got ${verify.summary}`);
      }
    }),

    createResult('sep53 verify stays valid when file name changes', async () => {
      const seed = hexToBytes('2323232323232323232323232323232323232323232323232323232323232323');
      const bytes = utf8ToBytes('same content different file name');
      const signContext = await makeFileContext('original-name.bin', bytes);
      const verifyContext = await makeFileContext('renamed-copy.bin', bytes);

      const signResult = await createLocalDetachedSignature({
        inputContext: signContext,
        seedBytes: seed,
        signerAddress: '',
        hashSelection: HASH_SELECTION.BOTH,
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: verifyContext,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID for renamed file, got ${verify.summary}`);
      }
    }),

    createResult('sep53 verify fails with wrong signer', async () => {
      const seedA = hexToBytes('6666666666666666666666666666666666666666666666666666666666666666');
      const seedB = hexToBytes('7777777777777777777777777777777777777777777777777777777777777777');
      const textContext = await makeTextContext('wrong signer test text');

      const signResult = await createLocalDetachedSignature({
        inputContext: textContext,
        seedBytes: seedA,
        signerAddress: '',
        hashSelection: HASH_SELECTION.BOTH,
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

    createResult('sep53 verify fails with wrong text input', async () => {
      const seed = hexToBytes('8888888888888888888888888888888888888888888888888888888888888888');
      const goodTextContext = await makeTextContext('original text payload');
      const badTextContext = await makeTextContext('tampered text payload');

      const signResult = await createLocalDetachedSignature({
        inputContext: goodTextContext,
        seedBytes: seed,
        signerAddress: '',
        hashSelection: HASH_SELECTION.BOTH,
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: badTextContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID for wrong text input.');
      }
      if (!verify.errors.some((line) => line.includes('Digest mismatch'))) {
        throw new Error(`Expected digest mismatch diagnostic for text, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('sep53 verify fails with wrong file input', async () => {
      const seed = hexToBytes('9999999999999999999999999999999999999999999999999999999999999999');
      const goodFileContext = await makeFileContext('doc.txt', utf8ToBytes('original file bytes'));
      const badFileContext = await makeFileContext('doc.txt', utf8ToBytes('modified file bytes'));

      const signResult = await createLocalDetachedSignature({
        inputContext: goodFileContext,
        seedBytes: seed,
        signerAddress: '',
        hashSelection: HASH_SELECTION.BOTH,
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: signResult.doc,
        inputContext: badFileContext,
      });

      if (verify.valid) {
        throw new Error('Expected INVALID for wrong file input.');
      }
      if (!verify.errors.some((line) => line.includes('Digest mismatch'))) {
        throw new Error(`Expected digest mismatch diagnostic for file, got: ${verify.errors.join(' | ')}`);
      }
    }),

    createResult('sep7 tx sign/verify', async () => {
      const seed = hexToBytes('3333333333333333333333333333333333333333333333333333333333333333');
      const fileContext = await makeFileContext('image.bin', utf8ToBytes('binary-like-content'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = createSep7Draft({
        inputContext: fileContext,
        signerAddress: signer,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        originDomain: 'localhost',
        hashSelection: HASH_SELECTION.BOTH,
      });

      const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
      const signature = await signBytesWithSeed(seed, txHash);
      const hint = signatureHint(decodeEd25519PublicKey(signer));

      const signedEnvelope = encodeSignedTxEnvelope({
        txXdr: draft.txXdr,
        signatures: [{ hint, signature }],
      });

      const signedXdr = bytesToBase64(signedEnvelope);
      const sep7Doc = await createSep7DetachedSignature({
        inputContext: fileContext,
        signedXdr,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        expectedSigner: signer,
        expectedManageDataEntries: draft.boundHashes,
        hashSelection: draft.hashSelection,
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: sep7Doc.doc,
        inputContext: fileContext,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID, got ${verify.summary}`);
      }
    }),

    createResult('sep7 placeholder source + explicit signer', async () => {
      const seed = hexToBytes('5555555555555555555555555555555555555555555555555555555555555555');
      const fileContext = await makeFileContext('blob.dat', utf8ToBytes('placeholder source account flow'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = createSep7Draft({
        inputContext: fileContext,
        signerAddress: '',
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        originDomain: 'localhost',
        hashSelection: HASH_SELECTION.BOTH,
      });

      const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
      const signature = await signBytesWithSeed(seed, txHash);
      const hint = signatureHint(signerPublic);

      const signedEnvelope = encodeSignedTxEnvelope({
        txXdr: draft.txXdr,
        signatures: [{ hint, signature }],
      });

      const signedXdr = bytesToBase64(signedEnvelope);
      const sep7Doc = await createSep7DetachedSignature({
        inputContext: fileContext,
        signedXdr,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        expectedSigner: signer,
        expectedManageDataEntries: draft.boundHashes,
        hashSelection: draft.hashSelection,
      });

      const verify = await verifyDetachedSignature({
        signatureDoc: sep7Doc.doc,
        inputContext: fileContext,
      });

      if (!verify.valid) {
        throw new Error(`Expected VALID, got ${verify.summary}`);
      }

      const warnLine = verify.warnings.find((line) => line.includes('sourceAccount') && line.includes('differs'));
      if (!warnLine) {
        throw new Error('Expected sourceAccount/signer mismatch warning.');
      }
    }),

    createResult('sep7 wrong network passphrase detection', async () => {
      const seed = hexToBytes('4444444444444444444444444444444444444444444444444444444444444444');
      const fileContext = await makeFileContext('a.bin', utf8ToBytes('wallet mode network mismatch test'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = createSep7Draft({
        inputContext: fileContext,
        signerAddress: signer,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        originDomain: 'localhost',
        hashSelection: HASH_SELECTION.BOTH,
      });

      const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
      const signature = await signBytesWithSeed(seed, txHash);
      const hint = signatureHint(signerPublic);

      const signedEnvelope = encodeSignedTxEnvelope({
        txXdr: draft.txXdr,
        signatures: [{ hint, signature }],
      });

      const signedXdr = bytesToBase64(signedEnvelope);
      const sep7Doc = await createSep7DetachedSignature({
        inputContext: fileContext,
        signedXdr,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        expectedSigner: signer,
        expectedManageDataEntries: draft.boundHashes,
        hashSelection: draft.hashSelection,
      });

      const badDoc = {
        ...sep7Doc.doc,
        network: {
          ...sep7Doc.doc.network,
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

    createResult('sep7 verify rejects incomplete hash coverage', async () => {
      const seed = hexToBytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      const textContext = await makeTextContext('incomplete coverage regression');

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = createSep7Draft({
        inputContext: textContext,
        signerAddress: signer,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        originDomain: 'localhost',
        hashSelection: HASH_SELECTION.SHA256,
      });

      const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
      const signature = await signBytesWithSeed(seed, txHash);
      const hint = signatureHint(signerPublic);
      const signedEnvelope = encodeSignedTxEnvelope({
        txXdr: draft.txXdr,
        signatures: [{ hint, signature }],
      });
      const signedXdr = bytesToBase64(signedEnvelope);

      const sep7Doc = await createSep7DetachedSignature({
        inputContext: textContext,
        signedXdr,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        expectedSigner: signer,
        expectedManageDataEntries: draft.boundHashes,
        hashSelection: draft.hashSelection,
      });

      const tamperedDoc = {
        ...sep7Doc.doc,
        hashes: [
          ...sep7Doc.doc.hashes,
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

    createResult('sep7 verify requires manageData.entries', async () => {
      const seed = hexToBytes('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
      const fileContext = await makeFileContext('strict.json', utf8ToBytes('strict manageData section'));

      const signerPublic = await derivePublicKeyFromSeed(seed);
      const signer = encodeEd25519PublicKey(signerPublic);

      const draft = createSep7Draft({
        inputContext: fileContext,
        signerAddress: signer,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        originDomain: 'localhost',
        hashSelection: HASH_SELECTION.BOTH,
      });

      const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
      const signature = await signBytesWithSeed(seed, txHash);
      const hint = signatureHint(signerPublic);
      const signedEnvelope = encodeSignedTxEnvelope({
        txXdr: draft.txXdr,
        signatures: [{ hint, signature }],
      });
      const signedXdr = bytesToBase64(signedEnvelope);

      const sep7Doc = await createSep7DetachedSignature({
        inputContext: fileContext,
        signedXdr,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        expectedSigner: signer,
        expectedManageDataEntries: draft.boundHashes,
        hashSelection: draft.hashSelection,
      });

      const badDoc = {
        ...sep7Doc.doc,
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
