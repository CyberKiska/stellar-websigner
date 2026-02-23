import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { bytesToHexLower, hexToBytes, utf8ToBytes, bytesToBase64 } from '../src/core/bytes.js';
import { createLocalDetachedSignature, createSep7Draft, createSep7DetachedSignature } from '../src/core/signing.js';
import { computeDigests } from '../src/core/hash.js';
import { HASH_SELECTION, TESTNET_NETWORK_PASSPHRASE } from '../src/core/constants.js';
import { derivePublicKeyFromSeed, signBytesWithSeed, signatureHint } from '../src/core/ed25519.js';
import { encodeEd25519PublicKey } from '../src/core/strkey.js';
import { computeTransactionHash, encodeSignedTxEnvelope } from '../src/core/xdr.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

async function makeTextContext(text) {
  const bytes = utf8ToBytes(text);
  return {
    type: 'text',
    fileName: '',
    fileSize: bytes.length,
    bytes,
    digests: await computeDigests(bytes),
  };
}

async function makeFileContext(name, bytes) {
  return {
    type: 'file',
    fileName: name,
    fileSize: bytes.length,
    bytes,
    digests: await computeDigests(bytes),
  };
}

async function buildVectors() {
  const seedBothHex = '1111111111111111111111111111111111111111111111111111111111111111';
  const seedSingleHex = '2222222222222222222222222222222222222222222222222222222222222222';
  const seedSep7Hex = '3333333333333333333333333333333333333333333333333333333333333333';
  const seedSep7PlaceholderHex = '5555555555555555555555555555555555555555555555555555555555555555';

  const seedBoth = hexToBytes(seedBothHex);
  const seedSingle = hexToBytes(seedSingleHex);
  const seedSep7 = hexToBytes(seedSep7Hex);
  const seedSep7Placeholder = hexToBytes(seedSep7PlaceholderHex);

  const textInput = 'offline ed25519 test text';
  const bothContext = await makeTextContext(textInput);
  const bothResult = await createLocalDetachedSignature({
    inputContext: bothContext,
    seedBytes: seedBoth,
    signerAddress: '',
    hashSelection: HASH_SELECTION.BOTH,
  });

  const fileBytes = utf8ToBytes('FIPS202 + RFC8032 deterministic test');
  const singleContext = await makeFileContext('doc.txt', fileBytes);
  const singleResult = await createLocalDetachedSignature({
    inputContext: singleContext,
    seedBytes: seedSingle,
    signerAddress: '',
    hashSelection: HASH_SELECTION.SHA3_512,
  });

  const walletBytes = utf8ToBytes('binary-like-content');
  const walletContext = await makeFileContext('image.bin', walletBytes);
  const walletPublic = await derivePublicKeyFromSeed(seedSep7);
  const walletSigner = encodeEd25519PublicKey(walletPublic);

  const draft = createSep7Draft({
    inputContext: walletContext,
    signerAddress: walletSigner,
    networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
    originDomain: 'localhost',
    hashSelection: HASH_SELECTION.BOTH,
  });

  const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
  const txSignature = await signBytesWithSeed(seedSep7, txHash);
  const txHint = signatureHint(walletPublic);
  const signedEnvelope = encodeSignedTxEnvelope({
    txXdr: draft.txXdr,
    signatures: [{ hint: txHint, signature: txSignature }],
  });
  const signedXdr = bytesToBase64(signedEnvelope);

  const sep7Result = await createSep7DetachedSignature({
    inputContext: walletContext,
    signedXdr,
    networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
    expectedSigner: walletSigner,
    expectedManageDataEntries: draft.boundHashes,
    hashSelection: draft.hashSelection,
  });

  const placeholderContext = await makeFileContext('placeholder.bin', utf8ToBytes('placeholder source account flow'));
  const placeholderPublic = await derivePublicKeyFromSeed(seedSep7Placeholder);
  const placeholderSigner = encodeEd25519PublicKey(placeholderPublic);

  const placeholderDraft = createSep7Draft({
    inputContext: placeholderContext,
    signerAddress: '',
    networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
    originDomain: 'localhost',
    hashSelection: HASH_SELECTION.BOTH,
  });

  const placeholderTxHash = await computeTransactionHash(placeholderDraft.txXdr, TESTNET_NETWORK_PASSPHRASE);
  const placeholderSignature = await signBytesWithSeed(seedSep7Placeholder, placeholderTxHash);
  const placeholderHint = signatureHint(placeholderPublic);
  const placeholderSignedEnvelope = encodeSignedTxEnvelope({
    txXdr: placeholderDraft.txXdr,
    signatures: [{ hint: placeholderHint, signature: placeholderSignature }],
  });
  const placeholderSignedXdr = bytesToBase64(placeholderSignedEnvelope);
  const placeholderSep7Result = await createSep7DetachedSignature({
    inputContext: placeholderContext,
    signedXdr: placeholderSignedXdr,
    networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
    expectedSigner: placeholderSigner,
    expectedManageDataEntries: placeholderDraft.boundHashes,
    hashSelection: placeholderDraft.hashSelection,
  });

  return {
    vectors: [
      {
        id: 'sep53-text-both-hashes-v1',
        seedHex: seedBothHex,
        signer: bothResult.signer,
        input: {
          type: 'text',
          text: textInput,
        },
        digests: {
          sha256Hex: bothContext.digests.sha256.hex,
          sha3_512Hex: bothContext.digests.sha3_512.hex,
        },
        message: bothResult.doc.message,
        signatureB64: bothResult.doc.signatureB64,
        doc: { ...bothResult.doc },
      },
      {
        id: 'sep53-file-sha3-v1',
        seedHex: seedSingleHex,
        signer: singleResult.signer,
        input: {
          type: 'file',
          fileName: singleContext.fileName,
          fileSize: singleContext.fileSize,
          fileContentUtf8: 'FIPS202 + RFC8032 deterministic test',
        },
        digests: {
          sha256Hex: singleContext.digests.sha256.hex,
          sha3_512Hex: singleContext.digests.sha3_512.hex,
        },
        message: singleResult.doc.message,
        signatureB64: singleResult.doc.signatureB64,
        doc: { ...singleResult.doc },
      },
      {
        id: 'sep7-manage-data-file-both-v1',
        seedHex: seedSep7Hex,
        signer: walletSigner,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        input: {
          type: 'file',
          fileName: walletContext.fileName,
          fileSize: walletContext.fileSize,
          fileContentUtf8: 'binary-like-content',
        },
        digests: {
          sha256Hex: walletContext.digests.sha256.hex,
          sha3_512Hex: walletContext.digests.sha3_512.hex,
        },
        manageData: {
          entries: draft.boundHashes.map((item) => ({
            name: item.manageDataName,
            alg: item.alg,
            valueHex: item.digestHex,
          })),
        },
        unsignedXdr: draft.unsignedXdrB64,
        txHashHex: bytesToHexLower(txHash),
        txSignatureB64: bytesToBase64(txSignature),
        signedXdr,
        doc: { ...sep7Result.doc },
      },
      {
        id: 'sep7-placeholder-source-explicit-signer-v1',
        seedHex: seedSep7PlaceholderHex,
        signer: placeholderSigner,
        networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
        input: {
          type: 'file',
          fileName: placeholderContext.fileName,
          fileSize: placeholderContext.fileSize,
          fileContentUtf8: 'placeholder source account flow',
        },
        digests: {
          sha256Hex: placeholderContext.digests.sha256.hex,
          sha3_512Hex: placeholderContext.digests.sha3_512.hex,
        },
        manageData: {
          entries: placeholderDraft.boundHashes.map((item) => ({
            name: item.manageDataName,
            alg: item.alg,
            valueHex: item.digestHex,
          })),
        },
        unsignedXdr: placeholderDraft.unsignedXdrB64,
        txHashHex: bytesToHexLower(placeholderTxHash),
        txSignatureB64: bytesToBase64(placeholderSignature),
        signedXdr: placeholderSignedXdr,
        doc: { ...placeholderSep7Result.doc },
      },
    ],
  };
}

async function main() {
  const data = await buildVectors();
  const out = `${JSON.stringify(data, null, 2)}\n`;
  await writeFile(path.join(root, 'test-vectors.json'), out, 'utf8');
  console.log('Generated test-vectors.json');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
