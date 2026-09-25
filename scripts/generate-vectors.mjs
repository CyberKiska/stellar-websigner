import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { base64ToBytes, bytesToHexLower, hexToBytes, utf8ToBytes, bytesToBase64 } from '../src/core/bytes.js';
import { createLocalSep53MessageSignature } from '../src/core/signing.js';
import { signSep53Message } from '../src/core/sep53.js';
import { SEP53_CANONICAL_TEST_VECTORS } from '../src/core/sep53-test-vectors.js';
import { createXdrProofDraft, finalizeXdrProof } from '../src/core/xdr-proof.js';
import { computeDigests } from '../src/core/hash.js';
import { TESTNET_NETWORK_PASSPHRASE } from '../src/core/constants.js';
import { derivePublicKeyFromSeed, signBytesWithSeed, signatureHint } from '../src/core/ed25519.js';
import { decodeEd25519SecretSeed, encodeEd25519PublicKey } from '../src/core/strkey.js';
import { computeTransactionHash, encodeSignedTxEnvelope } from '../src/core/xdr.js';
import { verifyDetachedSignature } from '../src/core/verify.js';

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

async function makeCanonicalSep53Context(vector) {
  if (vector.type === 'text') return makeTextContext(vector.message);
  if (vector.type === 'binary') return makeFileContext('sep53-canonical-binary.bin', base64ToBytes(vector.messageB64));
  throw new Error(`Unsupported SEP-53 vector type: ${vector.type}`);
}

async function buildCanonicalSep53Vector(vector) {
  const inputContext = await makeCanonicalSep53Context(vector);
  const signResult = await signSep53Message({
    messageBytes: inputContext.bytes,
    seedBytes: decodeEd25519SecretSeed(vector.seed),
  });
  const signatureHex = bytesToHexLower(signResult.signature);
  const expectedHexFromB64 = bytesToHexLower(base64ToBytes(vector.signatureB64));

  if (signResult.signatureB64 !== vector.signatureB64 || signatureHex !== vector.signatureHex) {
    throw new Error(`${vector.id}: generated signature does not match canonical SEP-53 vector.`);
  }
  if (expectedHexFromB64 !== vector.signatureHex) {
    throw new Error(`${vector.id}: canonical base64/hex signature values disagree.`);
  }

  return {
    id: vector.id,
    standard: 'SEP-0053',
    seed: vector.seed,
    signer: vector.address,
    input:
      vector.type === 'text'
        ? {
            type: 'text',
            text: vector.message,
          }
        : {
            type: 'binary',
            messageB64: vector.messageB64,
            size: inputContext.fileSize,
          },
    digests: {
      sha256Hex: inputContext.digests.sha256.hex,
      sha3_512Hex: inputContext.digests.sha3_512.hex,
    },
    signatureB64: signResult.signatureB64,
    signatureHex,
    expected: {
      signatureB64: vector.signatureB64,
      signatureHex: vector.signatureHex,
    },
    note: 'Independent raw-message SEP-53 vector; v3 containers sign protected-manifest bytes.',
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
  const canonicalSep53Vectors = await Promise.all(SEP53_CANONICAL_TEST_VECTORS.map(buildCanonicalSep53Vector));

  const textInput = 'offline ed25519 test text';
  const bothContext = await makeTextContext(textInput);
  const bothResult = await createLocalSep53MessageSignature({
    inputContext: bothContext,
    seedBytes: seedBoth,
    signerAddress: '',
  });

  const fileBytes = utf8ToBytes('FIPS202 + RFC8032 deterministic test');
  const singleContext = await makeFileContext('doc.txt', fileBytes);
  const singleResult = await createLocalSep53MessageSignature({
    inputContext: singleContext,
    seedBytes: seedSingle,
    signerAddress: '',
  });

  const walletBytes = utf8ToBytes('binary-like-content');
  const walletContext = await makeFileContext('image.bin', walletBytes);
  const walletPublic = await derivePublicKeyFromSeed(seedSep7);
  const walletSigner = encodeEd25519PublicKey(walletPublic);

  const draft = await createXdrProofDraft({
    inputContext: walletContext,
    signerAddress: walletSigner,
    networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
  });

  const txHash = await computeTransactionHash(draft.txXdr, TESTNET_NETWORK_PASSPHRASE);
  const txSignature = await signBytesWithSeed(seedSep7, txHash);
  const txHint = signatureHint(walletPublic);
  const signedEnvelope = encodeSignedTxEnvelope({
    txXdr: draft.txXdr,
    signatures: [{ hint: txHint, signature: txSignature }],
  });
  const signedXdr = bytesToBase64(signedEnvelope);

  const xdrResult = await finalizeXdrProof({
    inputContext: walletContext,
    signedXdr,
    draft,
    expectedSigner: walletSigner,
  });

  const placeholderContext = await makeFileContext('placeholder.bin', utf8ToBytes('placeholder source account flow'));
  const placeholderPublic = await derivePublicKeyFromSeed(seedSep7Placeholder);
  const placeholderSigner = encodeEd25519PublicKey(placeholderPublic);

  const placeholderDraft = await createXdrProofDraft({
    inputContext: placeholderContext,
    signerAddress: placeholderSigner,
    networkPassphrase: TESTNET_NETWORK_PASSPHRASE,
  });

  const placeholderTxHash = await computeTransactionHash(placeholderDraft.txXdr, TESTNET_NETWORK_PASSPHRASE);
  const placeholderSignature = await signBytesWithSeed(seedSep7Placeholder, placeholderTxHash);
  const placeholderHint = signatureHint(placeholderPublic);
  const placeholderSignedEnvelope = encodeSignedTxEnvelope({
    txXdr: placeholderDraft.txXdr,
    signatures: [{ hint: placeholderHint, signature: placeholderSignature }],
  });
  const placeholderSignedXdr = bytesToBase64(placeholderSignedEnvelope);
  const placeholderXdrResult = await finalizeXdrProof({
    inputContext: placeholderContext,
    signedXdr: placeholderSignedXdr,
    draft: placeholderDraft,
    expectedSigner: placeholderSigner,
  });

  return {
    vectors: [
      ...canonicalSep53Vectors,
      {
        id: 'sep53-protected-manifest-text-v3',
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
        signatureB64: bothResult.doc.signatureB64,
        doc: { ...bothResult.doc },
      },
      {
        id: 'sep53-protected-manifest-file-v3',
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
        signatureB64: singleResult.doc.signatureB64,
        doc: { ...singleResult.doc },
      },
      {
        id: 'xdr-protected-manifest-file-v3',
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
          name: draft.dataName,
          valueHex: bytesToHexLower(draft.manifestDigest),
        },
        unsignedXdr: draft.unsignedXdr,
        txHashHex: bytesToHexLower(txHash),
        txSignatureB64: bytesToBase64(txSignature),
        signedXdr,
        doc: { ...xdrResult.doc },
      },
      {
        id: 'xdr-protected-manifest-explicit-signer-v3',
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
          name: placeholderDraft.dataName,
          valueHex: bytesToHexLower(placeholderDraft.manifestDigest),
        },
        unsignedXdr: placeholderDraft.unsignedXdr,
        txHashHex: bytesToHexLower(placeholderTxHash),
        txSignatureB64: bytesToBase64(placeholderSignature),
        signedXdr: placeholderSignedXdr,
        doc: { ...placeholderXdrResult.doc },
      },
    ],
  };
}

async function assertVectorsVerify(data) {
  for (const vector of data.vectors) {
    if (!vector.doc) continue;
    const content = vector.input.type === 'text' ? vector.input.text : vector.input.fileContentUtf8;
    const inputContext =
      vector.input.type === 'text' ? await makeTextContext(content) : await makeFileContext(vector.input.fileName, utf8ToBytes(content));
    const report = await verifyDetachedSignature({ signatureDoc: vector.doc, inputContext, expectedSigner: vector.signer });
    if (report.summary !== 'VALID') throw new Error(`${vector.id}: generated vector does not verify (${report.summary}).`);
  }
}

async function main() {
  const data = await buildVectors();
  await assertVectorsVerify(data);
  const out = `${JSON.stringify(data, null, 2)}\n`;
  await writeFile(path.join(root, 'test-vectors.json'), out, 'utf8');
  console.log('Generated test-vectors.json');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
