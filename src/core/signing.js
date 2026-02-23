import { HASH_SELECTION, MODE, SEP7_SOURCE_PLACEHOLDER } from './constants.js';
import { bytesEqual, bytesToBase64 } from './bytes.js';
import { derivePublicKeyFromSeed, signBytesWithSeed } from './ed25519.js';
import {
  buildDeterministicMessage,
  buildHashEntriesFromDigests,
  buildInputDescriptor,
  computeSep53MessageHash,
  digestForHashAlgorithm,
  hashSelectionToAlgorithms,
  normalizeHashSelection,
  normalizeHashAlgorithmName,
} from './message.js';
import { buildSep7Uri, networkHintFromPassphrase } from './sep7.js';
import {
  assertSafeManageDataEnvelope,
  buildUnsignedManageDataEnvelope,
  computeTransactionHash,
  findValidDecoratedSignature,
  parseTransactionEnvelope,
  txEnvelopeToBase64,
} from './xdr.js';
import {
  createLocalSignatureDocument,
  createSep7SignatureDocument,
  serializeSignatureDocument,
  suggestSignatureFileName,
} from './signature-container.js';
import { knownNetworkPassphrases } from './sep7.js';
import { decodeEd25519PublicKey, encodeEd25519PublicKey } from './strkey.js';

export async function createLocalDetachedSignature({
  inputContext,
  seedBytes,
  signerAddress,
  hashSelection = HASH_SELECTION.BOTH,
}) {
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length !== 32) {
    throw new Error('Secret seed bytes are missing.');
  }

  const derivedPublic = await derivePublicKeyFromSeed(seedBytes);
  const derivedSigner = encodeEd25519PublicKey(derivedPublic);
  if (signerAddress && signerAddress !== derivedSigner) {
    throw new Error('Provided signer address does not match secret seed.');
  }

  const normalizedSelection = normalizeHashSelection(hashSelection);
  const hashEntries = buildHashEntriesFromDigests(inputContext.digests, normalizedSelection);

  const message = buildDeterministicMessage({
    type: inputContext.type,
    fileName: inputContext.fileName,
    fileSize: inputContext.fileSize,
    hashEntries,
  });

  const payload = await computeSep53MessageHash(message);
  const signature = await signBytesWithSeed(seedBytes, payload);

  const doc = createLocalSignatureDocument({
    signer: derivedSigner,
    hashEntries,
    message,
    signatureB64: bytesToBase64(signature),
    input: buildInputDescriptor({
      type: inputContext.type,
      fileName: inputContext.fileName,
      fileSize: inputContext.fileSize,
    }),
  });

  return {
    signer: derivedSigner,
    doc,
    json: serializeSignatureDocument(doc),
    signatureB64: doc.signatureB64,
    filename: suggestSignatureFileName({ inputType: inputContext.type, originalName: inputContext.fileName }),
    message,
    hashSelection: normalizedSelection,
  };
}

export function createSep7Draft({
  inputContext,
  signerAddress,
  networkPassphrase,
  originDomain,
  hashSelection = HASH_SELECTION.BOTH,
}) {
  const normalizedSelection = normalizeHashSelection(hashSelection);
  const selectedAlgs = hashSelectionToAlgorithms(normalizedSelection);
  const boundHashes = selectedAlgs.map((alg) => {
    const digest = digestForHashAlgorithm(inputContext.digests, alg);
    return {
      alg,
      digestHex: digest.hex,
      manageDataName: digest.manageDataName,
      digestBytes: digest.bytes,
    };
  });

  const hashEntries = boundHashes.map((item) => ({
    alg: item.alg,
    hex: item.digestHex,
  }));

  const sourceAddress = signerAddress || SEP7_SOURCE_PLACEHOLDER;
  const sourcePublicKey = decodeEd25519PublicKey(sourceAddress);

  const unsignedEnvelope = buildUnsignedManageDataEnvelope({
    sourcePublicKey,
    sequence: 0n,
    fee: 8000 * boundHashes.length,
    manageDataEntries: boundHashes.map((item) => ({
      dataName: item.manageDataName,
      dataValue: item.digestBytes,
    })),
  });

  const unsignedXdrB64 = txEnvelopeToBase64(unsignedEnvelope.envelopeXdr);
  const msg = `Sign detached digest(s): ${boundHashes.map((item) => item.alg).join(', ')}`;
  const sep7Uri = buildSep7Uri({
    unsignedXdrB64,
    networkPassphrase,
    message: msg,
    signerAddress,
    originDomain,
  });

  return {
    unsignedXdrB64,
    sep7Uri,
    txXdr: unsignedEnvelope.txXdr,
    hashSelection: normalizedSelection,
    hashEntries,
    boundHashes: boundHashes.map((item) => ({
      alg: item.alg,
      digestHex: item.digestHex,
      manageDataName: item.manageDataName,
    })),
    manageDataNames: boundHashes.map((item) => item.manageDataName),
    networkPassphrase,
    signerAddress: signerAddress || '',
    placeholderMode: !signerAddress,
  };
}

export async function createSep7DetachedSignature({
  inputContext,
  signedXdr,
  networkPassphrase,
  expectedSigner,
  expectedManageDataEntries,
  hashSelection,
}) {
  if (!String(signedXdr || '').trim()) {
    throw new Error('Paste signedXDR first.');
  }

  const parsed = parseTransactionEnvelope(String(signedXdr).trim());
  const normalizedSelection = hashSelection
    ? normalizeHashSelection(hashSelection)
    : HASH_SELECTION.BOTH;
  const selectedAlgs = hashSelectionToAlgorithms(normalizedSelection);
  const recomputedBoundHashes = selectedAlgs.map((alg) => {
    const digest = digestForHashAlgorithm(inputContext.digests, alg);
    return {
      alg,
      digestHex: digest.hex,
      manageDataName: digest.manageDataName,
      digestBytes: digest.bytes,
    };
  });

  const safeData = assertSafeManageDataEnvelope(parsed, {
    expectedEntries: Array.isArray(expectedManageDataEntries)
      ? expectedManageDataEntries.map((item) => {
          const alg = normalizeHashAlgorithmName(item.alg);
          const digest = digestForHashAlgorithm(inputContext.digests, alg);
          return {
            dataName: String(item.manageDataName || digest.manageDataName),
            dataValue: digest.bytes,
          };
        })
      : undefined,
  });

  if (safeData.manageDataEntries.length !== recomputedBoundHashes.length) {
    throw new Error('signedXDR ManageData operation count does not match selected hash set.');
  }

  for (const boundHash of recomputedBoundHashes) {
    const actual = safeData.manageDataEntries.find((item) => item.dataName === boundHash.manageDataName);
    if (!actual) {
      throw new Error(`signedXDR missing ManageData entry ${boundHash.manageDataName}.`);
    }
    if (!bytesEqual(actual.dataValue, boundHash.digestBytes)) {
      throw new Error(`ManageData value mismatch for ${boundHash.manageDataName}.`);
    }
  }

  for (const entry of safeData.manageDataEntries) {
    if (!recomputedBoundHashes.find((item) => item.manageDataName === entry.dataName)) {
      throw new Error(`Unexpected ManageData entry ${entry.dataName} in signedXDR.`);
    }
  }

  const hashEntries = buildHashEntriesFromDigests(inputContext.digests, normalizedSelection);

  const txSourceAddress = encodeEd25519PublicKey(safeData.sourceAccount);
  const normalizedExpectedSigner = String(expectedSigner || '').trim();
  const sourceIsPlaceholder = txSourceAddress === SEP7_SOURCE_PLACEHOLDER;
  const signer = normalizedExpectedSigner || (sourceIsPlaceholder ? '' : txSourceAddress);

  if (!signer) {
    throw new Error(
      'Cannot determine signer from signedXDR: sourceAccount is placeholder. Load signer G... in Keys before creating .sig.'
    );
  }

  const passphrase = String(networkPassphrase || '').trim();
  if (!passphrase) {
    throw new Error('Network passphrase is required.');
  }

  const signerPublic = decodeEd25519PublicKey(signer);
  const txHash = await computeTransactionHash(parsed.txXdr, passphrase);
  const match = await findValidDecoratedSignature(parsed.signatures, signerPublic, txHash);
  if (!match) {
    for (const alternative of knownNetworkPassphrases()) {
      if (alternative === passphrase) continue;
      const altHash = await computeTransactionHash(parsed.txXdr, alternative);
      const altMatch = await findValidDecoratedSignature(parsed.signatures, signerPublic, altHash);
      if (altMatch) {
        throw new Error(`No valid signer signature for selected network passphrase. Signature is valid on "${alternative}".`);
      }
    }

    if (signer === SEP7_SOURCE_PLACEHOLDER) {
      throw new Error(
        'signedXDR still uses placeholder sourceAccount. Use wallet URI flow with replace=sourceAccount or load signer G... in Keys before generating XDR.'
      );
    }

    if (!Array.isArray(parsed.signatures) || parsed.signatures.length === 0) {
      throw new Error('signedXDR has no signatures.');
    }

    throw new Error('No valid signer signature found in signedXDR.');
  }

  const doc = createSep7SignatureDocument({
    signer,
    networkPassphrase: passphrase,
    networkHint: networkHintFromPassphrase(passphrase),
    hashEntries,
    manageDataEntries: recomputedBoundHashes.map((item) => ({
      name: item.manageDataName,
      alg: item.alg,
      digestHex: item.digestHex,
    })),
    txSourceAccount: txSourceAddress,
    signedXdr: String(signedXdr).trim(),
    input: buildInputDescriptor({
      type: inputContext.type,
      fileName: inputContext.fileName,
      fileSize: inputContext.fileSize,
    }),
  });

  return {
    signer,
    doc,
    json: serializeSignatureDocument(doc),
    signatureB64: bytesToBase64(match.signature),
    filename: suggestSignatureFileName({ inputType: inputContext.type, originalName: inputContext.fileName }),
    hashSelection: normalizedSelection,
  };
}

export function isSep53Mode(modeValue) {
  return String(modeValue || '').trim() === MODE.SEP53;
}
