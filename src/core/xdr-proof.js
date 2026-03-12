import { HASH_SELECTION } from './constants.js';
import { bytesEqual, bytesToBase64 } from './bytes.js';
import {
  buildHashEntriesFromDigests,
  buildInputDescriptor,
  digestForHashAlgorithm,
  hashSelectionToAlgorithms,
  normalizeHashAlgorithmName,
  normalizeHashSelection,
} from './message.js';
import { knownNetworkPassphrases, networkHintFromPassphrase } from './network.js';
import {
  assertSafeManageDataEnvelope,
  buildUnsignedManageDataEnvelope,
  computeTransactionHash,
  findValidDecoratedSignature,
  parseTransactionEnvelope,
  txEnvelopeToBase64,
} from './xdr.js';
import {
  createXdrProofSignatureDocument,
  serializeSignatureDocument,
  suggestSignatureFileName,
} from './signature-container.js';
import { decodeEd25519PublicKey, encodeEd25519PublicKey } from './strkey.js';

export function createXdrProofDraft({
  inputContext,
  signerAddress,
  networkPassphrase,
  hashSelection = HASH_SELECTION.BOTH,
}) {
  const signer = String(signerAddress || '').trim();
  if (!signer) {
    throw new Error('Load signer G... in Keys before generating unsigned XDR.');
  }

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

  const sourcePublicKey = decodeEd25519PublicKey(signer);
  const unsignedEnvelope = buildUnsignedManageDataEnvelope({
    sourcePublicKey,
    sequence: 0n,
    fee: 8000 * boundHashes.length,
    manageDataEntries: boundHashes.map((item) => ({
      dataName: item.manageDataName,
      dataValue: item.digestBytes,
    })),
  });

  return {
    unsignedXdr: txEnvelopeToBase64(unsignedEnvelope.envelopeXdr),
    txXdr: unsignedEnvelope.txXdr,
    hashSelection: normalizedSelection,
    hashEntries,
    boundHashes: boundHashes.map((item) => ({
      alg: item.alg,
      digestHex: item.digestHex,
      manageDataName: item.manageDataName,
    })),
    networkPassphrase: String(networkPassphrase || '').trim(),
    signerAddress: signer,
  };
}

export async function finalizeXdrProof({
  inputContext,
  signedXdr,
  networkPassphrase,
  expectedSigner,
  expectedManageDataEntries,
  hashSelection,
}) {
  const signer = String(expectedSigner || '').trim();
  if (!signer) {
    throw new Error('Load signer G... in Keys before creating XDR proof.');
  }
  if (!String(signedXdr || '').trim()) {
    throw new Error('Paste signed XDR first.');
  }

  const parsed = parseTransactionEnvelope(String(signedXdr).trim());
  const normalizedSelection = hashSelection ? normalizeHashSelection(hashSelection) : HASH_SELECTION.BOTH;
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

  const txSourceAddress = encodeEd25519PublicKey(safeData.sourceAccount);
  if (txSourceAddress !== signer) {
    throw new Error(`signedXDR sourceAccount mismatch: expected ${signer}, got ${txSourceAddress}.`);
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

    if (!Array.isArray(parsed.signatures) || parsed.signatures.length === 0) {
      throw new Error('signedXDR has no signatures.');
    }

    throw new Error('No valid signer signature found in signedXDR.');
  }

  const hashEntries = buildHashEntriesFromDigests(inputContext.digests, normalizedSelection);
  const doc = createXdrProofSignatureDocument({
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
    displayJson: serializeSignatureDocument(doc, { pretty: true }),
    signatureB64: bytesToBase64(match.signature),
    filename: suggestSignatureFileName({ inputType: inputContext.type, originalName: inputContext.fileName }),
    hashSelection: normalizedSelection,
  };
}
