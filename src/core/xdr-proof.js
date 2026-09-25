import { MANIFEST_DATA_NAME, PROOF_TYPE } from './constants.js';
import { bytesEqual, bytesToBase64, bytesToHexLower } from './bytes.js';
import { assertStrictEd25519PublicKey } from './ed25519-validation.js';
import { knownNetworkPassphrases } from './network.js';
import {
  buildProtectedManifest,
  protectedManifestBytes,
  protectedManifestSha256,
} from './protected-manifest.js';
import {
  assertManifestProofEnvelope,
  buildUnsignedManifestEnvelope,
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

export async function createXdrProofDraft({ inputContext, signerAddress, networkPassphrase }) {
  const signer = String(signerAddress || '').trim();
  if (!signer) throw new Error('Load signer G... in Keys before generating unsigned XDR.');
  const sourcePublicKey = decodeEd25519PublicKey(signer);
  assertStrictEd25519PublicKey(sourcePublicKey);

  const protectedManifest = buildProtectedManifest({
    inputContext,
    signer,
    proofType: PROOF_TYPE.XDR_ENVELOPE,
    networkPassphrase,
  });
  const manifestBytes = protectedManifestBytes(protectedManifest);
  const manifestDigest = await protectedManifestSha256(protectedManifest);
  const unsignedEnvelope = buildUnsignedManifestEnvelope({ sourcePublicKey, manifestDigest });

  return Object.freeze({
    operationId: `sha256:${bytesToHexLower(manifestDigest)}`,
    unsignedXdr: txEnvelopeToBase64(unsignedEnvelope.envelopeXdr),
    dataName: MANIFEST_DATA_NAME,
    txXdr: unsignedEnvelope.txXdr,
    manifestBytes,
    manifestDigest,
    protectedManifest,
    boundHashes: protectedManifest.hashes,
    networkPassphrase: protectedManifest.network.passphrase,
    signerAddress: signer,
  });
}

export async function finalizeXdrProof({ inputContext, signedXdr, draft, expectedSigner = '' }) {
  if (!draft || typeof draft !== 'object') {
    throw new Error('The original unsigned XDR draft is required for finalization.');
  }
  const signer = String(expectedSigner || draft.signerAddress || '').trim();
  if (!signer || signer !== draft.signerAddress) {
    throw new Error('Active signer does not match the original XDR draft.');
  }
  if (!String(signedXdr || '').trim()) throw new Error('Paste signed XDR first.');

  const currentManifest = buildProtectedManifest({
    inputContext,
    signer,
    proofType: PROOF_TYPE.XDR_ENVELOPE,
    networkPassphrase: draft.networkPassphrase,
  });
  const currentManifestBytes = protectedManifestBytes(currentManifest);
  if (!bytesEqual(currentManifestBytes, draft.manifestBytes)) {
    throw new Error('Selected input or protected metadata changed after the unsigned XDR was generated.');
  }
  const currentManifestDigest = await protectedManifestSha256(currentManifest);
  if (!bytesEqual(currentManifestDigest, draft.manifestDigest)) {
    throw new Error('Protected manifest digest changed after the unsigned XDR was generated.');
  }

  const parsed = parseTransactionEnvelope(String(signedXdr).trim());
  if (!bytesEqual(parsed.txXdr, draft.txXdr)) {
    throw new Error('Signed XDR transaction differs from the exact unsigned draft.');
  }
  const safeData = assertManifestProofEnvelope(parsed, currentManifestDigest);

  const txSourceAddress = encodeEd25519PublicKey(safeData.sourceAccount);
  if (txSourceAddress !== signer) {
    throw new Error(`signedXDR sourceAccount mismatch: expected ${signer}, got ${txSourceAddress}.`);
  }
  const passphrase = draft.networkPassphrase;
  const signerPublic = decodeEd25519PublicKey(signer);
  const txHash = await computeTransactionHash(parsed.txXdr, passphrase);
  let match;
  try {
    match = await findValidDecoratedSignature(parsed.signatures, signerPublic, txHash);
  } catch (err) {
    throw new Error(`Invalid signedXDR signature set: ${err.message}`);
  }
  if (!match) {
    for (const alternative of knownNetworkPassphrases()) {
      if (alternative === passphrase) continue;
      const altHash = await computeTransactionHash(parsed.txXdr, alternative);
      if (await findValidDecoratedSignature(parsed.signatures, signerPublic, altHash)) {
        throw new Error(`Signature is valid on the wrong network: "${alternative}".`);
      }
    }
    throw new Error('No valid signer signature found in signedXDR.');
  }

  const canonicalSignedXdr = bytesToBase64(parsed.envelopeXdr);
  const doc = createXdrProofSignatureDocument({
    signer,
    signedXdr: canonicalSignedXdr,
    protectedManifest: currentManifest,
  });
  return {
    signer,
    doc,
    json: serializeSignatureDocument(doc),
    displayJson: serializeSignatureDocument(doc, { pretty: true }),
    signatureB64: bytesToBase64(match.signature),
    filename: suggestSignatureFileName({ inputType: inputContext.type, originalName: inputContext.fileName }),
    operationId: draft.operationId,
  };
}
