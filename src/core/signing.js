import { PROOF_TYPE } from './constants.js';
import { derivePublicKeyFromSeed } from './ed25519.js';
import { buildProtectedManifest, protectedManifestBytes } from './protected-manifest.js';
import {
  createSep53MessageSignatureDocument,
  serializeSignatureDocument,
  suggestSignatureFileName,
} from './signature-container.js';
import { encodeEd25519PublicKey } from './strkey.js';
import { signSep53Message, verifySep53Message } from './sep53.js';

export async function createLocalSep53MessageSignature({
  inputContext,
  seedBytes,
  signingKeySession = null,
  signerAddress,
}) {
  if (!signingKeySession && (!(seedBytes instanceof Uint8Array) || seedBytes.length !== 32)) {
    throw new Error('Secret seed bytes are missing.');
  }

  const derivedPublic = signingKeySession
    ? signingKeySession.publicBytes
    : await derivePublicKeyFromSeed(seedBytes);
  const derivedSigner = encodeEd25519PublicKey(derivedPublic);
  if (signerAddress && signerAddress !== derivedSigner) {
    throw new Error('Provided signer address does not match secret seed.');
  }

  const protectedManifest = buildProtectedManifest({
    inputContext,
    signer: derivedSigner,
    proofType: PROOF_TYPE.SEP53_MESSAGE,
  });
  const messageBytes = protectedManifestBytes(protectedManifest);
  const signed = await signSep53Message({ seedBytes, signingKeySession, messageBytes });
  const selfVerified = await verifySep53Message({
    publicKeyBytes: derivedPublic,
    messageBytes,
    signatureBytes: signed.signature,
  });
  if (!selfVerified) throw new Error('Newly created signature failed self-verification.');

  const doc = createSep53MessageSignatureDocument({
    signer: derivedSigner,
    signatureB64: signed.signatureB64,
    protectedManifest,
  });

  return {
    signer: derivedSigner,
    doc,
    json: serializeSignatureDocument(doc),
    displayJson: serializeSignatureDocument(doc, { pretty: true }),
    signatureB64: doc.signatureB64,
    filename: suggestSignatureFileName({ inputType: inputContext.type, originalName: inputContext.fileName }),
  };
}
