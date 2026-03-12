import { HASH_SELECTION } from './constants.js';
import { derivePublicKeyFromSeed } from './ed25519.js';
import { buildHashEntriesFromDigests, buildInputDescriptor } from './message.js';
import {
  createSep53MessageSignatureDocument,
  serializeSignatureDocument,
  suggestSignatureFileName,
} from './signature-container.js';
import { encodeEd25519PublicKey } from './strkey.js';
import { readInputContextBytes, signSep53Message } from './sep53.js';

export async function createLocalSep53MessageSignature({
  inputContext,
  seedBytes,
  signerAddress,
}) {
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length !== 32) {
    throw new Error('Secret seed bytes are missing.');
  }

  const derivedPublic = await derivePublicKeyFromSeed(seedBytes);
  const derivedSigner = encodeEd25519PublicKey(derivedPublic);
  if (signerAddress && signerAddress !== derivedSigner) {
    throw new Error('Provided signer address does not match secret seed.');
  }

  const messageBytes = readInputContextBytes(inputContext);
  const hashEntries = buildHashEntriesFromDigests(inputContext.digests, HASH_SELECTION.BOTH);
  const signed = await signSep53Message({ seedBytes, messageBytes });

  const doc = createSep53MessageSignatureDocument({
    signer: derivedSigner,
    signatureB64: signed.signatureB64,
    input: buildInputDescriptor({
      type: inputContext.type,
      fileName: inputContext.fileName,
      fileSize: inputContext.fileSize,
    }),
    hashEntries,
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
