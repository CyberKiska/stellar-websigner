import { base64ToBytes, bytesToBase64, utf8ToBytes } from './bytes.js';
import { signBytesWithSeed, verifyBytesWithPublic } from './ed25519.js';
import { createSha256Stream } from './hash.js';
import { SEP53_PREFIX } from './constants.js';

const SEP53_PREFIX_BYTES = utf8ToBytes(SEP53_PREFIX);
const SEP53_HASH_CHUNK_BYTES = 4 * 1024 * 1024;

export async function computeSep53Hash(messageBytes) {
  if (!(messageBytes instanceof Uint8Array)) {
    throw new Error('SEP-53 message must be Uint8Array.');
  }
  const sha256 = createSha256Stream();
  sha256.update(SEP53_PREFIX_BYTES);
  for (let offset = 0; offset < messageBytes.length; offset += SEP53_HASH_CHUNK_BYTES) {
    sha256.update(messageBytes.subarray(offset, offset + SEP53_HASH_CHUNK_BYTES));
  }
  return sha256.finish();
}

export async function signSep53Message({ seedBytes, messageBytes }) {
  const payloadHash = await computeSep53Hash(messageBytes);
  const signature = await signBytesWithSeed(seedBytes, payloadHash);
  return {
    payloadHash,
    signature,
    signatureB64: bytesToBase64(signature),
  };
}

export async function verifySep53Message({ publicKeyBytes, messageBytes, signatureBytes }) {
  const payloadHash = await computeSep53Hash(messageBytes);
  return verifyBytesWithPublic(publicKeyBytes, payloadHash, signatureBytes);
}

export function readInputContextBytes(inputContext) {
  if (!(inputContext?.bytes instanceof Uint8Array)) {
    throw new Error('Strict SEP-53 mode requires input bytes in memory.');
  }
  return inputContext.bytes;
}

export function parseSep53Signature(signatureB64) {
  const signatureBytes = base64ToBytes(String(signatureB64 || ''));
  if (signatureBytes.length !== 64) {
    throw new Error(`Expected 64-byte signature, got ${signatureBytes.length}.`);
  }
  return signatureBytes;
}
