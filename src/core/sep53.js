import { base64ToBytes, bytesToBase64, concatBytes, utf8ToBytes } from './bytes.js';
import { signBytesWithSeed, verifyBytesWithPublic } from './ed25519.js';
import { sha256 } from './hash.js';
import { SEP53_PREFIX } from './constants.js';

const SEP53_PREFIX_BYTES = utf8ToBytes(SEP53_PREFIX);

export async function computeSep53Hash(messageBytes) {
  if (!(messageBytes instanceof Uint8Array)) {
    throw new Error('SEP-53 message must be Uint8Array.');
  }
  return sha256(concatBytes(SEP53_PREFIX_BYTES, messageBytes));
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
  if (!(inputContext?.bytes instanceof Uint8Array) || inputContext.bytes.length === 0) {
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
