import { canonicalBase64ToBytes, bytesToBase64, concatBytes, utf8ToBytes, wipeBytes } from './bytes.js';
import { signBytesWithSeed, verifyBytesWithPublic } from './ed25519.js';
import { sha256 } from './hash.js';
import { SEP53_PREFIX } from './constants.js';

const SEP53_PREFIX_BYTES = utf8ToBytes(SEP53_PREFIX);

export async function computeSep53Hash(messageBytes) {
  if (!(messageBytes instanceof Uint8Array)) {
    throw new Error('SEP-53 message must be Uint8Array.');
  }
  const payload = concatBytes(SEP53_PREFIX_BYTES, messageBytes);
  try {
    return await sha256(payload);
  } finally {
    wipeBytes(payload);
  }
}

export async function signSep53Message({ seedBytes, signingKeySession, messageBytes }) {
  const payloadHash = await computeSep53Hash(messageBytes);
  try {
    const signature = signingKeySession
      ? await signingKeySession.sign(payloadHash)
      : await signBytesWithSeed(seedBytes, payloadHash);
    return {
      signature,
      signatureB64: bytesToBase64(signature),
    };
  } finally {
    wipeBytes(payloadHash);
  }
}

export async function verifySep53Message({ publicKeyBytes, messageBytes, signatureBytes }) {
  const payloadHash = await computeSep53Hash(messageBytes);
  try {
    return await verifyBytesWithPublic(publicKeyBytes, payloadHash, signatureBytes);
  } finally {
    wipeBytes(payloadHash);
  }
}

export function parseSep53Signature(signatureB64) {
  const signatureBytes = canonicalBase64ToBytes(String(signatureB64 || ''), { maxBytes: 64 });
  if (signatureBytes.length !== 64) {
    throw new Error(`Expected 64-byte signature, got ${signatureBytes.length}.`);
  }
  return signatureBytes;
}
