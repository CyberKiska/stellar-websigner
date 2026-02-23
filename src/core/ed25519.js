import { base64UrlToBytes, concatBytes } from './bytes.js';

const ED25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420');
const ED25519_SPKI_PREFIX = hexToBytes('302a300506032b6570032100');

export function randomSeed32() {
  const cryptoApi = getCrypto();
  const seed = new Uint8Array(32);
  cryptoApi.getRandomValues(seed);
  return seed;
}

export async function derivePublicKeyFromSeed(seedBytes) {
  assertSeed(seedBytes);
  const privateKey = await importPrivateKeyFromSeed(seedBytes);
  const jwk = await getSubtle().exportKey('jwk', privateKey);
  if (!jwk || typeof jwk.x !== 'string') {
    throw new Error('Cannot derive public key from seed.');
  }
  return base64UrlToBytes(jwk.x);
}

export async function signBytesWithSeed(seedBytes, messageBytes) {
  assertSeed(seedBytes);
  if (!(messageBytes instanceof Uint8Array)) {
    throw new Error('Message must be Uint8Array.');
  }
  const privateKey = await importPrivateKeyFromSeed(seedBytes);
  const signature = await getSubtle().sign('Ed25519', privateKey, messageBytes);
  return new Uint8Array(signature);
}

export async function verifyBytesWithPublic(publicBytes, messageBytes, signatureBytes) {
  assertPublic(publicBytes);
  if (!(messageBytes instanceof Uint8Array)) {
    throw new Error('Message must be Uint8Array.');
  }
  if (!(signatureBytes instanceof Uint8Array) || signatureBytes.length !== 64) {
    throw new Error('Signature must be 64 bytes.');
  }

  const publicKey = await importPublicKey(publicBytes);
  return getSubtle().verify('Ed25519', publicKey, signatureBytes, messageBytes);
}

export async function generateKeypair() {
  const seedBytes = randomSeed32();
  const publicBytes = await derivePublicKeyFromSeed(seedBytes);
  return { seedBytes, publicBytes };
}

export function signatureHint(publicBytes) {
  assertPublic(publicBytes);
  return publicBytes.slice(28, 32);
}

async function importPrivateKeyFromSeed(seedBytes) {
  const pkcs8 = concatBytes(ED25519_PKCS8_PREFIX, seedBytes);
  // Extractable is required because derivePublicKeyFromSeed exports JWK `x`.
  return getSubtle().importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
}

async function importPublicKey(publicBytes) {
  try {
    return await getSubtle().importKey('raw', publicBytes, { name: 'Ed25519' }, false, ['verify']);
  } catch {
    const spki = concatBytes(ED25519_SPKI_PREFIX, publicBytes);
    return getSubtle().importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
  }
}

function getCrypto() {
  if (!globalThis.crypto) {
    throw new Error('WebCrypto is unavailable.');
  }
  return globalThis.crypto;
}

function getSubtle() {
  const cryptoApi = getCrypto();
  if (!cryptoApi.subtle) {
    throw new Error('WebCrypto subtle API is unavailable.');
  }
  return cryptoApi.subtle;
}

function assertSeed(seedBytes) {
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length !== 32) {
    throw new Error('Secret seed must be 32 bytes.');
  }
}

function assertPublic(publicBytes) {
  if (!(publicBytes instanceof Uint8Array) || publicBytes.length !== 32) {
    throw new Error('Public key must be 32 bytes.');
  }
}

function hexToBytes(hex) {
  const value = String(hex).trim().toLowerCase();
  if (value.length % 2 !== 0) {
    throw new Error('hex must have even length.');
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < value.length; i += 2) {
    out[i / 2] = Number.parseInt(value.slice(i, i + 2), 16);
  }
  return out;
}
