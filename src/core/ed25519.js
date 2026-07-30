import { bytesEqual, concatBytes, wipeBytes } from './bytes.js';
import {
  assertStrictEd25519PublicKey,
  assertStrictEd25519Signature,
  deriveEd25519PublicKey,
} from './ed25519-validation.js';

const ED25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420');
const ED25519_SPKI_PREFIX = hexToBytes('302a300506032b6570032100');

export async function derivePublicKeyFromSeed(seedBytes) {
  assertSeed(seedBytes);
  return deriveEd25519PublicKey(seedBytes);
}

export async function signBytesWithSeed(seedBytes, messageBytes) {
  assertSeed(seedBytes);
  if (!(messageBytes instanceof Uint8Array)) {
    throw new Error('Message must be Uint8Array.');
  }
  const privateKey = await importSigningPrivateKeyFromSeed(seedBytes);
  return signWithPrivateKey(privateKey, messageBytes);
}

export async function verifyBytesWithPublic(publicBytes, messageBytes, signatureBytes) {
  assertPublic(publicBytes);
  if (!(messageBytes instanceof Uint8Array)) {
    throw new Error('Message must be Uint8Array.');
  }
  if (!(signatureBytes instanceof Uint8Array) || signatureBytes.length !== 64) {
    throw new Error('Signature must be 64 bytes.');
  }

  try {
    assertStrictEd25519PublicKey(publicBytes);
    assertStrictEd25519Signature(signatureBytes);
  } catch {
    return false;
  }

  const publicKey = await importPublicKey(publicBytes);
  return getSubtle().verify('Ed25519', publicKey, signatureBytes, messageBytes);
}

export async function generateKeypair() {
  const pair = await getSubtle().generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await getSubtle().exportKey('pkcs8', pair.privateKey));
  try {
    if (pkcs8.length !== ED25519_PKCS8_PREFIX.length + 32) {
      throw new Error('Unexpected generated Ed25519 PKCS#8 encoding.');
    }
    if (!bytesEqual(pkcs8.subarray(0, ED25519_PKCS8_PREFIX.length), ED25519_PKCS8_PREFIX)) {
      throw new Error('Unexpected generated Ed25519 PKCS#8 prefix.');
    }
    const seedBytes = pkcs8.slice(ED25519_PKCS8_PREFIX.length);
    const publicBytes = new Uint8Array(await getSubtle().exportKey('raw', pair.publicKey));
    assertStrictEd25519PublicKey(publicBytes);
    return { seedBytes, publicBytes };
  } finally {
    wipeBytes(pkcs8);
  }
}

export async function createSigningKeySession(seedBytes) {
  assertSeed(seedBytes);
  const ownedSeed = seedBytes.slice();
  try {
    const [privateKey, publicBytes] = await Promise.all([
      importSigningPrivateKeyFromSeed(ownedSeed),
      derivePublicKeyFromSeed(ownedSeed),
    ]);
    let active = true;
    let key = privateKey;
    const publicCopy = publicBytes.slice();
    return Object.freeze({
      get publicBytes() {
        return publicCopy.slice();
      },
      get active() {
        return active;
      },
      async sign(messageBytes) {
        if (!active || !key) throw new Error('Signing key session is no longer active.');
        const capturedKey = key;
        const signature = await signWithPrivateKey(capturedKey, messageBytes);
        if (!active || key !== capturedKey) {
          wipeBytes(signature);
          throw new Error('Signing key session changed during signing.');
        }
        return signature;
      },
      destroy() {
        active = false;
        key = null;
      },
    });
  } finally {
    wipeBytes(ownedSeed);
  }
}

export function signatureHint(publicBytes) {
  assertPublic(publicBytes);
  return publicBytes.slice(28, 32);
}

async function importSigningPrivateKeyFromSeed(seedBytes) {
  const pkcs8 = concatBytes(ED25519_PKCS8_PREFIX, seedBytes);
  try {
    return await getSubtle().importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  } finally {
    wipeBytes(pkcs8);
  }
}

async function signWithPrivateKey(privateKey, messageBytes) {
  const signature = new Uint8Array(await getSubtle().sign('Ed25519', privateKey, messageBytes));
  assertStrictEd25519Signature(signature);
  return signature;
}

async function importPublicKey(publicBytes) {
  assertStrictEd25519PublicKey(publicBytes);
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
