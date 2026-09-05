import { base64UrlToBytes, bytesEqual, concatBytes, wipeBytes } from './bytes.js';
import {
  assertStrictEd25519PublicKey,
  assertStrictEd25519Signature,
} from './ed25519-validation.js';

const ED25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420');
const ED25519_SPKI_PREFIX = hexToBytes('302a300506032b6570032100');
const KEY_PAIR_CHECK_MESSAGE = new Uint8Array([
  0x73, 0x74, 0x65, 0x6c, 0x6c, 0x61, 0x72, 0x2d, 0x77, 0x65, 0x62, 0x73, 0x69, 0x67, 0x6e, 0x65,
  0x72, 0x3a, 0x6b, 0x65, 0x79, 0x2d, 0x70, 0x61, 0x69, 0x72, 0x2d, 0x63, 0x68, 0x65, 0x63, 0x6b,
  0x3a, 0x76, 0x31,
]);

export async function derivePublicKeyFromSeed(seedBytes, options = {}) {
  assertSeed(seedBytes);
  const ownedSeed = new Uint8Array(seedBytes);
  const subtle = options.subtle || getSubtle();
  try {
    return await derivePublicKeyWithProvider(ownedSeed, subtle);
  } finally {
    wipeBytes(ownedSeed);
  }
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

export async function generateKeypair(options = {}) {
  const subtle = options.subtle || getSubtle();
  const pair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
  try {
    if (pkcs8.length !== ED25519_PKCS8_PREFIX.length + 32) {
      throw new Error('Unexpected generated Ed25519 PKCS#8 encoding.');
    }
    if (!bytesEqual(pkcs8.subarray(0, ED25519_PKCS8_PREFIX.length), ED25519_PKCS8_PREFIX)) {
      throw new Error('Unexpected generated Ed25519 PKCS#8 prefix.');
    }
    const publicBytes = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
    assertStrictEd25519PublicKey(publicBytes);
    // Create the returned secret copy only after all fallible provider checks.
    const seedBytes = pkcs8.slice(ED25519_PKCS8_PREFIX.length);
    return { seedBytes, publicBytes };
  } finally {
    wipeBytes(pkcs8);
  }
}

export async function createSigningKeySession(seedBytes, options = {}) {
  assertSeed(seedBytes);
  const ownedSeed = new Uint8Array(seedBytes);
  const subtle = options.subtle || getSubtle();
  try {
    const privateKey = await importSigningPrivateKeyFromSeed(ownedSeed, subtle);
    const publicBytes =
      options.publicBytes === undefined
        ? await derivePublicKeyWithProvider(ownedSeed, subtle, privateKey)
        : copyAndValidatePublicKey(options.publicBytes);
    if (options.publicBytes !== undefined) {
      await assertPrivateKeyMatchesPublicKey(privateKey, publicBytes, subtle);
    }
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
        const signature = await signWithPrivateKey(capturedKey, messageBytes, subtle);
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
  return new Uint8Array(publicBytes.subarray(28, 32));
}

async function importSigningPrivateKeyFromSeed(seedBytes, subtle = getSubtle()) {
  return importPrivateKeyFromSeed(seedBytes, false, subtle);
}

async function importPrivateKeyFromSeed(seedBytes, extractable, subtle) {
  const pkcs8 = concatBytes(ED25519_PKCS8_PREFIX, seedBytes);
  try {
    return await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, extractable, ['sign']);
  } finally {
    wipeBytes(pkcs8);
  }
}

async function signWithPrivateKey(privateKey, messageBytes, subtle = getSubtle()) {
  const signature = new Uint8Array(await subtle.sign('Ed25519', privateKey, messageBytes));
  assertStrictEd25519Signature(signature);
  return signature;
}

async function importPublicKey(publicBytes, subtle = getSubtle()) {
  assertStrictEd25519PublicKey(publicBytes);
  try {
    return await subtle.importKey('raw', publicBytes, { name: 'Ed25519' }, false, ['verify']);
  } catch {
    const spki = concatBytes(ED25519_SPKI_PREFIX, publicBytes);
    try {
      return await subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
    } finally {
      wipeBytes(spki);
    }
  }
}

async function derivePublicKeyWithProvider(seedBytes, subtle, privateKey = null) {
  if (typeof subtle.getPublicKey === 'function') {
    const ownedPrivateKey = privateKey || (await importPrivateKeyFromSeed(seedBytes, false, subtle));
    try {
      const publicKey = await subtle.getPublicKey(ownedPrivateKey, ['verify']);
      const publicBytes = new Uint8Array(await subtle.exportKey('raw', publicKey));
      assertStrictEd25519PublicKey(publicBytes);
      return publicBytes;
    } catch (err) {
      if (!isNotSupportedError(err)) throw err;
    }
  }
  return derivePublicKeyViaJwk(seedBytes, subtle);
}

async function derivePublicKeyViaJwk(seedBytes, subtle) {
  const privateKey = await importPrivateKeyFromSeed(seedBytes, true, subtle);
  let jwk = null;
  let privateBytes = null;
  try {
    jwk = await subtle.exportKey('jwk', privateKey);
    if (jwk?.kty !== 'OKP' || jwk?.crv !== 'Ed25519') {
      throw new Error('Unexpected Ed25519 private JWK metadata.');
    }
    privateBytes = decodeEd25519JwkMember(jwk.d, 'private key');
    if (!bytesEqual(privateBytes, seedBytes)) {
      throw new Error('Exported Ed25519 private JWK does not match the imported seed.');
    }
    const publicBytes = decodeEd25519JwkMember(jwk.x, 'public key');
    try {
      assertStrictEd25519PublicKey(publicBytes);
      return publicBytes;
    } catch (err) {
      wipeBytes(publicBytes);
      throw err;
    }
  } finally {
    wipeBytes(privateBytes);
    if (jwk) {
      jwk.d = '';
      jwk.x = '';
    }
    jwk = null;
  }
}

function decodeEd25519JwkMember(value, label) {
  const encoded = String(value || '');
  if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) {
    throw new Error(`Ed25519 JWK ${label} is not canonical 32-byte base64url.`);
  }
  const bytes = base64UrlToBytes(encoded);
  if (bytes.length !== 32) {
    wipeBytes(bytes);
    throw new Error(`Ed25519 JWK ${label} must be 32 bytes.`);
  }
  return bytes;
}

function copyAndValidatePublicKey(publicBytes) {
  assertPublic(publicBytes);
  const copy = new Uint8Array(publicBytes);
  assertStrictEd25519PublicKey(copy);
  return copy;
}

async function assertPrivateKeyMatchesPublicKey(privateKey, publicBytes, subtle) {
  const signature = await signWithPrivateKey(privateKey, KEY_PAIR_CHECK_MESSAGE, subtle);
  try {
    const publicKey = await importPublicKey(publicBytes, subtle);
    const valid = await subtle.verify('Ed25519', publicKey, signature, KEY_PAIR_CHECK_MESSAGE);
    if (!valid) throw new Error('Provided Ed25519 public key does not match the private seed.');
  } finally {
    wipeBytes(signature);
  }
}

function isNotSupportedError(err) {
  return err?.name === 'NotSupportedError';
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
