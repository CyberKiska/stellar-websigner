import { bytesEqual } from './bytes.js';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STRKEY_VERSION_BYTE_ED25519_PUBLIC_KEY = 6 << 3;
const STRKEY_VERSION_BYTE_ED25519_SECRET_SEED = 18 << 3;
const STRKEY_BODY_REGEX = /^[A-Z2-7]+$/;

export function decodeEd25519PublicKey(address) {
  return decodeStrKey(address, STRKEY_VERSION_BYTE_ED25519_PUBLIC_KEY, 32, 'G');
}

export function decodeEd25519SecretSeed(seed) {
  return decodeStrKey(seed, STRKEY_VERSION_BYTE_ED25519_SECRET_SEED, 32, 'S');
}

export function encodeEd25519PublicKey(publicBytes) {
  return encodeStrKey(publicBytes, STRKEY_VERSION_BYTE_ED25519_PUBLIC_KEY);
}

export function encodeEd25519SecretSeed(seedBytes) {
  return encodeStrKey(seedBytes, STRKEY_VERSION_BYTE_ED25519_SECRET_SEED);
}

export function isValidPublicAddress(address) {
  try {
    decodeEd25519PublicKey(address);
    return true;
  } catch {
    return false;
  }
}

export function isValidSecretSeed(seed) {
  try {
    decodeEd25519SecretSeed(seed);
    return true;
  } catch {
    return false;
  }
}

function decodeStrKey(strKey, expectedVersionByte, expectedPayloadLength, expectedPrefix) {
  validateStrKeyShape(strKey, expectedPrefix);
  const bytes = base32Decode(strKey);
  if (bytes.length < 3) {
    throw new Error('StrKey is too short.');
  }

  const payload = bytes.slice(0, -2);
  const checksum = bytes.slice(-2);
  const expectedChecksum = crc16XModem(payload);
  const actualChecksum = checksum[0] | (checksum[1] << 8);
  if (expectedChecksum !== actualChecksum) {
    throw new Error('Invalid StrKey checksum.');
  }

  const versionByte = payload[0];
  if (versionByte !== expectedVersionByte) {
    throw new Error('Unexpected StrKey version byte.');
  }

  const data = payload.slice(1);
  if (data.length !== expectedPayloadLength) {
    throw new Error(`Unexpected StrKey payload length: ${data.length}`);
  }

  return data;
}

function validateStrKeyShape(value, expectedPrefix) {
  const kind = expectedPrefix === 'G' ? 'Public address' : 'Secret seed';
  const str = String(value || '').trim();

  if (str.length !== 56) {
    throw new Error(`${kind} must be exactly 56 characters long.`);
  }

  if (str[0] !== expectedPrefix) {
    throw new Error(`${kind} must start with "${expectedPrefix}".`);
  }

  if (!STRKEY_BODY_REGEX.test(str)) {
    throw new Error(`${kind} must use base32 charset [A-Z2-7].`);
  }
}

function encodeStrKey(payload, versionByte) {
  if (!(payload instanceof Uint8Array)) {
    throw new Error('StrKey payload must be Uint8Array.');
  }
  const body = new Uint8Array(payload.length + 1);
  body[0] = versionByte;
  body.set(payload, 1);

  const checksum = crc16XModem(body);
  const out = new Uint8Array(body.length + 2);
  out.set(body, 0);
  out[body.length] = checksum & 0xff;
  out[body.length + 1] = (checksum >>> 8) & 0xff;
  return base32Encode(out);
}

function crc16XModem(bytes) {
  let crc = 0x0000;
  for (let i = 0; i < bytes.length; i += 1) {
    crc ^= bytes[i] << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      if ((crc & 0x8000) !== 0) {
        crc = ((crc << 1) ^ 0x1021) & 0xffff;
      } else {
        crc = (crc << 1) & 0xffff;
      }
    }
  }
  return crc;
}

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';

  for (let i = 0; i < bytes.length; i += 1) {
    value = (value << 8) | bytes[i];
    bits += 8;

    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return out;
}

function base32Decode(input) {
  const clean = String(input || '').trim().replace(/=+$/g, '');
  if (!clean) {
    throw new Error('StrKey is empty.');
  }

  let bits = 0;
  let value = 0;
  const out = [];

  for (let i = 0; i < clean.length; i += 1) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx < 0) {
      throw new Error(`Invalid base32 symbol: ${clean[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Uint8Array.from(out);
}

export function sameAddressBytes(a, b) {
  return bytesEqual(a, b);
}
