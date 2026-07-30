import { wipeBytes } from './bytes.js';

// RFC 8032, section 5.1.  BigInt is used only for public point validation and
// public-key derivation; secret signing remains in Web Crypto.
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const D = mod(-121665n * invert(121666n));
const SQRT_M1 = powMod(2n, (P - 1n) / 4n);
const IDENTITY = Object.freeze({ x: 0n, y: 1n, z: 1n, t: 0n });
const BASE_POINT = decodePoint(basePointEncoding(), { allowIdentity: false, requireSubgroup: false });

export function assertStrictEd25519PublicKey(publicBytes) {
  assertLength(publicBytes, 32, 'Public key');
  decodePoint(publicBytes, { allowIdentity: false, requireSubgroup: true });
}

export function assertStrictEd25519Signature(signatureBytes) {
  assertLength(signatureBytes, 64, 'Signature');
  decodePoint(signatureBytes.subarray(0, 32), { allowIdentity: false, requireSubgroup: true });
  const scalar = littleEndianToBigInt(signatureBytes.subarray(32));
  if (scalar >= L) {
    throw new Error('Ed25519 signature scalar S is not canonical.');
  }
}

export async function deriveEd25519PublicKey(seedBytes) {
  assertLength(seedBytes, 32, 'Secret seed');
  const digest = new Uint8Array(await subtle().digest('SHA-512', seedBytes));
  try {
    digest[0] &= 248;
    digest[31] &= 63;
    digest[31] |= 64;
    const scalar = littleEndianToBigInt(digest.subarray(0, 32));
    return encodePoint(scalarMultiply(BASE_POINT, scalar));
  } finally {
    wipeBytes(digest);
  }
}

function decodePoint(encoded, { allowIdentity, requireSubgroup }) {
  assertLength(encoded, 32, 'Encoded Ed25519 point');
  const copy = encoded.slice();
  const sign = copy[31] >>> 7;
  copy[31] &= 0x7f;
  const y = littleEndianToBigInt(copy);
  wipeBytes(copy);
  if (y >= P) throw new Error('Ed25519 point encoding is non-canonical.');

  const y2 = mod(y * y);
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  let x = mod(u * powMod(v, 3n) * powMod(mod(u * powMod(v, 7n)), (P - 5n) / 8n));
  if (mod(v * x * x - u) !== 0n) x = mod(x * SQRT_M1);
  if (mod(v * x * x - u) !== 0n) throw new Error('Ed25519 point is not on the curve.');
  if (Number(x & 1n) !== sign) x = mod(-x);
  if (x === 0n && sign !== 0) throw new Error('Ed25519 point has a non-canonical sign bit.');

  const point = { x, y, z: 1n, t: mod(x * y) };
  if (!allowIdentity && isIdentity(point)) {
    throw new Error('Ed25519 identity point is not allowed.');
  }
  if (requireSubgroup && !isIdentity(scalarMultiply(point, L))) {
    throw new Error('Ed25519 point is not in the prime-order subgroup.');
  }
  return point;
}

function encodePoint(point) {
  const zInv = invert(point.z);
  const x = mod(point.x * zInv);
  const y = mod(point.y * zInv);
  const out = bigIntToLittleEndian(y, 32);
  out[31] |= Number(x & 1n) << 7;
  return out;
}

function addPoints(a, b) {
  const aa = mod((a.y - a.x) * (b.y - b.x));
  const bb = mod((a.y + a.x) * (b.y + b.x));
  const cc = mod(2n * D * a.t * b.t);
  const dd = mod(2n * a.z * b.z);
  const e = mod(bb - aa);
  const f = mod(dd - cc);
  const g = mod(dd + cc);
  const h = mod(bb + aa);
  return {
    x: mod(e * f),
    y: mod(g * h),
    z: mod(f * g),
    t: mod(e * h),
  };
}

function scalarMultiply(point, scalar) {
  let n = scalar;
  let result = IDENTITY;
  let addend = point;
  while (n > 0n) {
    if (n & 1n) result = addPoints(result, addend);
    addend = addPoints(addend, addend);
    n >>= 1n;
  }
  return result;
}

function isIdentity(point) {
  return mod(point.x) === 0n && mod(point.y - point.z) === 0n;
}

function invert(value) {
  const normalized = mod(value);
  if (normalized === 0n) throw new Error('Cannot invert zero in Ed25519 field.');
  return powMod(normalized, P - 2n);
}

function powMod(base, exponent) {
  let result = 1n;
  let factor = mod(base);
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = mod(result * factor);
    factor = mod(factor * factor);
    power >>= 1n;
  }
  return result;
}

function mod(value) {
  const result = value % P;
  return result >= 0n ? result : result + P;
}

function littleEndianToBigInt(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

function bigIntToLittleEndian(value, length) {
  const out = new Uint8Array(length);
  let remaining = value;
  for (let i = 0; i < length; i += 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function basePointEncoding() {
  return bigIntToLittleEndian(mod(4n * invert(5n)), 32);
}

function assertLength(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${label} must be ${length} bytes.`);
  }
}

function subtle() {
  if (!globalThis.crypto?.subtle) throw new Error('WebCrypto subtle API is unavailable.');
  return globalThis.crypto.subtle;
}
