const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8ToBytes(value) {
  return textEncoder.encode(String(value));
}

export function bytesToUtf8(bytes) {
  return textDecoder.decode(bytes);
}

export function bytesToHexLower(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytes(hex) {
  const value = String(hex).trim().toLowerCase();
  if (value.length % 2 !== 0) {
    throw new Error('Hex string must have even length.');
  }
  if (!/^[0-9a-f]*$/.test(value)) {
    throw new Error('Hex string has invalid characters.');
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < value.length; i += 2) {
    out[i / 2] = Number.parseInt(value.slice(i, i + 2), 16);
  }
  return out;
}

export function sanitizeBase64(input) {
  return String(input || '').replace(/\s+/g, '');
}

export function bytesToBase64(bytes) {
  if (typeof btoa === 'function') {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }

  throw new Error('Base64 encoder is unavailable in this runtime.');
}

export function base64ToBytes(base64Value) {
  const rawValue = sanitizeBase64(base64Value).replace(/-/g, '+').replace(/_/g, '/');
  if (!rawValue) {
    throw new Error('Base64 value is empty.');
  }

  if (!/^[A-Za-z0-9+/=]+$/.test(rawValue)) {
    throw new Error('Invalid base64 value.');
  }

  const firstPadding = rawValue.indexOf('=');
  if (firstPadding !== -1) {
    const padding = rawValue.slice(firstPadding);
    if (!/^=+$/.test(padding) || padding.length > 2) {
      throw new Error('Invalid base64 value.');
    }
  }

  const withoutPadding = rawValue.replace(/=+$/g, '');
  const remainder = withoutPadding.length % 4;
  if (remainder === 1) {
    throw new Error('Invalid base64 value.');
  }
  const normalized = withoutPadding + '='.repeat((4 - remainder) % 4);

  if (typeof atob === 'function') {
    let binary;
    try {
      binary = atob(normalized);
    } catch {
      throw new Error('Invalid base64 value.');
    }
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }

  if (typeof Buffer !== 'undefined') {
    try {
      const buf = Buffer.from(normalized, 'base64');
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } catch {
      throw new Error('Invalid base64 value.');
    }
  }

  throw new Error('Base64 decoder is unavailable in this runtime.');
}

export function base64UrlToBytes(value) {
  let normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  while (normalized.length % 4 !== 0) normalized += '=';
  return base64ToBytes(normalized);
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function concatBytes(...parts) {
  const total = parts.reduce((acc, part) => acc + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) return false;
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= left[i] ^ right[i];
  }
  return diff === 0;
}

export function wipeBytes(value) {
  if (value instanceof Uint8Array) {
    value.fill(0);
  }
}

export function shortHex(value, prefix = 10, suffix = 10) {
  const hex = typeof value === 'string' ? value.toLowerCase() : bytesToHexLower(value);
  if (hex.length <= prefix + suffix) return hex;
  return `${hex.slice(0, prefix)}...${hex.slice(hex.length - suffix)}`;
}

export function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('Malformed JSON.');
  }
}
