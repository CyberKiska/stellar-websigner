import { assertWellFormedUnicode } from './canonical-json.js';

const textEncoder = new TextEncoder();
const strictUtf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function utf8ToBytes(value) {
  const text = String(value);
  assertWellFormedUnicode(text);
  return textEncoder.encode(text);
}

// Signature documents must be exactly UTF-8 without a byte-order mark (RFC 8259 section 8.1, RFC 7493).
export function decodeUtf8Strict(bytes) {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new Error('Text must not start with a byte-order mark.');
  }
  try {
    return strictUtf8Decoder.decode(bytes);
  } catch {
    throw new Error('Text is not valid UTF-8.');
  }
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
      return new Uint8Array(Buffer.from(normalized, 'base64'));
    } catch {
      throw new Error('Invalid base64 value.');
    }
  }

  throw new Error('Base64 decoder is unavailable in this runtime.');
}

export function canonicalBase64ToBytes(base64Value, { maxBytes = Number.POSITIVE_INFINITY } = {}) {
  const value = String(base64Value || '');
  if (!value) throw new Error('Base64 value is empty.');
  if (value.length % 4 !== 0) throw new Error('Base64 value must use canonical padding.');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('Base64 value is not canonical RFC 4648 encoding.');
  }
  if (Math.floor((value.length * 3) / 4) > maxBytes + 2) {
    throw new Error(`Decoded base64 exceeds ${maxBytes} bytes.`);
  }
  const out = base64ToBytes(value);
  if (out.length > maxBytes) throw new Error(`Decoded base64 exceeds ${maxBytes} bytes.`);
  if (bytesToBase64(out) !== value) {
    throw new Error('Base64 value has non-canonical pad bits.');
  }
  return out;
}

export function base64UrlToBytes(value) {
  let normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  while (normalized.length % 4 !== 0) normalized += '=';
  return base64ToBytes(normalized);
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

export function safeJsonParse(text, { maxLength = 256 * 1024, maxDepth = 16 } = {}) {
  const source = String(text);
  if (source.length > maxLength) {
    throw new Error(`JSON document exceeds ${maxLength} characters.`);
  }
  try {
    scanJson(source, maxDepth);
    const parsed = JSON.parse(source);
    assertParsedJsonValue(parsed);
    return parsed;
  } catch (err) {
    if (err instanceof Error && /^(Duplicate JSON member|JSON document|JSON nesting|Text contains)/.test(err.message)) {
      throw err;
    }
    throw new Error('Malformed JSON.');
  }
}

function assertParsedJsonValue(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JSON document contains a non-finite number.');
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertParsedJsonValue(item);
    return;
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) assertParsedJsonValue(item);
    return;
  }
  throw new Error('Malformed JSON value.');
}

function scanJson(source, maxDepth) {
  let offset = 0;
  const whitespace = /\s/;

  function skipWhitespace() {
    while (offset < source.length && whitespace.test(source[offset])) offset += 1;
  }

  function parseValue(depth) {
    skipWhitespace();
    const token = source[offset];
    if (token === '{') return parseObject(depth + 1);
    if (token === '[') return parseArray(depth + 1);
    if (token === '"') return parseString();
    for (const literal of ['true', 'false', 'null']) {
      if (source.startsWith(literal, offset)) {
        offset += literal.length;
        return;
      }
    }
    const match = source.slice(offset).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (!match) throw new Error('Malformed JSON value.');
    offset += match[0].length;
  }

  function parseObject(depth) {
    if (depth > maxDepth) throw new Error(`JSON nesting exceeds ${maxDepth} levels.`);
    offset += 1;
    skipWhitespace();
    const names = new Set();
    if (source[offset] === '}') {
      offset += 1;
      return;
    }
    while (offset < source.length) {
      skipWhitespace();
      if (source[offset] !== '"') throw new Error('Malformed JSON object member.');
      const name = parseString();
      if (names.has(name)) throw new Error(`Duplicate JSON member: ${name}`);
      names.add(name);
      skipWhitespace();
      if (source[offset] !== ':') throw new Error('Malformed JSON object member.');
      offset += 1;
      parseValue(depth);
      skipWhitespace();
      if (source[offset] === '}') {
        offset += 1;
        return;
      }
      if (source[offset] !== ',') throw new Error('Malformed JSON object.');
      offset += 1;
    }
    throw new Error('Malformed JSON object.');
  }

  function parseArray(depth) {
    if (depth > maxDepth) throw new Error(`JSON nesting exceeds ${maxDepth} levels.`);
    offset += 1;
    skipWhitespace();
    if (source[offset] === ']') {
      offset += 1;
      return;
    }
    while (offset < source.length) {
      parseValue(depth);
      skipWhitespace();
      if (source[offset] === ']') {
        offset += 1;
        return;
      }
      if (source[offset] !== ',') throw new Error('Malformed JSON array.');
      offset += 1;
    }
    throw new Error('Malformed JSON array.');
  }

  function parseString() {
    const start = offset;
    offset += 1;
    while (offset < source.length) {
      const code = source.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        const value = JSON.parse(source.slice(start, offset));
        assertWellFormedUnicode(value);
        return value;
      }
      if (code < 0x20) throw new Error('Malformed JSON string.');
      if (code === 0x5c) {
        offset += 1;
        if (source[offset] === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(offset + 1, offset + 5))) {
            throw new Error('Malformed JSON Unicode escape.');
          }
          offset += 5;
          continue;
        }
        if (!'"\\/bfnrt'.includes(source[offset])) throw new Error('Malformed JSON escape.');
      }
      offset += 1;
    }
    throw new Error('Malformed JSON string.');
  }

  parseValue(0);
  skipWhitespace();
  if (offset !== source.length) throw new Error('Malformed JSON trailing data.');
}
