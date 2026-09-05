export function canonicalJsonStringify(value) {
  return serialize(value, new Set());
}

function serialize(value, ancestors) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') {
    assertIJsonUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Canonical JSON does not allow non-finite numbers.');
    return JSON.stringify(value);
  }
  if (!value || typeof value !== 'object') {
    throw new Error(`Canonical JSON cannot serialize ${typeof value}.`);
  }
  if (ancestors.has(value)) throw new Error('Canonical JSON cannot serialize cyclic data.');

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const items = [];
      for (let i = 0; i < value.length; i += 1) {
        if (!Object.hasOwn(value, i)) throw new Error('Canonical JSON does not allow sparse arrays.');
        items.push(serialize(value[i], ancestors));
      }
      return `[${items.join(',')}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error('Canonical JSON requires plain objects.');
    }
    const members = [];
    for (const key of Object.keys(value).sort()) {
      assertIJsonUnicode(key);
      members.push(`${JSON.stringify(key)}:${serialize(value[key], ancestors)}`);
    }
    return `{${members.join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function assertWellFormedUnicode(value) {
  const text = String(value);
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error('Text contains an unpaired UTF-16 surrogate.');
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error('Text contains an unpaired UTF-16 surrogate.');
    }
  }
}

// I-JSON applies stricter character rules than arbitrary UTF-8 message data.
export function assertIJsonUnicode(text) {
  assertWellFormedUnicode(text);
  for (const character of text) {
    const code = character.codePointAt(0);
    if ((code >= 0xfdd0 && code <= 0xfdef) || (code & 0xffff) >= 0xfffe) {
      throw new Error('Text contains a Unicode noncharacter prohibited by I-JSON.');
    }
  }
}
