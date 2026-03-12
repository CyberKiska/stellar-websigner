import {
  HASH_ALG,
  HASH_SELECTION,
  MANAGE_DATA_NAME,
} from './constants.js';

export function normalizeInputKind(kind) {
  if (kind === 'file' || kind === 'text') return kind;
  throw new Error('Input type must be file or text.');
}

export function normalizeHashSelection(value) {
  const normalized = String(value || HASH_SELECTION.BOTH).trim().toLowerCase();
  if (normalized === HASH_SELECTION.BOTH) return HASH_SELECTION.BOTH;
  if (normalized === HASH_SELECTION.SHA256) return HASH_SELECTION.SHA256;
  if (normalized === HASH_SELECTION.SHA3_512) return HASH_SELECTION.SHA3_512;
  throw new Error(`Unsupported hash selection: ${value}`);
}

export function hashSelectionToAlgorithms(selection) {
  const normalized = normalizeHashSelection(selection);
  if (normalized === HASH_SELECTION.BOTH) {
    return [HASH_ALG.SHA256, HASH_ALG.SHA3_512];
  }
  if (normalized === HASH_SELECTION.SHA256) {
    return [HASH_ALG.SHA256];
  }
  return [HASH_ALG.SHA3_512];
}

export function buildHashEntriesFromDigests(digests, hashSelection = HASH_SELECTION.BOTH) {
  if (!digests?.sha256 || !digests?.sha3_512) {
    throw new Error('Missing computed digests.');
  }

  const algorithms = hashSelectionToAlgorithms(hashSelection);
  return algorithms.map((alg) => {
    const digest = digestForHashAlgorithm(digests, alg);
    return {
      alg,
      hex: digest.hex,
    };
  });
}

export function digestForHashAlgorithm(digests, hashAlg) {
  const normalized = normalizeHashAlgorithmName(hashAlg);
  if (!digests?.sha256 || !digests?.sha3_512) {
    throw new Error('Missing computed digests.');
  }

  if (normalized === HASH_ALG.SHA256) {
    return {
      alg: HASH_ALG.SHA256,
      bytes: digests.sha256.bytes,
      hex: digests.sha256.hex,
      manageDataName: MANAGE_DATA_NAME.SHA256,
    };
  }

  return {
    alg: HASH_ALG.SHA3_512,
    bytes: digests.sha3_512.bytes,
    hex: digests.sha3_512.hex,
    manageDataName: MANAGE_DATA_NAME.SHA3_512,
  };
}

export function hashAlgorithmFromManageDataName(name) {
  const value = String(name || '').trim();
  if (value === MANAGE_DATA_NAME.SHA256) return HASH_ALG.SHA256;
  if (value === MANAGE_DATA_NAME.SHA3_512) return HASH_ALG.SHA3_512;
  return null;
}

export function parseHashEntries(signatureDoc) {
  const raw = signatureDoc?.hashes;
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error('Signature has no hash entries.');
  }

  const normalized = [];
  const seen = new Set();
  for (const item of raw) {
    const alg = normalizeHashAlgorithmName(item?.alg);
    const hex = String(item?.hex || '').toLowerCase();

    if (!/^[0-9a-f]+$/.test(hex)) {
      throw new Error(`Invalid digest hex for ${alg}.`);
    }
    if (hex.length !== expectedDigestHexLength(alg)) {
      throw new Error(`Invalid digest hex length for ${alg}.`);
    }
    if (seen.has(alg)) {
      throw new Error(`Duplicate hash entry: ${alg}.`);
    }

    seen.add(alg);
    normalized.push({ alg, hex });
  }

  return normalized;
}

export function normalizeHashAlgorithmName(value) {
  const normalized = String(value || '').trim().toUpperCase();
  if (normalized === HASH_ALG.SHA256) return HASH_ALG.SHA256;
  if (normalized === HASH_ALG.SHA3_512) return HASH_ALG.SHA3_512;
  throw new Error(`Unsupported hash algorithm: ${value}`);
}

function expectedDigestHexLength(alg) {
  const normalized = normalizeHashAlgorithmName(alg);
  if (normalized === HASH_ALG.SHA256) return 64;
  return 128;
}

export function buildInputDescriptor({ type, fileName, fileSize }) {
  const kind = normalizeInputKind(type);
  if (kind === 'file') {
    return {
      type: 'file',
      name: String(fileName || ''),
      size: Number(fileSize || 0),
    };
  }
  return { type: 'text', size: Number(fileSize || 0) };
}
