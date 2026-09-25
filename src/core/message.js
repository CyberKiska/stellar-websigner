import { HASH_ALG } from './constants.js';

export function normalizeInputKind(kind) {
  if (kind === 'file' || kind === 'text') return kind;
  throw new Error('Input type must be file or text.');
}

export function buildHashEntriesFromDigests(digests) {
  if (!digests?.sha256?.hex || !digests?.sha3_512?.hex) {
    throw new Error('Missing computed digests.');
  }
  return [
    { alg: HASH_ALG.SHA256, hex: digests.sha256.hex },
    { alg: HASH_ALG.SHA3_512, hex: digests.sha3_512.hex },
  ];
}

export function buildInputDescriptor({ type, fileName, fileSize, mediaType = '' }) {
  const kind = normalizeInputKind(type);
  if (kind === 'file') {
    return {
      type: 'file',
      name: String(fileName || ''),
      namePolicy: 'exact-basename',
      size: Number(fileSize || 0),
      mediaType: String(mediaType || '').trim().toLowerCase() || 'application/octet-stream',
    };
  }
  return {
    type: 'text',
    size: Number(fileSize || 0),
    mediaType: 'text/plain;charset=utf-8',
    textEncoding: 'utf-8-dom-value-no-normalization',
  };
}
