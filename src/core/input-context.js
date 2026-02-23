import { utf8ToBytes, wipeBytes } from './bytes.js';
import { computeDigests } from './hash.js';

const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;
const MAX_FILE_SIZE_BYTES = 256 * 1024 * 1024;

export async function createFileInputContext(file, options = {}) {
  if (!file) throw new Error('File is required.');
  const totalSize = Number(file.size || 0);
  if (!Number.isFinite(totalSize) || totalSize < 0) {
    throw new Error('File size is invalid.');
  }
  if (totalSize > MAX_FILE_SIZE_BYTES) {
    throw new Error(`File is too large. Maximum supported size is ${MAX_FILE_SIZE_BYTES} bytes.`);
  }

  const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
  const chunkSize = Number.isInteger(options.chunkSize) && options.chunkSize > 0 ? options.chunkSize : DEFAULT_CHUNK_SIZE;
  const keepBytes = options.keepBytes === true;

  onProgress?.({
    phase: 'start',
    loaded: 0,
    total: Number(file.size || 0),
    message: 'Preparing file read...',
  });

  const bytes = await readFileChunked(file, {
    chunkSize,
    onProgress,
  });

  onProgress?.({
    phase: 'digest',
    loaded: bytes.length,
    total: bytes.length,
    message: 'Computing SHA-256 and SHA3-512...',
  });

  const digests = await computeDigests(bytes);

  onProgress?.({
    phase: 'done',
    loaded: bytes.length,
    total: bytes.length,
    message: 'Digests ready.',
  });

  let outputBytes = new Uint8Array(0);
  if (keepBytes) {
    outputBytes = bytes;
  } else {
    wipeBytes(bytes);
  }

  return {
    type: 'file',
    fileName: String(file.name || ''),
    fileSize: Number(file.size || 0),
    fileLastModified: Number(file.lastModified || 0),
    bytes: outputBytes,
    digests,
  };
}

export async function createTextInputContext(text) {
  const bytes = utf8ToBytes(String(text || ''));
  const digests = await computeDigests(bytes);
  return {
    type: 'text',
    fileName: '',
    fileSize: bytes.length,
    fileLastModified: 0,
    bytes,
    digests,
  };
}

async function readFileChunked(file, { chunkSize, onProgress }) {
  const total = Number(file.size || 0);
  if (total === 0) return new Uint8Array(0);

  const out = new Uint8Array(total);
  let offset = 0;

  while (offset < total) {
    const end = Math.min(offset + chunkSize, total);
    const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());
    out.set(chunk, offset);
    wipeBytes(chunk);
    offset = end;

    onProgress?.({
      phase: 'read',
      loaded: offset,
      total,
      message: `Reading file: ${Math.round((offset / total) * 100)}%`,
    });
  }

  return out;
}
