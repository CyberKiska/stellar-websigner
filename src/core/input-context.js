import { bytesToBase64, bytesToHexLower, utf8ToBytes, wipeBytes } from './bytes.js';
import { computeDigests, createSha256Stream, createSha3_512Stream } from './hash.js';

const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;
const MAX_BUFFERED_FILE_SIZE_BYTES = 256 * 1024 * 1024;
const MAX_STREAMED_FILE_SIZE_BYTES = 1024 * 1024 * 1024;

export async function createFileInputContext(file, options = {}) {
  if (!file) throw new Error('File is required.');
  const totalSize = Number(file.size || 0);
  if (!Number.isFinite(totalSize) || totalSize < 0) {
    throw new Error('File size is invalid.');
  }
  const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
  const signal = options.signal || null;
  const chunkSize = Number.isInteger(options.chunkSize) && options.chunkSize > 0 ? options.chunkSize : DEFAULT_CHUNK_SIZE;
  const keepBytes = options.keepBytes === true;
  const maxFileSize = keepBytes ? MAX_BUFFERED_FILE_SIZE_BYTES : MAX_STREAMED_FILE_SIZE_BYTES;
  if (totalSize > maxFileSize) {
    throw new Error(`File is too large. Maximum supported size is ${maxFileSize} bytes.`);
  }
  throwIfAborted(signal);

  onProgress?.({
    phase: 'start',
    loaded: 0,
    total: Number(file.size || 0),
    message: 'Preparing file read...',
  });

  const { bytes, digests } = await readFileChunked(file, {
    chunkSize,
    keepBytes,
    onProgress,
    signal,
  });

  onProgress?.({
    phase: 'done',
    loaded: totalSize,
    total: totalSize,
    message: 'Digests ready.',
  });

  return {
    type: 'file',
    fileName: String(file.name || ''),
    fileSize: Number(file.size || 0),
    fileLastModified: Number(file.lastModified || 0),
    bytes,
    digests,
  };
}

export async function createTextInputContext(text, options = {}) {
  const bytes = utf8ToBytes(String(text || ''));
  const fileSize = bytes.length;
  const keepBytes = options.keepBytes === true;
  const signal = options.signal || null;
  try {
    throwIfAborted(signal);
    const digests = await computeDigests(bytes);
    throwIfAborted(signal);
    return {
      type: 'text',
      fileName: '',
      fileSize,
      fileLastModified: 0,
      bytes: keepBytes ? bytes.slice() : new Uint8Array(0),
      digests,
    };
  } finally {
    wipeBytes(bytes);
  }
}

async function readFileChunked(file, { chunkSize, keepBytes, onProgress, signal }) {
  const total = Number(file.size || 0);
  const sha256Stream = createSha256Stream({ nativeThreshold: 0 });
  const sha3Stream = createSha3_512Stream();
  const out = keepBytes ? new Uint8Array(total) : new Uint8Array(0);
  let sha256Bytes = null;
  let sha3512Bytes = null;

  let offset = 0;
  try {
    while (offset < total) {
      throwIfAborted(signal);
      const end = Math.min(offset + chunkSize, total);
      const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());
      try {
        throwIfAborted(signal);
        sha256Stream.update(chunk);
        sha3Stream.update(chunk);
        if (keepBytes) {
          out.set(chunk, offset);
        }
      } finally {
        wipeBytes(chunk);
      }
      offset = end;

      onProgress?.({
        phase: 'read',
        loaded: offset,
        total,
        message: `Reading and hashing file: ${Math.round((offset / total) * 100)}%`,
      });
    }

    onProgress?.({
      phase: 'digest',
      loaded: total,
      total,
      message: 'Finalizing SHA-256 and SHA3-512...',
    });
    throwIfAborted(signal);

    [sha256Bytes, sha3512Bytes] = await Promise.all([sha256Stream.finish(), sha3Stream.finish()]);
    throwIfAborted(signal);
    return {
      bytes: out,
      digests: {
        sha256: {
          alg: 'SHA-256',
          bytes: sha256Bytes,
          hex: bytesToHexLower(sha256Bytes),
          base64: bytesToBase64(sha256Bytes),
        },
        sha3_512: {
          alg: 'SHA3-512',
          bytes: sha3512Bytes,
          hex: bytesToHexLower(sha3512Bytes),
          base64: bytesToBase64(sha3512Bytes),
        },
      },
    };
  } catch (err) {
    wipeBytes(out);
    if (sha256Bytes) wipeBytes(sha256Bytes);
    if (sha3512Bytes) wipeBytes(sha3512Bytes);
    throw err;
  }
}

function throwIfAborted(signal) {
  if (!signal?.aborted) return;
  if (signal.reason instanceof Error) {
    throw signal.reason;
  }
  const err = new Error(signal.reason ? String(signal.reason) : 'Operation cancelled.');
  err.name = 'AbortError';
  throw err;
}
