import { bytesToBase64, bytesToHexLower, utf8ToBytes, wipeBytes } from './bytes.js';
import { createSha256Stream, createSha3_512Stream } from './hash.js';

// Keep fallback SHA3-512 work slices short enough to yield regularly on the UI
// thread. Web Crypto has no portable streaming digest API.
const DEFAULT_CHUNK_SIZE = 512 * 1024;
const DEFAULT_TEXT_CHUNK_SIZE = 64 * 1024;
const MAX_BUFFERED_FILE_SIZE_BYTES = 32 * 1024 * 1024;
const MAX_STREAMED_FILE_SIZE_BYTES = 64 * 1024 * 1024;
export const MAX_TEXT_INPUT_SIZE_BYTES = 1024 * 1024;

export async function createFileInputContext(file, options = {}) {
  if (!file) throw new Error('File is required.');
  const totalSize = Number(file.size);
  if (!Number.isSafeInteger(totalSize) || totalSize < 0) {
    throw new Error('File size is invalid.');
  }
  const fileName = String(file.name || '');
  const fileLastModified = Number(file.lastModified || 0);
  const mediaType = String(file.type || '').trim().toLowerCase() || 'application/octet-stream';
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
    total: totalSize,
    message: 'Preparing file read...',
  });

  const { bytes, digests } = await readFileChunked(file, {
    total: totalSize,
    chunkSize,
    keepBytes,
    onProgress,
    signal,
  });
  if (Number(file.size) !== totalSize) {
    wipeBytes(bytes);
    wipeDigestSet(digests);
    throw new Error('File changed while it was being read.');
  }

  onProgress?.({
    phase: 'done',
    loaded: totalSize,
    total: totalSize,
    message: 'Digests ready.',
  });

  return {
    type: 'file',
    fileName,
    fileSize: totalSize,
    fileLastModified,
    mediaType,
    bytes,
    digests,
  };
}

export async function createTextInputContext(text, options = {}) {
  const value = String(text || '');
  if (value.length > MAX_TEXT_INPUT_SIZE_BYTES) {
    throw new Error(`Text input is too large. Maximum supported UTF-8 size is ${MAX_TEXT_INPUT_SIZE_BYTES} bytes.`);
  }
  const bytes = utf8ToBytes(value);
  const fileSize = bytes.length;
  const keepBytes = options.keepBytes === true;
  const signal = options.signal || null;
  const chunkSize =
    Number.isInteger(options.chunkSize) && options.chunkSize > 0 ? options.chunkSize : DEFAULT_TEXT_CHUNK_SIZE;
  let digests = null;
  try {
    if (fileSize > MAX_TEXT_INPUT_SIZE_BYTES) {
      throw new Error(`Text input is too large. Maximum supported UTF-8 size is ${MAX_TEXT_INPUT_SIZE_BYTES} bytes.`);
    }
    throwIfAborted(signal);
    digests = await computeDigestsCooperatively(bytes, { chunkSize, signal });
    throwIfAborted(signal);
    return {
      type: 'text',
      fileName: '',
      fileSize,
      fileLastModified: 0,
      mediaType: 'text/plain;charset=utf-8',
      bytes: keepBytes ? bytes.slice() : new Uint8Array(0),
      digests,
    };
  } catch (err) {
    wipeDigestSet(digests);
    throw err;
  } finally {
    wipeBytes(bytes);
  }
}

async function readFileChunked(file, { total, chunkSize, keepBytes, onProgress, signal }) {
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
        const expectedLength = end - offset;
        if (chunk.length !== expectedLength) {
          throw new Error(
            `File read returned ${chunk.length} bytes for a ${expectedLength}-byte range; the file may have changed.`
          );
        }
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
      await yieldToEventLoop();
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

async function computeDigestsCooperatively(bytes, { chunkSize, signal }) {
  const sha256Stream = createSha256Stream({ nativeThreshold: 0 });
  const sha3Stream = createSha3_512Stream();
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    throwIfAborted(signal);
    const chunk = bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length));
    sha256Stream.update(chunk);
    sha3Stream.update(chunk);
    await yieldToEventLoop();
  }
  throwIfAborted(signal);
  const [sha256Bytes, sha3512Bytes] = await Promise.all([sha256Stream.finish(), sha3Stream.finish()]);
  return {
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
  };
}

function wipeDigestSet(digests) {
  wipeBytes(digests?.sha256?.bytes);
  wipeBytes(digests?.sha3_512?.bytes);
}

function yieldToEventLoop() {
  return new Promise((resolve) => setTimeout(resolve, 0));
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
