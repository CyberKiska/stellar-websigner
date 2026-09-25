import { utf8ToBytes, wipeBytes } from './bytes.js';
import { createSha3_512Stream, digestSet, sha256 } from './hash.js';

// SHA3-512 is absorbed in short slices so the UI thread yields regularly. Web Crypto has no
// incremental digest, so SHA-256 is computed once by the provider over the assembled input.
const DEFAULT_CHUNK_SIZE = 512 * 1024;
const DEFAULT_TEXT_CHUNK_SIZE = 64 * 1024;
export const MAX_FILE_INPUT_SIZE_BYTES = 64 * 1024 * 1024;
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
  if (totalSize > MAX_FILE_INPUT_SIZE_BYTES) {
    throw new Error(`File is too large. Maximum supported size is ${MAX_FILE_INPUT_SIZE_BYTES} bytes.`);
  }
  throwIfAborted(signal);

  onProgress?.({
    phase: 'start',
    loaded: 0,
    total: totalSize,
    message: 'Preparing file read...',
  });

  const digests = await readFileChunked(file, {
    total: totalSize,
    chunkSize,
    onProgress,
    signal,
  });
  if (Number(file.size) !== totalSize) {
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
    digests,
  };
}

export async function createTextInputContext(text, options = {}) {
  // HTML textarea API values normalize CRLF/CR to LF, but not every engine applies this to every
  // insertion path (Linux WebKit keeps CR). Normalize here so sign and verify agree across engines.
  const value = String(text || '').replace(/\r\n?/g, '\n');
  if (value.length > MAX_TEXT_INPUT_SIZE_BYTES) {
    throw new Error(`Text input is too large. Maximum supported UTF-8 size is ${MAX_TEXT_INPUT_SIZE_BYTES} bytes.`);
  }
  const bytes = utf8ToBytes(value);
  const fileSize = bytes.length;
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
      digests,
    };
  } catch (err) {
    wipeDigestSet(digests);
    throw err;
  } finally {
    wipeBytes(bytes);
  }
}

async function readFileChunked(file, { total, chunkSize, onProgress, signal }) {
  const content = new Uint8Array(total);
  const sha3Stream = createSha3_512Stream();
  let digests = null;
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
        sha3Stream.update(chunk);
        content.set(chunk, offset);
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
    digests = digestSet(await sha256(content), await sha3Stream.finish());
    throwIfAborted(signal);
    return digests;
  } catch (err) {
    wipeDigestSet(digests);
    throw err;
  } finally {
    wipeBytes(content);
  }
}

async function computeDigestsCooperatively(bytes, { chunkSize, signal }) {
  const sha3Stream = createSha3_512Stream();
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    throwIfAborted(signal);
    sha3Stream.update(bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length)));
    await yieldToEventLoop();
  }
  throwIfAborted(signal);
  return digestSet(await sha256(bytes), await sha3Stream.finish());
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
