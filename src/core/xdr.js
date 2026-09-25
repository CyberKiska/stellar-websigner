import {
  canonicalBase64ToBytes,
  bytesEqual,
  bytesToBase64,
  bytesToUtf8,
  concatBytes,
  utf8ToBytes,
} from './bytes.js';
import { signatureHint, verifyBytesWithPublic } from './ed25519.js';
import { sha256 } from './hash.js';
import { MANIFEST_DATA_NAME } from './constants.js';

export const ENVELOPE_TYPE_TX = 2;
export const OPERATION_TYPE_MANAGE_DATA = 10;
export const MAX_XDR_ENVELOPE_BYTES = 64 * 1024;

const KEY_TYPE_ED25519 = 0;
const PRECOND_NONE = 0;
const MEMO_NONE = 0;
const INT64_MIN = -(1n << 63n);
const INT64_MAX = (1n << 63n) - 1n;
const MAX_PROOF_FEE = 100000;

// The proof profile is one ManageData operation carrying SHA-256 of the protected manifest, with sequence 0
// so the signed transaction can never be applied on-ledger.
export function buildUnsignedManifestEnvelope({ sourcePublicKey, manifestDigest, sequence = 0n, fee = 8000 }) {
  if (!(sourcePublicKey instanceof Uint8Array) || sourcePublicKey.length !== 32) {
    throw new Error('sourcePublicKey must be 32 bytes.');
  }
  if (!(manifestDigest instanceof Uint8Array) || manifestDigest.length !== 32) {
    throw new Error('Manifest digest must be 32 bytes.');
  }
  if (!Number.isInteger(fee) || fee <= 0 || fee > 0xffffffff) {
    throw new Error('fee must be uint32 > 0.');
  }

  const txWriter = new XdrWriter();
  txWriter.writeInt32(KEY_TYPE_ED25519);
  txWriter.writeOpaqueFixed(sourcePublicKey);
  txWriter.writeUint32(fee);
  txWriter.writeInt64(sequence);
  txWriter.writeInt32(PRECOND_NONE);
  txWriter.writeInt32(MEMO_NONE);
  txWriter.writeInt32(1); // operation count
  txWriter.writeInt32(0); // operation source account absent
  txWriter.writeInt32(OPERATION_TYPE_MANAGE_DATA);
  txWriter.writeString(MANIFEST_DATA_NAME);
  txWriter.writeInt32(1); // dataValue present
  txWriter.writeOpaque(manifestDigest);
  txWriter.writeInt32(0); // tx.ext.v = 0

  const txXdr = txWriter.finish();

  const envelopeWriter = new XdrWriter();
  envelopeWriter.writeInt32(ENVELOPE_TYPE_TX);
  envelopeWriter.writeRaw(txXdr);
  envelopeWriter.writeInt32(0); // zero signatures

  return {
    txXdr,
    envelopeXdr: envelopeWriter.finish(),
  };
}

export function encodeSignedTxEnvelope({ txXdr, signatures }) {
  if (!(txXdr instanceof Uint8Array)) {
    throw new Error('txXdr must be Uint8Array.');
  }
  if (!Array.isArray(signatures) || signatures.length === 0) {
    throw new Error('At least one decorated signature is required.');
  }

  const writer = new XdrWriter();
  writer.writeInt32(ENVELOPE_TYPE_TX);
  writer.writeRaw(txXdr);
  writer.writeInt32(signatures.length);

  for (const item of signatures) {
    if (!(item.hint instanceof Uint8Array) || item.hint.length !== 4) {
      throw new Error('Decorated signature hint must be 4 bytes.');
    }
    if (!(item.signature instanceof Uint8Array) || item.signature.length !== 64) {
      throw new Error('Decorated signature must be 64 bytes.');
    }
    writer.writeOpaqueFixed(item.hint);
    writer.writeOpaque(item.signature);
  }

  return writer.finish();
}

export function parseTransactionEnvelope(input) {
  const raw = input instanceof Uint8Array
    ? input
    : canonicalBase64ToBytes(input, { maxBytes: MAX_XDR_ENVELOPE_BYTES });
  if (raw.length > MAX_XDR_ENVELOPE_BYTES) throw new Error('XDR envelope is too large.');
  const reader = new XdrReader(raw);

  const envelopeType = reader.readInt32();
  if (envelopeType !== ENVELOPE_TYPE_TX) {
    throw new Error(`Unsupported envelope type: ${envelopeType}`);
  }

  const txStart = reader.offset;
  const transaction = parseTransaction(reader);
  const txEnd = reader.offset;

  const signatures = parseDecoratedSignatures(reader);
  reader.ensureConsumed();

  return {
    envelopeType,
    transaction,
    signatures,
    txXdr: raw.slice(txStart, txEnd),
    envelopeXdr: raw,
  };
}

export function assertManifestProofEnvelope(parsed, expectedManifestDigest) {
  const tx = parsed?.transaction;
  if (!tx) throw new Error('Envelope parse result is missing transaction.');
  if (tx.sequence !== 0n) throw new Error('Unsafe transaction: sequence must be 0.');
  if (!Number.isInteger(tx.fee) || tx.fee <= 0 || tx.fee > MAX_PROOF_FEE) {
    throw new Error('Unsafe transaction: fee is outside allowed range.');
  }
  if (!Array.isArray(tx.operations) || tx.operations.length !== 1) {
    throw new Error('Proof transaction must contain exactly one ManageData operation.');
  }
  const [op] = tx.operations;
  if (op.type !== OPERATION_TYPE_MANAGE_DATA) {
    throw new Error('Unsafe transaction: only ManageData operation is allowed.');
  }
  if (op.sourceAccount) {
    throw new Error('Unsafe transaction: operation-level sourceAccount is not allowed.');
  }
  if (op.body?.dataName !== MANIFEST_DATA_NAME) {
    throw new Error(`Unsupported ManageData name: ${op.body?.dataName}`);
  }
  const value = op.body.dataValue;
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error('ManageData value must be a 32-byte protected-manifest digest.');
  }
  if (!bytesEqual(value, expectedManifestDigest)) {
    throw new Error('ManageData value mismatch: the transaction does not bind this protected manifest.');
  }
  return { sourceAccount: tx.sourceAccount };
}

export async function computeTransactionHash(txXdr, networkPassphrase) {
  if (!(txXdr instanceof Uint8Array)) {
    throw new Error('txXdr must be Uint8Array.');
  }
  if (!String(networkPassphrase || '').length) {
    throw new Error('Network passphrase is required.');
  }

  const networkId = await sha256(utf8ToBytes(networkPassphrase));
  const writer = new XdrWriter();
  writer.writeRaw(networkId);
  writer.writeInt32(ENVELOPE_TYPE_TX);
  writer.writeRaw(txXdr);
  return sha256(writer.finish());
}

export async function findValidDecoratedSignature(signatures, signerPublicBytes, txHash) {
  if (!Array.isArray(signatures) || signatures.length !== 1) {
    throw new Error('This proof profile requires exactly one decorated signature.');
  }
  if (!(signatures[0].signature instanceof Uint8Array) || signatures[0].signature.length !== 64) {
    throw new Error('This proof profile requires one 64-byte Ed25519 signature.');
  }
  const signerHint = signatureHint(signerPublicBytes);
  const item = signatures[0];
  if (!(item.hint instanceof Uint8Array) || item.hint.length !== 4 || !bytesEqual(item.hint, signerHint)) {
    throw new Error('Decorated signature hint does not match the declared signer.');
  }
  return (await verifyBytesWithPublic(signerPublicBytes, txHash, item.signature)) ? item : null;
}

export function txEnvelopeToBase64(envelopeXdrBytes) {
  return bytesToBase64(envelopeXdrBytes);
}

function parseTransaction(reader) {
  const sourceType = reader.readInt32();
  if (sourceType !== KEY_TYPE_ED25519) {
    throw new Error('Only ED25519 source account is supported.');
  }
  const sourceAccount = reader.readOpaqueFixed(32);
  const fee = reader.readUint32();
  const sequence = reader.readInt64();

  const preconditionsType = reader.readInt32();
  if (preconditionsType !== PRECOND_NONE) {
    throw new Error('Only PRECOND_NONE is supported.');
  }

  const memoType = reader.readInt32();
  if (memoType !== MEMO_NONE) {
    throw new Error('Only MEMO_NONE is supported.');
  }

  const operationCount = reader.readInt32();
  if (!Number.isInteger(operationCount) || operationCount < 0 || operationCount > 100) {
    throw new Error(`Invalid operation count: ${operationCount}`);
  }

  const operations = [];
  for (let i = 0; i < operationCount; i += 1) {
    operations.push(parseOperation(reader));
  }

  const ext = reader.readInt32();
  if (ext !== 0) {
    throw new Error('Only tx.ext.v=0 is supported.');
  }

  return {
    sourceAccount,
    fee,
    sequence,
    operations,
  };
}

function parseOperation(reader) {
  const hasSourceAccount = reader.readInt32();
  if (hasSourceAccount !== 0 && hasSourceAccount !== 1) {
    throw new Error('Invalid operation.sourceAccount optional field.');
  }

  let sourceAccount = null;
  if (hasSourceAccount === 1) {
    const sourceType = reader.readInt32();
    if (sourceType !== KEY_TYPE_ED25519) {
      throw new Error('Only ED25519 operation.sourceAccount is supported.');
    }
    sourceAccount = reader.readOpaqueFixed(32);
  }

  const type = reader.readInt32();
  if (type !== OPERATION_TYPE_MANAGE_DATA) {
    throw new Error(`Unsafe transaction: operation type ${type} is not allowed.`);
  }

  const dataName = reader.readString(64);
  const hasDataValue = reader.readInt32();
  if (hasDataValue !== 0 && hasDataValue !== 1) {
    throw new Error('Invalid ManageData optional value flag.');
  }

  const dataValue = hasDataValue ? reader.readOpaque(64) : null;

  return {
    type,
    sourceAccount,
    body: {
      dataName,
      dataValue,
    },
  };
}

function parseDecoratedSignatures(reader) {
  const count = reader.readInt32();
  if (!Number.isInteger(count) || count < 0 || count > 20) {
    throw new Error(`Invalid signature count: ${count}`);
  }

  const out = [];
  for (let i = 0; i < count; i += 1) {
    const hint = reader.readOpaqueFixed(4);
    const signature = reader.readOpaque(64);
    out.push({ hint, signature });
  }

  return out;
}

class XdrWriter {
  constructor() {
    this.parts = [];
    this.length = 0;
  }

  push(bytes) {
    this.parts.push(bytes);
    this.length += bytes.length;
  }

  writeRaw(bytes) {
    this.push(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes));
  }

  writeInt32(value) {
    const bytes = new Uint8Array(4);
    const view = new DataView(bytes.buffer);
    view.setInt32(0, Number(value), false);
    this.push(bytes);
  }

  writeUint32(value) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new Error('uint32 out of range.');
    }
    const bytes = new Uint8Array(4);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, value, false);
    this.push(bytes);
  }

  writeInt64(value) {
    const n = BigInt(value);
    if (n < INT64_MIN || n > INT64_MAX) {
      throw new Error('int64 out of range.');
    }
    const encoded = BigInt.asUintN(64, n);
    const bytes = new Uint8Array(8);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, Number((encoded >> 32n) & 0xffffffffn), false);
    view.setUint32(4, Number(encoded & 0xffffffffn), false);
    this.push(bytes);
  }

  writeOpaqueFixed(bytes) {
    const data = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    this.push(data);
    const pad = (4 - (data.length % 4)) % 4;
    if (pad) this.push(new Uint8Array(pad));
  }

  writeOpaque(bytes) {
    const data = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    this.writeInt32(data.length);
    this.writeOpaqueFixed(data);
  }

  writeString(value) {
    this.writeOpaque(utf8ToBytes(value));
  }

  finish() {
    return concatBytes(...this.parts);
  }
}

class XdrReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }

  ensureAvailable(length) {
    if (this.offset + length > this.bytes.length) {
      throw new Error('Unexpected end of XDR data.');
    }
  }

  readSlice(length) {
    this.ensureAvailable(length);
    const out = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  readInt32() {
    const chunk = this.readSlice(4);
    return new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength).getInt32(0, false);
  }

  readUint32() {
    const chunk = this.readSlice(4);
    return new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength).getUint32(0, false);
  }

  readInt64() {
    const high = this.readUint32();
    const low = this.readUint32();
    return BigInt.asIntN(64, (BigInt(high) << 32n) | BigInt(low));
  }

  readOpaqueFixed(length) {
    const data = this.readSlice(length);
    const pad = (4 - (length % 4)) % 4;
    if (pad) {
      const padding = this.readSlice(pad);
      for (const byte of padding) {
        if (byte !== 0) throw new Error('XDR padding bytes must be zero.');
      }
    }
    return data;
  }

  readOpaque(maxLength = MAX_XDR_ENVELOPE_BYTES) {
    const length = this.readInt32();
    if (length < 0 || length > maxLength) {
      throw new Error('Invalid opaque length.');
    }
    return this.readOpaqueFixed(length);
  }

  readString(maxLength) {
    return bytesToUtf8(this.readOpaque(maxLength));
  }

  ensureConsumed() {
    if (this.offset !== this.bytes.length) {
      throw new Error('XDR contains trailing bytes.');
    }
  }
}
