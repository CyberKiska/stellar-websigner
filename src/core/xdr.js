import {
  base64ToBytes,
  bytesEqual,
  bytesToBase64,
  bytesToUtf8,
  concatBytes,
  utf8ToBytes,
} from './bytes.js';
import { signatureHint, verifyBytesWithPublic } from './ed25519.js';
import { sha256 } from './hash.js';
import { MANAGE_DATA_NAME } from './constants.js';

export const ENVELOPE_TYPE_TX = 2;
export const OPERATION_TYPE_MANAGE_DATA = 10;

const KEY_TYPE_ED25519 = 0;
const PRECOND_NONE = 0;
const MEMO_NONE = 0;

export function buildUnsignedManageDataEnvelope({
  sourcePublicKey,
  sequence = 0n,
  fee = 8000,
  manageDataEntries,
  dataName,
  dataValue,
}) {
  if (!(sourcePublicKey instanceof Uint8Array) || sourcePublicKey.length !== 32) {
    throw new Error('sourcePublicKey must be 32 bytes.');
  }
  if (!Number.isInteger(fee) || fee <= 0 || fee > 0xffffffff) {
    throw new Error('fee must be uint32 > 0.');
  }
  const entries = normalizeManageDataEntries({ manageDataEntries, dataName, dataValue });
  if (entries.length === 0) {
    throw new Error('At least one ManageData entry is required.');
  }
  if (entries.length > 8) {
    throw new Error('Too many ManageData entries. Maximum allowed is 8.');
  }

  const txWriter = new XdrWriter();
  txWriter.writeInt32(KEY_TYPE_ED25519);
  txWriter.writeOpaqueFixed(sourcePublicKey);
  txWriter.writeUint32(fee);
  txWriter.writeInt64(sequence);
  txWriter.writeInt32(PRECOND_NONE);
  txWriter.writeInt32(MEMO_NONE);

  txWriter.writeInt32(entries.length); // operation count

  for (const entry of entries) {
    txWriter.writeInt32(0); // operation source account absent
    txWriter.writeInt32(OPERATION_TYPE_MANAGE_DATA);
    txWriter.writeString(entry.dataName);
    txWriter.writeInt32(1); // dataValue present
    txWriter.writeOpaque(entry.dataValue);
  }

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
  const raw = input instanceof Uint8Array ? input : base64ToBytes(input);
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

export function assertSafeManageDataEnvelope(parsed, { expectedDataName, expectedDataValue, expectedEntries } = {}) {
  if (!parsed?.transaction) {
    throw new Error('Envelope parse result is missing transaction.');
  }

  const tx = parsed.transaction;

  if (tx.sequence !== 0n) {
    throw new Error('Unsafe transaction: sequence must be 0.');
  }

  if (!Number.isInteger(tx.fee) || tx.fee <= 0 || tx.fee > 100000) {
    throw new Error('Unsafe transaction: fee is outside allowed range.');
  }

  if (!Array.isArray(tx.operations) || tx.operations.length === 0) {
    throw new Error('Unsafe transaction: at least one operation is required.');
  }

  if (tx.operations.length > 8) {
    throw new Error('Unsafe transaction: too many operations.');
  }

  const manageDataEntries = [];
  const seenDataNames = new Set();
  for (const op of tx.operations) {
    if (op.type !== OPERATION_TYPE_MANAGE_DATA) {
      throw new Error('Unsafe transaction: only ManageData operation is allowed.');
    }

    if (op.sourceAccount) {
      throw new Error('Unsafe transaction: operation-level sourceAccount is not allowed.');
    }

    if (!op.body?.dataValue || !(op.body.dataValue instanceof Uint8Array)) {
      throw new Error('ManageData operation must include a non-empty value.');
    }

    const dataName = String(op.body?.dataName || '');
    assertSupportedManageDataName(dataName);
    if (seenDataNames.has(dataName)) {
      throw new Error(`Duplicate ManageData name in transaction: ${dataName}`);
    }
    seenDataNames.add(dataName);

    if (op.body.dataValue.length > 64) {
      throw new Error('ManageData value exceeds 64 bytes.');
    }
    const expectedLength = expectedManageDataLength(dataName);
    if (op.body.dataValue.length !== expectedLength) {
      throw new Error(
        `ManageData value length mismatch for ${dataName}: expected ${expectedLength} bytes, got ${op.body.dataValue.length}.`
      );
    }

    manageDataEntries.push({
      dataName,
      dataValue: op.body.dataValue,
    });
  }

  if (expectedDataName || expectedDataValue) {
    if (manageDataEntries.length !== 1) {
      throw new Error('ManageData transaction shape mismatch: expected single operation.');
    }
    const first = manageDataEntries[0];

    if (expectedDataName && first.dataName !== expectedDataName) {
      throw new Error(`ManageData name mismatch. expected=${expectedDataName} actual=${first.dataName}`);
    }

    if (expectedDataValue && !bytesEqual(first.dataValue, expectedDataValue)) {
      throw new Error('ManageData value does not match expected digest bytes.');
    }
  }

  if (Array.isArray(expectedEntries) && expectedEntries.length > 0) {
    const normalizedExpected = expectedEntries.map((item) => ({
      dataName: String(item?.dataName || ''),
      dataValue: item?.dataValue instanceof Uint8Array ? item.dataValue : null,
    }));

    if (normalizedExpected.length !== manageDataEntries.length) {
      throw new Error('ManageData operation count does not match expected entries.');
    }

    const seenExpected = new Set();
    for (const expected of normalizedExpected) {
      if (!expected.dataName) {
        throw new Error('Expected ManageData entry has empty name.');
      }
      if (seenExpected.has(expected.dataName)) {
        throw new Error(`Expected ManageData entries contain duplicate name: ${expected.dataName}`);
      }
      seenExpected.add(expected.dataName);
    }

    const entryMap = new Map(manageDataEntries.map((item) => [item.dataName, item]));
    for (const expected of normalizedExpected) {
      const actual = entryMap.get(expected.dataName);
      if (!actual) {
        throw new Error(`ManageData name mismatch: missing ${expected.dataName}`);
      }
      if (expected.dataValue && !bytesEqual(expected.dataValue, actual.dataValue)) {
        throw new Error(`ManageData value mismatch for ${expected.dataName}`);
      }
    }
  }

  return {
    sourceAccount: tx.sourceAccount,
    dataName: manageDataEntries[0].dataName,
    dataValue: manageDataEntries[0].dataValue,
    manageDataEntries,
  };
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
  const signerHint = signatureHint(signerPublicBytes);

  for (const item of signatures) {
    if (!(item.signature instanceof Uint8Array) || item.signature.length !== 64) continue;
    if (!(item.hint instanceof Uint8Array) || item.hint.length !== 4) continue;
    if (!bytesEqual(item.hint, signerHint)) continue;

    const ok = await verifyBytesWithPublic(signerPublicBytes, txHash, item.signature);
    if (ok) return item;
  }

  for (const item of signatures) {
    if (!(item.signature instanceof Uint8Array) || item.signature.length !== 64) continue;
    const ok = await verifyBytesWithPublic(signerPublicBytes, txHash, item.signature);
    if (ok) return item;
  }

  return null;
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

  const dataName = reader.readString();
  const hasDataValue = reader.readInt32();
  if (hasDataValue !== 0 && hasDataValue !== 1) {
    throw new Error('Invalid ManageData optional value flag.');
  }

  const dataValue = hasDataValue ? reader.readOpaque() : null;

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
    const signature = reader.readOpaque();
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
    if (n < 0n || n > 0x7fffffffffffffffn) {
      throw new Error('int64 out of range.');
    }
    const bytes = new Uint8Array(8);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, Number((n >> 32n) & 0xffffffffn), false);
    view.setUint32(4, Number(n & 0xffffffffn), false);
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

function normalizeManageDataEntries({ manageDataEntries, dataName, dataValue }) {
  if (Array.isArray(manageDataEntries)) {
    const seen = new Set();
    return manageDataEntries.map((entry, idx) => {
      const name = String(entry?.dataName || '').trim();
      const value = entry?.dataValue;
      if (!name || name.length > 64) {
        throw new Error(`ManageData name #${idx + 1} must be 1..64 characters.`);
      }
      if (seen.has(name)) {
        throw new Error(`ManageData name #${idx + 1} duplicates previous entry: ${name}`);
      }
      seen.add(name);
      if (!(value instanceof Uint8Array) || value.length === 0 || value.length > 64) {
        throw new Error(`ManageData value #${idx + 1} must be 1..64 bytes.`);
      }
      assertSupportedManageDataName(name);
      const expectedLength = expectedManageDataLength(name);
      if (value.length !== expectedLength) {
        throw new Error(`ManageData value #${idx + 1} must be exactly ${expectedLength} bytes for ${name}.`);
      }
      return {
        dataName: name,
        dataValue: value,
      };
    });
  }

  if (dataName || dataValue) {
    const name = String(dataName || '').trim();
    if (!name || name.length > 64) {
      throw new Error('ManageData name must be 1..64 characters.');
    }
    if (!(dataValue instanceof Uint8Array) || dataValue.length === 0 || dataValue.length > 64) {
      throw new Error('ManageData value must be 1..64 bytes.');
    }
    assertSupportedManageDataName(name);
    const expectedLength = expectedManageDataLength(name);
    if (dataValue.length !== expectedLength) {
      throw new Error(`ManageData value must be exactly ${expectedLength} bytes for ${name}.`);
    }
    return [{ dataName: name, dataValue }];
  }

  return [];
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
    return (BigInt(high) << 32n) | BigInt(low);
  }

  readOpaqueFixed(length) {
    const data = this.readSlice(length);
    const pad = (4 - (length % 4)) % 4;
    if (pad) this.readSlice(pad);
    return data;
  }

  readOpaque() {
    const length = this.readInt32();
    if (length < 0) {
      throw new Error('Invalid opaque length.');
    }
    return this.readOpaqueFixed(length);
  }

  readString() {
    return bytesToUtf8(this.readOpaque());
  }

  ensureConsumed() {
    if (this.offset !== this.bytes.length) {
      throw new Error('XDR contains trailing bytes.');
    }
  }
}

function assertSupportedManageDataName(name) {
  if (name !== MANAGE_DATA_NAME.SHA256 && name !== MANAGE_DATA_NAME.SHA3_512) {
    throw new Error(`Unsupported ManageData name: ${name}`);
  }
}

function expectedManageDataLength(name) {
  if (name === MANAGE_DATA_NAME.SHA256) return 32;
  return 64;
}
