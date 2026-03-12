import {
  PAYLOAD_TYPE,
  PROOF_TYPE,
  SIGNATURE_SCHEME,
  SIGNATURE_SCHEMA_V2,
} from './constants.js';

export function createSep53MessageSignatureDocument({
  signer,
  signatureB64,
  input,
  hashEntries = [],
}) {
  return {
    schema: SIGNATURE_SCHEMA_V2,
    signer,
    proofType: PROOF_TYPE.SEP53_MESSAGE,
    payloadType: PAYLOAD_TYPE.RAW_BYTES,
    signatureScheme: SIGNATURE_SCHEME.SEP53_SHA256_ED25519,
    input,
    hashes: hashEntries,
    signatureB64,
  };
}

export function createXdrProofSignatureDocument({
  signer,
  networkPassphrase,
  networkHint,
  hashEntries,
  manageDataEntries,
  txSourceAccount,
  signedXdr,
  input,
}) {
  return {
    schema: SIGNATURE_SCHEMA_V2,
    signer,
    proofType: PROOF_TYPE.XDR_ENVELOPE,
    payloadType: PAYLOAD_TYPE.DETACHED_DIGESTS,
    signatureScheme: SIGNATURE_SCHEME.TX_ENVELOPE_ED25519,
    network: {
      passphrase: networkPassphrase,
      hint: networkHint,
    },
    hashes: hashEntries,
    manageData: {
      entries: manageDataEntries,
    },
    txSourceAccount: String(txSourceAccount || ''),
    signedXdr,
    input,
  };
}

export function serializeSignatureDocument(doc, options = {}) {
  const canonicalDoc = canonicalizeJsonValue(doc);
  if (options.pretty === true) {
    return `${JSON.stringify(canonicalDoc, null, 2)}\n`;
  }
  return `${JSON.stringify(canonicalDoc)}\n`;
}

export function suggestSignatureFileName({ inputType, originalName }) {
  if (inputType === 'file') {
    const safe = String(originalName || 'file').replace(/[^a-zA-Z0-9._-]+/g, '_');
    return `${safe}.sig`;
  }
  return 'plain-text.sig';
}

export function isV2SignatureDocument(signatureDoc) {
  return String(signatureDoc?.schema || '').trim() === SIGNATURE_SCHEMA_V2;
}

function canonicalizeJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeJsonValue(item));
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = canonicalizeJsonValue(value[key]);
    }
    return out;
  }
  return value;
}
