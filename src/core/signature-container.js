import { MODE, SIGNATURE_SCHEMA } from './constants.js';

export function createLocalSignatureDocument({
  signer,
  hashEntries,
  message,
  signatureB64,
  input,
}) {
  return {
    schema: SIGNATURE_SCHEMA,
    mode: MODE.SEP53,
    signer,
    hashes: hashEntries,
    message,
    signatureB64,
    input,
  };
}

export function createSep7SignatureDocument({
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
    schema: SIGNATURE_SCHEMA,
    mode: MODE.SEP7_TX,
    signer,
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

export function serializeSignatureDocument(doc) {
  return `${JSON.stringify(doc, null, 2)}\n`;
}

export function suggestSignatureFileName({ inputType, originalName }) {
  if (inputType === 'file') {
    const safe = String(originalName || 'file').replace(/[^a-zA-Z0-9._-]+/g, '_');
    return `${safe}.sig`;
  }
  return 'plain-text.sig';
}
