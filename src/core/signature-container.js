import { canonicalJsonStringify } from './canonical-json.js';
import { SIGNATURE_SCHEMA_V3 } from './constants.js';

export function createSep53MessageSignatureDocument({ signer, signatureB64, protectedManifest }) {
  return {
    schema: SIGNATURE_SCHEMA_V3,
    signer,
    protected: protectedManifest,
    signatureB64,
  };
}

export function createXdrProofSignatureDocument({ signer, signedXdr, protectedManifest }) {
  return {
    schema: SIGNATURE_SCHEMA_V3,
    signer,
    protected: protectedManifest,
    signedXdr,
  };
}

export function serializeSignatureDocument(doc, options = {}) {
  const canonical = canonicalJsonStringify(doc);
  if (options.pretty === true) {
    return `${JSON.stringify(JSON.parse(canonical), null, 2)}\n`;
  }
  return canonical;
}

export function suggestSignatureFileName({ inputType, originalName }) {
  if (inputType === 'file') {
    const safe = String(originalName || 'file').replace(/[^a-zA-Z0-9._-]+/g, '_');
    return `${safe}.sig`;
  }
  return 'plain-text.sig';
}

export function isV3SignatureDocument(signatureDoc) {
  return String(signatureDoc?.schema || '') === SIGNATURE_SCHEMA_V3;
}
