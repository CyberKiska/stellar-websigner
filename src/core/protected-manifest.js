import {
  HASH_ALG,
  PAYLOAD_TYPE,
  PROOF_TYPE,
  SIGNATURE_APPLICATION,
  SIGNATURE_PURPOSE,
  SIGNATURE_SCHEME,
} from './constants.js';
import { canonicalJsonStringify } from './canonical-json.js';
import { utf8ToBytes } from './bytes.js';
import { sha256 } from './hash.js';
import { buildHashEntriesFromDigests, buildInputDescriptor } from './message.js';
import { networkHintFromPassphrase } from './network.js';

const HASH_ALGORITHMS = Object.freeze([HASH_ALG.SHA256, HASH_ALG.SHA3_512]);

export function buildProtectedManifest({ inputContext, signer, proofType, networkPassphrase = '' }) {
  const normalizedSigner = String(signer || '').trim();
  if (!normalizedSigner) throw new Error('Protected manifest signer is required.');
  if (proofType !== PROOF_TYPE.SEP53_MESSAGE && proofType !== PROOF_TYPE.XDR_ENVELOPE) {
    throw new Error(`Unsupported protected-manifest proof type: ${proofType}`);
  }

  const manifest = {
    application: SIGNATURE_APPLICATION,
    formatVersion: 1,
    purpose: SIGNATURE_PURPOSE,
    proofType,
    payloadType: PAYLOAD_TYPE.PROTECTED_MANIFEST,
    signatureScheme:
      proofType === PROOF_TYPE.SEP53_MESSAGE
        ? SIGNATURE_SCHEME.SEP53_SHA256_ED25519
        : SIGNATURE_SCHEME.TX_ENVELOPE_ED25519,
    signer: normalizedSigner,
    input: buildInputDescriptor({
      type: inputContext.type,
      fileName: inputContext.fileName,
      fileSize: inputContext.fileSize,
      mediaType: inputContext.mediaType,
    }),
    hashes: buildHashEntriesFromDigests(inputContext.digests),
  };

  if (proofType === PROOF_TYPE.XDR_ENVELOPE) {
    const passphrase = String(networkPassphrase || '').trim();
    if (!passphrase) throw new Error('Protected manifest network passphrase is required.');
    manifest.network = {
      passphrase,
      hint: networkHintFromPassphrase(passphrase),
    };
  }
  validateProtectedManifest({
    manifest,
    inputContext,
    expectedProofType: proofType,
    expectedSigner: normalizedSigner,
  });
  return manifest;
}

export function protectedManifestBytes(manifest) {
  return utf8ToBytes(canonicalJsonStringify(manifest));
}

export async function protectedManifestSha256(manifest) {
  return sha256(protectedManifestBytes(manifest));
}

export function validateProtectedManifest({ manifest, inputContext, expectedProofType, expectedSigner }) {
  assertPlainObject(manifest, 'protected');
  const expectedTopKeys = [
    'application',
    'formatVersion',
    'purpose',
    'proofType',
    'payloadType',
    'signatureScheme',
    'signer',
    'input',
    'hashes',
    ...(expectedProofType === PROOF_TYPE.XDR_ENVELOPE ? ['network'] : []),
  ];
  assertExactKeys(manifest, expectedTopKeys, 'protected');
  if (manifest.application !== SIGNATURE_APPLICATION) throw new Error('Protected application is invalid.');
  if (manifest.formatVersion !== 1) throw new Error('Protected formatVersion is invalid.');
  if (manifest.purpose !== SIGNATURE_PURPOSE) throw new Error('Protected purpose is invalid.');
  if (manifest.proofType !== expectedProofType) throw new Error('Protected proofType is invalid.');
  if (manifest.payloadType !== PAYLOAD_TYPE.PROTECTED_MANIFEST) throw new Error('Protected payloadType is invalid.');
  const expectedScheme =
    expectedProofType === PROOF_TYPE.SEP53_MESSAGE
      ? SIGNATURE_SCHEME.SEP53_SHA256_ED25519
      : SIGNATURE_SCHEME.TX_ENVELOPE_ED25519;
  if (manifest.signatureScheme !== expectedScheme) throw new Error('Protected signatureScheme is invalid.');
  if (manifest.signer !== expectedSigner) throw new Error('Protected signer does not match document signer.');

  validateInput(manifest.input, inputContext);
  validateHashes(manifest.hashes, inputContext.digests);

  if (expectedProofType === PROOF_TYPE.XDR_ENVELOPE) {
    assertPlainObject(manifest.network, 'protected.network');
    assertExactKeys(manifest.network, ['passphrase', 'hint'], 'protected.network');
    const passphrase = String(manifest.network.passphrase || '');
    if (!passphrase || passphrase !== passphrase.trim() || passphrase.length > 255) {
      throw new Error('Protected network passphrase is invalid.');
    }
    if (manifest.network.hint !== networkHintFromPassphrase(passphrase)) {
      throw new Error('Protected network hint is invalid.');
    }
  }
  // Also rejects non-I-JSON values and malformed Unicode before verification.
  protectedManifestBytes(manifest);
}

function validateInput(input, inputContext) {
  assertPlainObject(input, 'protected.input');
  if (inputContext.type === 'file') {
    assertExactKeys(input, ['type', 'name', 'namePolicy', 'size', 'mediaType'], 'protected.input');
    if (input.type !== 'file') throw new Error('Protected input type does not match selected file.');
    if (input.namePolicy !== 'exact-basename') throw new Error('Protected filename policy is invalid.');
    validateFileName(input.name);
    if (input.name !== String(inputContext.fileName || '')) {
      throw new Error(`Protected filename mismatch: expected ${input.name}, received ${inputContext.fileName || ''}.`);
    }
  } else if (inputContext.type === 'text') {
    assertExactKeys(input, ['type', 'size', 'mediaType', 'textEncoding'], 'protected.input');
    if (input.type !== 'text') throw new Error('Protected input type does not match selected text.');
    if (input.textEncoding !== 'utf-8-dom-value-no-normalization') {
      throw new Error('Protected text encoding policy is invalid.');
    }
  } else {
    throw new Error('Selected input type is invalid.');
  }
  if (!Number.isSafeInteger(input.size) || input.size < 0 || input.size !== inputContext.fileSize) {
    throw new Error('Protected input size does not match selected input.');
  }
  const expectedMediaType = normalizedMediaType(inputContext);
  if (input.mediaType !== expectedMediaType) throw new Error('Protected input mediaType does not match selected input.');
}

function validateHashes(hashes, digests) {
  if (!Array.isArray(hashes) || hashes.length !== HASH_ALGORITHMS.length) {
    throw new Error('Protected hashes must contain exactly SHA-256 and SHA3-512.');
  }
  for (let i = 0; i < HASH_ALGORITHMS.length; i += 1) {
    const entry = hashes[i];
    assertPlainObject(entry, `protected.hashes[${i}]`);
    assertExactKeys(entry, ['alg', 'hex'], `protected.hashes[${i}]`);
    const alg = HASH_ALGORITHMS[i];
    if (entry.alg !== alg) throw new Error(`Protected hash order/algorithm mismatch at index ${i}.`);
    const expected = alg === HASH_ALG.SHA256 ? digests.sha256 : digests.sha3_512;
    if (entry.hex !== expected.hex) throw new Error(`Protected ${alg} digest does not match selected input.`);
  }
}

function normalizedMediaType(inputContext) {
  if (inputContext.type === 'text') return 'text/plain;charset=utf-8';
  const value = String(inputContext.mediaType || '').trim().toLowerCase();
  return value || 'application/octet-stream';
}

export function validateFileName(name) {
  const value = String(name || '');
  if (!value || value.length > 255 || value === '.' || value === '..' || /[\\/\u0000]/.test(value)) {
    throw new Error('Protected filename must be a safe basename of 1..255 characters.');
  }
}

function assertPlainObject(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
}

export function assertExactKeys(value, expectedKeys, path) {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${path} has missing or unknown fields.`);
  }
}
