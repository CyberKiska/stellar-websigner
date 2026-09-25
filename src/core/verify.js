import {
  HASH_ALG,
  LEGACY_V2_DEPRECATED_SINCE,
  LEGACY_V2_REMOVAL_NOT_BEFORE,
  LEGACY_V2_REMOVAL_VERSION,
  MANAGE_DATA_NAME,
  PAYLOAD_TYPE,
  PROOF_TYPE,
  SIGNATURE_SCHEME,
  SIGNATURE_SCHEMA_V2,
  SIGNATURE_SCHEMA_V3,
} from './constants.js';
import { bytesEqual, hexToBytes } from './bytes.js';
import { assertStrictEd25519PublicKey } from './ed25519-validation.js';
import { parseHashEntries, digestForHashAlgorithm, hashAlgorithmFromManageDataName } from './message.js';
import { knownNetworkPassphrases, networkHintFromPassphrase } from './network.js';
import {
  assertExactKeys,
  compareProtectedManifestInput,
  protectedManifestBytes,
  protectedManifestSha256,
  validateProtectedManifestStructure,
} from './protected-manifest.js';
import { parseSep53Signature, readInputContextBytes, verifySep53Message } from './sep53.js';
import { decodeEd25519PublicKey, encodeEd25519PublicKey } from './strkey.js';
import {
  assertSafeManageDataEnvelope,
  computeTransactionHash,
  findValidDecoratedSignature,
  parseTransactionEnvelope,
} from './xdr.js';

const V2_PROFILES = Object.freeze([
  {
    id: 'v2-sep53-content-only',
    proofType: PROOF_TYPE.SEP53_MESSAGE,
    payloadType: PAYLOAD_TYPE.RAW_BYTES,
    signatureScheme: SIGNATURE_SCHEME.SEP53_SHA256_ED25519,
    keys: ['schema', 'signer', 'proofType', 'payloadType', 'signatureScheme', 'input', 'hashes', 'signatureB64'],
  },
  {
    id: 'v2-xdr-content-digests-only',
    proofType: PROOF_TYPE.XDR_ENVELOPE,
    payloadType: PAYLOAD_TYPE.DETACHED_DIGESTS,
    signatureScheme: SIGNATURE_SCHEME.TX_ENVELOPE_ED25519,
    keys: [
      'schema',
      'signer',
      'proofType',
      'payloadType',
      'signatureScheme',
      'network',
      'hashes',
      'manageData',
      'txSourceAccount',
      'signedXdr',
      'input',
    ],
  },
]);

export async function verifyDetachedSignature({ signatureDoc, inputContext, expectedSigner = '', strict = true }) {
  const report = createReport();
  const checked = emptyChecked();
  try {
    validateInputContext(inputContext);
    if (!isPlainObject(signatureDoc)) throw new Error('Malformed signature document: expected JSON object.');
    if (signatureDoc.schema === SIGNATURE_SCHEMA_V3) {
      return await verifyV3({ report, checked, signatureDoc, inputContext, expectedSigner, strict });
    }
    if (signatureDoc.schema === SIGNATURE_SCHEMA_V2) {
      return await verifyV2({ report, checked, signatureDoc, inputContext, expectedSigner, strict });
    }
    report.fail(`Unsupported schema: ${String(signatureDoc.schema || '(missing)')}`);
  } catch (err) {
    report.fail(err instanceof Error ? err.message : String(err));
  }
  return report.finish({ signer: String(signatureDoc?.signer || ''), checked });
}

async function verifyV3({ report, checked, signatureDoc, inputContext, expectedSigner, strict }) {
  const signer = validateSigner({ report, signatureDoc });
  checked.schema = SIGNATURE_SCHEMA_V3;
  const proofType = signatureDoc.protected?.proofType;
  if (proofType !== PROOF_TYPE.SEP53_MESSAGE && proofType !== PROOF_TYPE.XDR_ENVELOPE) {
    throw new Error('Protected proofType is unsupported.');
  }
  const expectedTopKeys =
    proofType === PROOF_TYPE.SEP53_MESSAGE
      ? ['schema', 'signer', 'protected', 'signatureB64']
      : ['schema', 'signer', 'protected', 'signedXdr'];
  if (strict) assertExactKeys(signatureDoc, expectedTopKeys, 'signature document');

  validateProtectedManifestStructure({
    manifest: signatureDoc.protected,
    expectedProofType: proofType,
    expectedSigner: signer.address,
  });
  checked.mode = proofType === PROOF_TYPE.SEP53_MESSAGE ? 'protected-manifest-sep53' : 'protected-manifest-xdr';
  checked.proofType = proofType;
  checked.payloadType = signatureDoc.protected.payloadType;
  checked.signatureScheme = signatureDoc.protected.signatureScheme;
  checked.hashes = signatureDoc.protected.hashes.map((entry) => ({ ...entry }));
  report.ok('Protected manifest schema, protocol metadata, and canonical hash set are structurally valid.');

  let proofValid;
  if (proofType === PROOF_TYPE.SEP53_MESSAGE) {
    proofValid = await verifyV3Sep53({ report, signatureDoc, signer, checked });
  } else {
    proofValid = await verifyV3Xdr({ report, signatureDoc, signer });
  }
  if (proofValid) {
    report.markSignatureValid();
    validateExpectedSigner({ report, expectedSigner, actualSigner: signer.address });
    const comparison = compareProtectedManifestInput({ manifest: signatureDoc.protected, inputContext });
    for (const error of comparison.errors) report.inputMismatch(error);
    for (const warning of comparison.warnings) report.warn(warning);
    if (comparison.matches) {
      report.markInputMatches();
      report.ok('Selected input type, identity, size, and both content digests match the signed manifest.');
    }
  }
  return report.finish({ signer: signer.address, checked });
}

async function verifyV3Sep53({ report, signatureDoc, signer, checked }) {
  let signatureBytes;
  try {
    signatureBytes = parseSep53Signature(signatureDoc.signatureB64);
  } catch (err) {
    report.fail(`Malformed signature: ${err.message}`);
    return false;
  }
  const manifestBytes = protectedManifestBytes(signatureDoc.protected);
  checked.messageBytesLength = manifestBytes.length;
  const valid = await verifySep53Message({
    publicKeyBytes: signer.publicBytes,
    messageBytes: manifestBytes,
    signatureBytes,
  });
  if (valid) {
    report.ok('SEP-53 signature over the canonical protected manifest is valid.');
    return true;
  }
  report.fail('SEP-53 protected-manifest signature verification failed.');
  return false;
}

async function verifyV3Xdr({ report, signatureDoc, signer }) {
  let parsed;
  try {
    parsed = parseTransactionEnvelope(signatureDoc.signedXdr);
  } catch (err) {
    report.fail(`Malformed signedXdr: ${err.message}`);
    return false;
  }
  const manifestDigest = await protectedManifestSha256(signatureDoc.protected);
  let safe;
  try {
    safe = assertSafeManageDataEnvelope(parsed, {
      expectedEntries: [{ dataName: MANAGE_DATA_NAME.MANIFEST_SHA256, dataValue: manifestDigest }],
    });
  } catch (err) {
    report.fail(err.message);
    return false;
  }
  const sourceAddress = encodeEd25519PublicKey(safe.sourceAccount);
  if (sourceAddress !== signer.address) {
    report.fail(`signedXdr sourceAccount mismatch: signer=${signer.address}, sourceAccount=${sourceAddress}.`);
    return false;
  }
  const passphrase = signatureDoc.protected.network.passphrase;
  const txHash = await computeTransactionHash(parsed.txXdr, passphrase);
  let match;
  try {
    match = await findValidDecoratedSignature(parsed.signatures, signer.publicBytes, txHash);
  } catch (err) {
    report.fail(`Invalid signedXdr signature set: ${err.message}`);
    return false;
  }
  if (match) {
    report.ok('XDR signature and protected-manifest digest binding are valid.');
    return true;
  }
  for (const alternative of knownNetworkPassphrases()) {
    if (alternative === passphrase) continue;
    const alternativeHash = await computeTransactionHash(parsed.txXdr, alternative);
    if (await findValidDecoratedSignature(parsed.signatures, signer.publicBytes, alternativeHash)) {
      report.fail('Wrong network passphrase: signature is valid under a different known network passphrase.');
      return false;
    }
  }
  report.fail('No valid signer signature found in signedXdr.');
  return false;
}

async function verifyV2({ report, checked, signatureDoc, inputContext, expectedSigner, strict }) {
  checked.schema = SIGNATURE_SCHEMA_V2;
  const signer = validateSigner({ report, signatureDoc });
  const profile = V2_PROFILES.find(
    (item) =>
      signatureDoc.proofType === item.proofType &&
      signatureDoc.payloadType === item.payloadType &&
      signatureDoc.signatureScheme === item.signatureScheme
  );
  if (!profile) throw new Error('Unsupported v2 signature profile.');
  if (strict) assertExactKeys(signatureDoc, profile.keys, 'legacy signature document');
  checked.mode = profile.id;
  checked.proofType = signatureDoc.proofType;
  checked.payloadType = signatureDoc.payloadType;
  checked.signatureScheme = signatureDoc.signatureScheme;
  report.warn(
    `Legacy v2 compatibility (deprecated ${LEGACY_V2_DEPRECATED_SINCE}): only content bytes/digests are authenticated; surrounding metadata is not signed. Verification is scheduled for removal in v${LEGACY_V2_REMOVAL_VERSION}, no earlier than ${LEGACY_V2_REMOVAL_NOT_BEFORE}.`
  );

  if (strict) {
    if (!Array.isArray(signatureDoc.hashes)) throw new Error('Legacy hashes must be an array.');
    signatureDoc.hashes.forEach((entry, index) => {
      assertExactKeys(entry, ['alg', 'hex'], `legacy hashes[${index}]`);
    });
  }
  const entries = parseHashEntries(signatureDoc);
  assertExactHashSet(entries);
  checked.hashes = entries.map((entry) => ({ ...entry }));
  validateLegacyInputStructure(signatureDoc.input);

  let proofValid;
  if (profile.id === 'v2-sep53-content-only') {
    const signatureBytes = parseSep53Signature(signatureDoc.signatureB64);
    const messageBytes = readInputContextBytes(inputContext);
    checked.messageBytesLength = messageBytes.length;
    const valid = await verifySep53Message({
      publicKeyBytes: signer.publicBytes,
      messageBytes,
      signatureBytes,
    });
    if (valid) {
      report.ok('Legacy SEP-53 content signature is valid for the selected bytes.');
      proofValid = true;
    } else {
      report.fail('SEP-53 content signature verification failed.');
      proofValid = false;
    }
  } else {
    proofValid = await verifyV2Xdr({ report, signatureDoc, signer });
  }

  if (proofValid) {
    report.markSignatureValid();
    validateExpectedSigner({ report, expectedSigner, actualSigner: signer.address });
    for (const entry of entries) {
      const recomputed = digestForHashAlgorithm(inputContext.digests, entry.alg);
      if (entry.hex !== recomputed.hex) report.inputMismatch(`Legacy digest mismatch for ${entry.alg}.`);
      else report.ok(`Legacy digest match for ${entry.alg}.`);
    }
    compareLegacyInput({ report, input: signatureDoc.input, inputContext });
    if (profile.id === 'v2-xdr-content-digests-only') {
      compareLegacyManageDataDigests({ report, signatureDoc, inputContext });
    }
    report.markInputMatches();
  }
  return report.finish({ signer: signer.address, checked });
}

async function verifyV2Xdr({ report, signatureDoc, signer }) {
  assertExactKeys(signatureDoc.network, ['passphrase', 'hint'], 'legacy network');
  assertExactKeys(signatureDoc.manageData, ['entries'], 'legacy manageData');
  if (signatureDoc.txSourceAccount !== signer.address) throw new Error('Legacy txSourceAccount is required and must match signer.');
  const declared = signatureDoc.manageData.entries;
  if (!Array.isArray(declared) || declared.length !== 2) throw new Error('Legacy manageData.entries must contain exactly two entries.');
  const expectedEntries = declared.map((entry, index) => {
    assertExactKeys(entry, ['name', 'alg', 'digestHex'], `legacy manageData.entries[${index}]`);
    const alg = hashAlgorithmFromManageDataName(entry.name);
    if (!alg || alg !== entry.alg) throw new Error('Legacy ManageData name/algorithm mismatch.');
    const digestHexLength = alg === HASH_ALG.SHA256 ? 64 : 128;
    if (typeof entry.digestHex !== 'string' || entry.digestHex.length !== digestHexLength || !/^[0-9a-f]+$/.test(entry.digestHex)) {
      throw new Error(`Legacy ManageData ${alg} digest encoding is invalid.`);
    }
    return { dataName: entry.name, dataValue: hexToBytes(entry.digestHex) };
  });
  const parsed = parseTransactionEnvelope(signatureDoc.signedXdr);
  const safe = assertSafeManageDataEnvelope(parsed, { expectedEntries });
  if (encodeEd25519PublicKey(safe.sourceAccount) !== signer.address) throw new Error('Legacy XDR source does not match signer.');
  const passphrase = String(signatureDoc.network.passphrase || '');
  if (!passphrase || signatureDoc.network.hint !== networkHintFromPassphrase(passphrase)) {
    throw new Error('Legacy network fields are invalid.');
  }
  const txHash = await computeTransactionHash(parsed.txXdr, passphrase);
  const match = await findValidDecoratedSignature(parsed.signatures, signer.publicBytes, txHash);
  if (!match) {
    report.fail('No valid signer signature found in legacy signedXdr.');
    return false;
  }
  report.ok('Legacy XDR signature and declared digest operations are valid.');
  return true;
}

function validateSigner({ report, signatureDoc }) {
  const address = typeof signatureDoc.signer === 'string' ? signatureDoc.signer : '';
  if (!address || address !== address.trim()) throw new Error('Signer field is missing or non-canonical.');
  const publicBytes = decodeEd25519PublicKey(address);
  assertStrictEd25519PublicKey(publicBytes);
  report.ok('Document signer address and strict Ed25519 public-point policy are valid.');
  return { address, publicBytes };
}

function validateExpectedSigner({ report, expectedSigner, actualSigner }) {
  const expected = String(expectedSigner || '').trim();
  if (!expected) {
    // A self-asserted signer is not an identity check; leave the context result NOT CHECKED.
    report.warn('No expected signer was supplied; the signer identity was not checked.');
    return;
  }
  try {
    const publicBytes = decodeEd25519PublicKey(expected);
    assertStrictEd25519PublicKey(publicBytes);
  } catch (err) {
    report.contextMismatch(`Expected signer is invalid: ${err.message}`);
    return;
  }
  if (expected !== actualSigner) {
    report.contextMismatch(`Wrong signer: expected ${expected}, got ${actualSigner}.`);
    return;
  }
  report.ok('Document signer matches the externally expected signer.');
  report.markContextMatches();
}

function validateLegacyInputStructure(input) {
  if (!isPlainObject(input)) throw new Error('Legacy input descriptor is required.');
  if (input.type === 'file') {
    assertExactKeys(input, ['type', 'name', 'size'], 'legacy input');
  } else if (input.type === 'text') {
    assertExactKeys(input, ['type', 'size'], 'legacy input');
  } else {
    throw new Error('Legacy input type is invalid.');
  }
  if (!Number.isSafeInteger(input.size) || input.size < 0) {
    throw new Error('Legacy input size is invalid.');
  }
}

function compareLegacyInput({ report, input, inputContext }) {
  if (input.type !== inputContext.type) report.inputMismatch('Legacy input type mismatch.');
  if (input.type === 'file' && inputContext.type === 'file' && input.name !== inputContext.fileName) {
    report.inputMismatch('Legacy input filename mismatch.');
  }
  if (input.size !== inputContext.fileSize) {
    report.inputMismatch('Legacy input size mismatch.');
  }
}

function compareLegacyManageDataDigests({ report, signatureDoc, inputContext }) {
  for (const entry of signatureDoc.manageData.entries) {
    const digest = digestForHashAlgorithm(inputContext.digests, entry.alg);
    if (entry.digestHex !== digest.hex) {
      report.inputMismatch(`Legacy ManageData declared digest mismatch for ${entry.alg}.`);
    } else {
      report.ok(`Legacy ManageData digest match for ${entry.alg}.`);
    }
  }
}

function assertExactHashSet(entries) {
  if (
    entries.length !== 2 ||
    entries[0].alg !== HASH_ALG.SHA256 ||
    entries[1].alg !== HASH_ALG.SHA3_512
  ) {
    throw new Error('Signature hashes must contain exactly SHA-256 and SHA3-512 in canonical order.');
  }
}

function createReport() {
  const details = [];
  const errors = [];
  const warnings = [];
  const signatureErrors = [];
  const inputErrors = [];
  const contextErrors = [];
  let signatureValid = false;
  let inputMatches = null;
  let contextMatches = null;
  return {
    ok(message) {
      details.push(`OK: ${message}`);
    },
    fail(message) {
      details.push(`FAIL: ${message}`);
      errors.push(message);
      signatureErrors.push(message);
      signatureValid = false;
    },
    markSignatureValid() {
      if (signatureErrors.length > 0) throw new Error('Cannot mark a failed signature proof as valid.');
      signatureValid = true;
    },
    markInputMatches() {
      if (inputMatches === null) inputMatches = true;
    },
    markContextMatches() {
      if (contextMatches === null) contextMatches = true;
    },
    inputMismatch(message) {
      details.push(`MISMATCH[input]: ${message}`);
      errors.push(message);
      inputErrors.push(message);
      inputMatches = false;
    },
    contextMismatch(message) {
      details.push(`MISMATCH[context]: ${message}`);
      errors.push(message);
      contextErrors.push(message);
      contextMatches = false;
    },
    warn(message) {
      details.push(`WARN: ${message}`);
      warnings.push(message);
    },
    finish({ signer, checked }) {
      const valid = signatureValid && inputMatches === true && contextMatches === true && signatureErrors.length === 0;
      const summary = !signatureValid || signatureErrors.length > 0
        ? 'INVALID'
        : inputMatches === false || contextMatches === false
          ? 'MISMATCH'
          : inputMatches !== true || contextMatches !== true
            ? 'SIGNER_UNVERIFIED'
            : warnings.length > 0
              ? 'VALID_WITH_WARNINGS'
              : 'VALID';
      return {
        valid,
        signatureValid,
        inputMatches,
        contextMatches,
        signer,
        checked,
        details,
        errors,
        signatureErrors,
        inputErrors,
        contextErrors,
        warnings,
        summary,
      };
    },
  };
}

function emptyChecked() {
  return { mode: '', schema: '', proofType: '', payloadType: '', signatureScheme: '', hashes: [] };
}

export function validateInputContext(inputContext) {
  if (!isPlainObject(inputContext)) throw new Error('Input context is required.');
  if (inputContext.type !== 'file' && inputContext.type !== 'text') throw new Error('Input context type must be file or text.');
  if (!inputContext.digests?.sha256 || !inputContext.digests?.sha3_512) throw new Error('Input context digests are missing.');
  if (!Number.isSafeInteger(inputContext.fileSize) || inputContext.fileSize < 0) throw new Error('Input context size is invalid.');
}

export function diagnosticsForDisplay(report) {
  const unauthenticated = report.signatureValid ? '' : ' (claimed, not authenticated)';
  const lines = [
    `Result: ${report.summary || (report.valid ? 'VALID' : 'INVALID')}`,
    `Signature Valid: ${report.signatureValid ? 'YES' : 'NO'}`,
    `Selected Input Matches: ${formatCheckState(report.inputMatches)}`,
    `Expected Signer Matches: ${formatCheckState(report.contextMatches)}`,
    `Signer${unauthenticated}: ${report.signer || '-'}`,
    `Schema: ${report.checked?.schema || '-'}`,
    `Proof Type: ${report.checked?.proofType || '-'}`,
    `Payload Type: ${report.checked?.payloadType || '-'}`,
    `Signature Scheme: ${report.checked?.signatureScheme || '-'}`,
    `Mode: ${report.checked?.mode || '-'}`,
  ];
  if (report.checked?.hashes?.length) {
    lines.push(`Hashes${unauthenticated}:`);
    for (const item of report.checked.hashes) lines.push(`  ${item.alg}: ${item.hex}`);
  } else lines.push('Hashes: -');
  if (Number.isInteger(report.checked?.messageBytesLength)) lines.push(`Signed Manifest Bytes: ${report.checked.messageBytesLength}`);
  lines.push('', ...report.details);
  return lines.join('\n');
}

export function signatureDocRequiresInputBytes(signatureDoc) {
  return signatureDoc?.schema === SIGNATURE_SCHEMA_V2 && signatureDoc?.proofType === PROOF_TYPE.SEP53_MESSAGE;
}

export function sameDigestBytes(a, b) {
  return bytesEqual(a, b);
}

function formatCheckState(value) {
  if (value === true) return 'YES';
  if (value === false) return 'NO';
  return 'NOT CHECKED';
}

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
