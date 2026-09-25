import { PROOF_TYPE, SIGNATURE_SCHEMA_V3 } from './constants.js';
import { assertStrictEd25519PublicKey } from './ed25519-validation.js';
import {
  assertExactKeys,
  compareProtectedManifestInput,
  protectedManifestBytes,
  protectedManifestSha256,
  validateProtectedManifestStructure,
} from './protected-manifest.js';
import { knownNetworkPassphrases } from './network.js';
import { parseSep53Signature, verifySep53Message } from './sep53.js';
import { decodeEd25519PublicKey, encodeEd25519PublicKey } from './strkey.js';
import {
  assertManifestProofEnvelope,
  computeTransactionHash,
  findValidDecoratedSignature,
  parseTransactionEnvelope,
} from './xdr.js';

export async function verifyDetachedSignature({ signatureDoc, inputContext, expectedSigner = '' }) {
  const report = createReport();
  const checked = emptyChecked();
  try {
    validateInputContext(inputContext);
    if (!isPlainObject(signatureDoc)) throw new Error('Malformed signature document: expected JSON object.');
    if (signatureDoc.schema === SIGNATURE_SCHEMA_V3) {
      return await verifyV3({ report, checked, signatureDoc, inputContext, expectedSigner });
    }
    report.fail(`Unsupported schema: ${String(signatureDoc.schema || '(missing)')}`);
  } catch (err) {
    report.fail(err instanceof Error ? err.message : String(err));
  }
  return report.finish({ signer: String(signatureDoc?.signer || ''), checked });
}

async function verifyV3({ report, checked, signatureDoc, inputContext, expectedSigner }) {
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
  assertExactKeys(signatureDoc, expectedTopKeys, 'signature document');
  const proofField = proofType === PROOF_TYPE.SEP53_MESSAGE ? 'signatureB64' : 'signedXdr';
  if (typeof signatureDoc[proofField] !== 'string') throw new Error(`${proofField} must be a string.`);

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
    safe = assertManifestProofEnvelope(parsed, manifestDigest);
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

function validateSigner({ report, signatureDoc }) {
  const address = typeof signatureDoc.signer === 'string' ? signatureDoc.signer : '';
  if (!address || address !== address.trim()) throw new Error('Signer field is missing or non-canonical.');
  const publicBytes = decodeEd25519PublicKey(address);
  assertStrictEd25519PublicKey(publicBytes);
  report.ok('Document signer address and strict Ed25519 public-point policy are valid.');
  return { address, publicBytes };
}

function validateExpectedSigner({ report, expectedSigner, actualSigner }) {
  if (typeof expectedSigner !== 'string') {
    report.contextMismatch('Expected signer must be a string.');
    return;
  }
  const expected = expectedSigner.trim();
  if (!expected) {
    report.warn('No trusted expected signer was supplied. The signature verifies under the document\'s public key; signer identity has not been confirmed.');
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
          : contextMatches === null
            ? 'SIGNER_UNCONFIRMED'
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
    `Expected Signer Matches: ${report.signatureValid && report.contextMatches === null ? 'NOT SUPPLIED' : formatCheckState(report.contextMatches)}`,
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

function formatCheckState(value) {
  if (value === true) return 'YES';
  if (value === false) return 'NO';
  return 'NOT CHECKED';
}

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
