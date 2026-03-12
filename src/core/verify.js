import {
  HASH_ALG,
  PAYLOAD_TYPE,
  PROOF_TYPE,
  SIGNATURE_SCHEME,
  SIGNATURE_SCHEMA_V2,
} from './constants.js';
import { bytesEqual } from './bytes.js';
import { decodeEd25519PublicKey, encodeEd25519PublicKey } from './strkey.js';
import {
  assertSafeManageDataEnvelope,
  computeTransactionHash,
  findValidDecoratedSignature,
  parseTransactionEnvelope,
} from './xdr.js';
import {
  digestForHashAlgorithm,
  hashAlgorithmFromManageDataName,
  normalizeHashAlgorithmName,
  parseHashEntries,
} from './message.js';
import { knownNetworkPassphrases, networkHintFromPassphrase } from './network.js';
import { parseSep53Signature, readInputContextBytes, verifySep53Message } from './sep53.js';

const SUPPORTED_PROFILES = Object.freeze([
  Object.freeze({
    id: 'sep53-message',
    proofType: PROOF_TYPE.SEP53_MESSAGE,
    payloadType: PAYLOAD_TYPE.RAW_BYTES,
    signatureScheme: SIGNATURE_SCHEME.SEP53_SHA256_ED25519,
  }),
  Object.freeze({
    id: 'xdr-envelope',
    proofType: PROOF_TYPE.XDR_ENVELOPE,
    payloadType: PAYLOAD_TYPE.DETACHED_DIGESTS,
    signatureScheme: SIGNATURE_SCHEME.TX_ENVELOPE_ED25519,
  }),
]);

export async function verifyDetachedSignature({ signatureDoc, inputContext, expectedSigner = '' }) {
  const report = createReport();
  const emptyChecked = {
    mode: '',
    schema: '',
    proofType: '',
    payloadType: '',
    signatureScheme: '',
    hashes: [],
  };

  if (!signatureDoc || typeof signatureDoc !== 'object') {
    report.fail('Malformed signature document: expected JSON object.');
    return report.finish({ signer: '', checked: emptyChecked });
  }

  const schema = String(signatureDoc.schema || '').trim();
  const isV2Schema = schema === SIGNATURE_SCHEMA_V2;
  if (!isV2Schema) {
    report.fail(`Unsupported schema: ${String(signatureDoc.schema || '(missing)')}`);
  } else {
    report.ok(`Schema accepted: ${schema}`);
  }

  const signer = String(signatureDoc.signer || '').trim();
  let signerPublicBytes = null;
  try {
    signerPublicBytes = decodeEd25519PublicKey(signer);
    report.ok('Signer address format is valid.');
  } catch (err) {
    report.fail(`Invalid signer address: ${err.message}`);
  }

  const expectedSignerTrimmed = String(expectedSigner || '').trim();
  if (expectedSignerTrimmed && signer && expectedSignerTrimmed !== signer) {
    report.fail(`Wrong signer: expected ${expectedSignerTrimmed}, got ${signer}.`);
  }

  const proofType = String(signatureDoc.proofType || '').trim();
  const payloadType = String(signatureDoc.payloadType || '').trim();
  const signatureScheme = String(signatureDoc.signatureScheme || '').trim();
  let recomputedEntries = [];
  let checked = {
    mode: '',
    schema,
    proofType,
    payloadType,
    signatureScheme,
    hashes: [],
  };

  let hashEntries;
  try {
    hashEntries = parseHashEntries(signatureDoc);
    report.ok(`Hash entries parsed: ${hashEntries.map((item) => item.alg).join(', ')}`);
  } catch (err) {
    report.fail(`Malformed hashes section: ${err.message}`);
    return report.finish({ signer, checked });
  }

  recomputedEntries = [];
  for (const entry of hashEntries) {
    const digest = digestForHashAlgorithm(inputContext.digests, entry.alg);
    const recomputed = {
      alg: digest.alg,
      hex: digest.hex,
      bytes: digest.bytes,
      manageDataName: digest.manageDataName,
    };
    recomputedEntries.push(recomputed);

    if (entry.hex !== recomputed.hex) {
      report.fail(`Digest mismatch for ${entry.alg}: signature=${entry.hex}, recomputed=${recomputed.hex}`);
    } else {
      report.ok(`Digest match for ${entry.alg}.`);
    }
  }

  checked = {
    mode: '',
    schema,
    proofType,
    payloadType,
    signatureScheme,
    hashes: recomputedEntries.map((item) => ({ alg: item.alg, hex: item.hex })),
  };

  const profile = resolveSupportedProfile({ schema, proofType, payloadType, signatureScheme });
  if (!profile) {
    report.fail(
      `Unsupported signature profile: ${proofType || '(missing)'} / ${payloadType || '(missing)'} / ${signatureScheme || '(missing)'}.`
    );
    return report.finish({ signer, checked });
  }
  report.ok(`Signature profile accepted: ${profile.id}.`);

  if (profile.id === 'sep53-message') {
    await verifyV2Sep53MessageSignatureMode({
      report,
      signatureDoc,
      signerPublicBytes,
      inputContext,
      checked,
    });
  } else if (profile.id === 'xdr-envelope') {
    await verifyXdrProofMode({
      report,
      signatureDoc,
      signer,
      signerPublicBytes,
      inputContext,
      recomputedEntries,
    });
  }

  return report.finish({ signer, checked });
}

async function verifyV2Sep53MessageSignatureMode({
  report,
  signatureDoc,
  signerPublicBytes,
  inputContext,
  checked,
}) {
  let signatureBytes;
  try {
    signatureBytes = parseSep53Signature(signatureDoc.signatureB64);
    report.ok('signatureB64 parsed successfully.');
  } catch (err) {
    report.fail(`Malformed signature: ${err.message}`);
    return;
  }

  validateInputDescriptor({
    report,
    declaredInput: signatureDoc.input && typeof signatureDoc.input === 'object' ? signatureDoc.input : null,
    inputContext,
  });

  let messageBytes;
  try {
    messageBytes = readInputContextBytes(inputContext);
    report.ok(`Input bytes loaded for SEP-53 verification (${messageBytes.length} bytes).`);
    checked.messageBytesLength = messageBytes.length;
  } catch (err) {
    report.fail(err.message);
    return;
  }

  if (!signerPublicBytes) return;

  const ok = await verifySep53Message({ publicKeyBytes: signerPublicBytes, messageBytes, signatureBytes });
  if (!ok) {
    report.fail('SEP-53 content signature verification failed.');
  } else {
    report.ok('SEP-53 content signature verification passed.');
  }
}

async function verifyXdrProofMode({
  report,
  signatureDoc,
  signer,
  signerPublicBytes,
  inputContext,
  recomputedEntries,
}) {
  const signedXdr = String(signatureDoc.signedXdr || '').trim();
  if (!signedXdr) {
    report.fail('Malformed signature: signedXdr field is missing.');
    return;
  }

  let parsed;
  try {
    parsed = parseTransactionEnvelope(signedXdr);
    report.ok('signedXdr parsed successfully.');
  } catch (err) {
    report.fail(`Malformed signedXdr: ${err.message}`);
    return;
  }

  let declaredManageDataEntries;
  try {
    declaredManageDataEntries = parseDeclaredManageDataEntries(signatureDoc.manageData);
  } catch (err) {
    report.fail(`Malformed manageData section: ${err.message}`);
    return;
  }
  if (declaredManageDataEntries.length === 0) {
    report.fail('manageData.entries must contain at least one entry.');
    return;
  }
  let safeOp;
  try {
    safeOp = assertSafeManageDataEnvelope(parsed, {
      expectedEntries: declaredManageDataEntries.length
        ? declaredManageDataEntries.map((item) => ({ dataName: item.name }))
        : undefined,
    });
    report.ok('Transaction structure is safe for signing/verification policy.');
  } catch (err) {
    report.fail(err.message);
    return;
  }

  const sourceAddress = encodeEd25519PublicKey(safeOp.sourceAccount);
  if (!signer) {
    report.fail('Signer field is missing in signature document.');
    return;
  }

  const declaredTxSource = String(signatureDoc.txSourceAccount || '').trim();
  if (declaredTxSource && declaredTxSource !== sourceAddress) {
    report.fail(
      `txSourceAccount mismatch: signature document declares ${declaredTxSource}, signedXdr has ${sourceAddress}.`
    );
    return;
  }

  if (sourceAddress !== signer) {
    report.fail(`signedXdr sourceAccount mismatch: signer=${signer}, sourceAccount=${sourceAddress}.`);
    return;
  }
  report.ok('signedXdr sourceAccount matches signer field.');

  if (safeOp.manageDataEntries.length === 0) {
    report.fail('signedXdr has no ManageData entries.');
    return;
  }

  if (safeOp.manageDataEntries.length !== recomputedEntries.length) {
    report.fail('signedXdr ManageData count must exactly match hashes[] count.');
    return;
  }

  const seenManageDataNames = new Set();
  const seenAlgorithms = new Set();
  for (const txEntry of safeOp.manageDataEntries) {
    if (seenManageDataNames.has(txEntry.dataName)) {
      report.fail(`Duplicate ManageData name in signedXdr: ${txEntry.dataName}.`);
      return;
    }
    seenManageDataNames.add(txEntry.dataName);

    const declared = declaredManageDataEntries.find((item) => item.name === txEntry.dataName);
    const boundAlg = declared?.alg || hashAlgorithmFromManageDataName(txEntry.dataName);

    if (!boundAlg) {
      report.fail(`Cannot determine hash algorithm bound to ManageData ${txEntry.dataName}.`);
      return;
    }

    if (seenAlgorithms.has(boundAlg)) {
      report.fail(`Duplicate ManageData algorithm binding: ${boundAlg}.`);
      return;
    }
    seenAlgorithms.add(boundAlg);

    const expectedValueLength = boundAlg === HASH_ALG.SHA3_512 ? 64 : 32;
    if (txEntry.dataValue.length !== expectedValueLength) {
      report.fail(
        `ManageData value length mismatch for ${boundAlg}: expected ${expectedValueLength} bytes, got ${txEntry.dataValue.length}.`
      );
      return;
    }

    const boundDigest = digestForHashAlgorithm(inputContext.digests, boundAlg);
    if (!bytesEqual(txEntry.dataValue, boundDigest.bytes)) {
      report.fail(`ManageData digest mismatch for ${boundAlg}.`);
      return;
    }

    if (declared?.digestHex && declared.digestHex !== boundDigest.hex) {
      report.fail(`manageData.digestHex mismatch for ${txEntry.dataName}.`);
      return;
    }

    const boundEntry = recomputedEntries.find((entry) => entry.alg === boundAlg);
    if (!boundEntry) {
      report.fail(`hashes[] does not include bound ManageData algorithm ${boundAlg}.`);
      return;
    }

    report.ok(`ManageData digest matches recomputed ${boundAlg} digest.`);
  }

  for (const hashEntry of recomputedEntries) {
    if (!seenAlgorithms.has(hashEntry.alg)) {
      report.fail(`signedXdr is missing ManageData entry for ${hashEntry.alg}.`);
      return;
    }
  }

  if (!signerPublicBytes) return;

  const passphrase = String(signatureDoc.network?.passphrase || '').trim();
  if (!passphrase) {
    report.fail('network.passphrase is missing.');
    return;
  }
  const declaredHint = String(signatureDoc.network?.hint || '').trim();
  const expectedHint = networkHintFromPassphrase(passphrase);
  if (declaredHint && declaredHint !== expectedHint) {
    report.warn(`network.hint mismatch: expected ${expectedHint}, got ${declaredHint}.`);
  } else {
    report.ok(`Network hint accepted: ${declaredHint || expectedHint}.`);
  }

  const txHash = await computeTransactionHash(parsed.txXdr, passphrase);
  const match = await findValidDecoratedSignature(parsed.signatures, signerPublicBytes, txHash);
  if (match) {
    report.ok('Decorated signature is valid for transaction hash and signer.');
    return;
  }

  for (const alternative of knownNetworkPassphrases()) {
    if (alternative === passphrase) continue;
    const altHash = await computeTransactionHash(parsed.txXdr, alternative);
    const altMatch = await findValidDecoratedSignature(parsed.signatures, signerPublicBytes, altHash);
    if (altMatch) {
      report.fail('Wrong network passphrase: signature is valid under a different known network passphrase.');
      return;
    }
  }

  report.fail('No valid signer signature found in signedXdr (malformed or wrong signature).');
}

function createReport() {
  const details = [];
  const errors = [];
  const warnings = [];

  function ok(message) {
    details.push(`OK: ${message}`);
  }

  function fail(message) {
    details.push(`FAIL: ${message}`);
    errors.push(message);
  }

  function warn(message) {
    details.push(`WARN: ${message}`);
    warnings.push(message);
  }

  function finish({ signer, checked }) {
    return {
      valid: errors.length === 0,
      signer,
      checked,
      details,
      errors,
      warnings,
      summary: errors.length === 0 ? 'VALID' : 'INVALID',
    };
  }

  return { ok, fail, warn, finish };
}

export function validateInputContext(inputContext) {
  if (!inputContext || typeof inputContext !== 'object') {
    throw new Error('Input context is required.');
  }
  if (inputContext.type !== 'file' && inputContext.type !== 'text') {
    throw new Error('Input context type must be file or text.');
  }
  if (!inputContext.digests?.sha256 || !inputContext.digests?.sha3_512) {
    throw new Error('Input context digests are missing.');
  }
  if (inputContext.type === 'file' && (!Number.isInteger(inputContext.fileSize) || inputContext.fileSize < 0)) {
    throw new Error('Input context fileSize is invalid.');
  }
}

export function diagnosticsForDisplay(report) {
  const lines = [];
  lines.push(`Result: ${report.valid ? 'VALID' : 'INVALID'}`);
  lines.push(`Signer: ${report.signer || '-'}`);
  lines.push(`Schema: ${report.checked?.schema || '-'}`);
  lines.push(`Proof Type: ${report.checked?.proofType || '-'}`);
  lines.push(`Payload Type: ${report.checked?.payloadType || '-'}`);
  lines.push(`Signature Scheme: ${report.checked?.signatureScheme || '-'}`);
  lines.push(`Mode: ${report.checked?.mode || '-'}`);
  if (Array.isArray(report.checked?.hashes) && report.checked.hashes.length > 0) {
    lines.push('Hashes:');
    for (const item of report.checked.hashes) {
      lines.push(`  ${item.alg}: ${item.hex}`);
    }
  } else {
    lines.push('Hashes: -');
  }
  if (Number.isInteger(report.checked?.messageBytesLength)) {
    lines.push(`Message Bytes: ${report.checked.messageBytesLength}`);
  }
  lines.push('');
  lines.push(...report.details);
  return lines.join('\n');
}

export function signatureDocRequiresInputBytes(signatureDoc) {
  const profile = resolveSupportedProfile({
    schema: String(signatureDoc?.schema || '').trim(),
    proofType: String(signatureDoc?.proofType || '').trim(),
    payloadType: String(signatureDoc?.payloadType || '').trim(),
    signatureScheme: String(signatureDoc?.signatureScheme || '').trim(),
  });
  return profile?.id === 'sep53-message';
}

export function sameDigestBytes(a, b) {
  return bytesEqual(a, b);
}

function parseDeclaredManageDataEntries(manageDataSection) {
  const entries = manageDataSection?.entries;
  if (!Array.isArray(entries)) {
    throw new Error('manageData.entries must be an array.');
  }
  if (entries.length === 0) {
    throw new Error('manageData.entries must not be empty.');
  }

  const seen = new Set();
  return entries.map((item) => {
    const name = String(item?.name || '').trim();
    const alg = normalizeHashAlgorithmName(item?.alg);
    const digestHex = String(item?.digestHex || '').toLowerCase();

    if (!name) {
      throw new Error('manageData.entries contains empty name.');
    }
    if (seen.has(name)) {
      throw new Error(`manageData.entries contains duplicate name: ${name}`);
    }
    seen.add(name);
    if (!/^[0-9a-f]+$/.test(digestHex)) {
      throw new Error(`manageData.entries digestHex is invalid for ${name}.`);
    }

    const impliedAlg = hashAlgorithmFromManageDataName(name);
    if (!impliedAlg) {
      throw new Error(`Unsupported ManageData name: ${name}.`);
    }
    if (impliedAlg !== alg) {
      throw new Error(`ManageData name/alg mismatch for ${name}.`);
    }

    const expectedHexLength = expectedDigestHexLength(alg);
    if (digestHex.length !== expectedHexLength) {
      throw new Error(`manageData.entries digestHex length mismatch for ${name}.`);
    }

    return {
      name,
      alg,
      digestHex,
    };
  });
}

function validateInputDescriptor({ report, declaredInput, inputContext }) {
  if (declaredInput?.type === 'file' || declaredInput?.type === 'text') {
    report.ok(`Input descriptor accepted: ${declaredInput.type}.`);
    if (declaredInput.type !== inputContext.type) {
      report.fail(`Input type mismatch: signature expects ${declaredInput.type}, received ${inputContext.type}.`);
    }
    if (Number.isInteger(declaredInput.size) && declaredInput.size !== inputContext.fileSize) {
      report.fail(`Input size mismatch: signature expects ${declaredInput.size}, received ${inputContext.fileSize}.`);
    }
    return;
  }

  if (declaredInput) {
    report.warn('Signature input descriptor is present but has unsupported type metadata.');
    return;
  }

  report.warn('Signature input descriptor is missing.');
}

function expectedDigestHexLength(alg) {
  const normalized = normalizeHashAlgorithmName(alg);
  if (normalized === HASH_ALG.SHA256) return 64;
  return 128;
}

function resolveSupportedProfile({ schema, proofType, payloadType, signatureScheme }) {
  if (schema !== SIGNATURE_SCHEMA_V2) return null;
  return (
    SUPPORTED_PROFILES.find(
      (item) =>
        item.proofType === proofType &&
        item.payloadType === payloadType &&
        item.signatureScheme === signatureScheme
    ) || null
  );
}
