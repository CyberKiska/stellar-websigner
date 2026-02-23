import { HASH_ALG, MODE, SIGNATURE_SCHEMA } from './constants.js';
import {
  base64ToBytes,
  bytesEqual,
  sanitizeBase64,
} from './bytes.js';
import { decodeEd25519PublicKey, encodeEd25519PublicKey } from './strkey.js';
import { verifyBytesWithPublic } from './ed25519.js';
import {
  assertSafeManageDataEnvelope,
  computeTransactionHash,
  findValidDecoratedSignature,
  parseTransactionEnvelope,
} from './xdr.js';
import {
  buildDeterministicMessage,
  computeSep53MessageHash,
  digestForHashAlgorithm,
  hashAlgorithmFromManageDataName,
  normalizeHashAlgorithmName,
  parseHashEntries,
} from './message.js';
import { knownNetworkPassphrases } from './sep7.js';

export async function verifyDetachedSignature({ signatureDoc, inputContext, expectedSigner = '' }) {
  const report = createReport();

  if (!signatureDoc || typeof signatureDoc !== 'object') {
    report.fail('Malformed signature document: expected JSON object.');
    return report.finish('', []);
  }

  if (signatureDoc.schema !== SIGNATURE_SCHEMA) {
    report.fail(`Unsupported schema: ${String(signatureDoc.schema || '(missing)')}`);
  } else {
    report.ok(`Schema accepted: ${SIGNATURE_SCHEMA}`);
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

  let hashEntries;
  try {
    hashEntries = parseHashEntries(signatureDoc);
    report.ok(`Hash entries parsed: ${hashEntries.map((item) => item.alg).join(', ')}`);
  } catch (err) {
    report.fail(`Malformed hashes section: ${err.message}`);
    return report.finish(signer, []);
  }

  const recomputedEntries = [];
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

  const mode = String(signatureDoc.mode || '').trim();
  if (mode === MODE.SEP53) {
    await verifyLocalSignatureMode({
      report,
      signatureDoc,
      signerPublicBytes,
      inputContext,
      recomputedEntries,
    });
  } else if (mode === MODE.SEP7_TX) {
    await verifySep7SignatureMode({
      report,
      signatureDoc,
      signer,
      signerPublicBytes,
      inputContext,
      recomputedEntries,
    });
  } else {
    report.fail(`Unsupported signature mode: ${mode || '(missing)'}`);
  }

  return report.finish(signer, recomputedEntries);
}

async function verifyLocalSignatureMode({
  report,
  signatureDoc,
  signerPublicBytes,
  inputContext,
  recomputedEntries,
}) {
  const expectedMessage = buildDeterministicMessage({
    type: inputContext.type,
    fileName: inputContext.fileName,
    fileSize: inputContext.fileSize,
    hashEntries: recomputedEntries,
  });

  if (String(signatureDoc.message || '') !== expectedMessage) {
    report.fail('Deterministic message mismatch: signed message differs from reconstructed input message.');
  } else {
    report.ok('Deterministic message matches reconstructed input.');
  }

  let signatureBytes;
  try {
    signatureBytes = base64ToBytes(String(signatureDoc.signatureB64 || ''));
    if (signatureBytes.length !== 64) {
      throw new Error(`Expected 64-byte signature, got ${signatureBytes.length}.`);
    }
    report.ok('signatureB64 parsed successfully.');
  } catch (err) {
    report.fail(`Malformed signature: ${err.message}`);
    return;
  }

  if (!signerPublicBytes) return;

  const message = String(signatureDoc.message || '');
  const payload = await computeSep53MessageHash(message);

  const ok = await verifyBytesWithPublic(signerPublicBytes, payload, signatureBytes);
  if (!ok) {
    report.fail('SEP-53 signature verification failed.');
  } else {
    report.ok('SEP-53 signature verification passed.');
  }
}

async function verifySep7SignatureMode({
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

  if (sourceAddress === signer) {
    report.ok('signedXdr sourceAccount matches signer field.');
  } else {
    report.warn(
      `signedXdr sourceAccount (${sourceAddress}) differs from signer (${signer}); accepting as off-chain signature.`
    );
  }

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

  function finish(signer, recomputedEntries) {
    return {
      valid: errors.length === 0,
      signer,
      checked: {
        hashes: recomputedEntries.map((item) => ({ alg: item.alg, hex: item.hex })),
      },
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
  if (Array.isArray(report.checked?.hashes) && report.checked.hashes.length > 0) {
    lines.push('Hashes:');
    for (const item of report.checked.hashes) {
      lines.push(`  ${item.alg}: ${item.hex}`);
    }
  } else {
    lines.push('Hashes: -');
  }
  lines.push('');
  lines.push(...report.details);
  return lines.join('\n');
}

export function sameDigestBytes(a, b) {
  return bytesEqual(a, b);
}

export function sameBase64(a, b) {
  return sanitizeBase64(String(a || '')) === sanitizeBase64(String(b || ''));
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

function expectedDigestHexLength(alg) {
  const normalized = normalizeHashAlgorithmName(alg);
  if (normalized === HASH_ALG.SHA256) return 64;
  return 128;
}
