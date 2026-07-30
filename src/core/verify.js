import {
  HASH_ALG,
  MANAGE_DATA_NAME,
  PAYLOAD_TYPE,
  PROOF_TYPE,
  SIGNATURE_SCHEME,
  SIGNATURE_SCHEMA_V2,
  SIGNATURE_SCHEMA_V3,
} from './constants.js';
import { bytesEqual } from './bytes.js';
import { assertStrictEd25519PublicKey } from './ed25519-validation.js';
import { parseHashEntries, digestForHashAlgorithm, hashAlgorithmFromManageDataName } from './message.js';
import { knownNetworkPassphrases, networkHintFromPassphrase } from './network.js';
import {
  assertExactKeys,
  protectedManifestBytes,
  protectedManifestSha256,
  validateProtectedManifest,
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
  const signer = validateSigner({ report, signatureDoc, expectedSigner });
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

  validateProtectedManifest({
    manifest: signatureDoc.protected,
    inputContext,
    expectedProofType: proofType,
    expectedSigner: signer.address,
  });
  checked.mode = proofType === PROOF_TYPE.SEP53_MESSAGE ? 'protected-manifest-sep53' : 'protected-manifest-xdr';
  checked.proofType = proofType;
  checked.payloadType = signatureDoc.protected.payloadType;
  checked.signatureScheme = signatureDoc.protected.signatureScheme;
  checked.hashes = signatureDoc.protected.hashes.map((entry) => ({ ...entry }));
  report.ok('Protected manifest schema, metadata, input identity, and exact hash set validated.');

  if (proofType === PROOF_TYPE.SEP53_MESSAGE) {
    await verifyV3Sep53({ report, signatureDoc, signer, checked });
  } else {
    await verifyV3Xdr({ report, signatureDoc, signer });
  }
  return report.finish({ signer: signer.address, checked });
}

async function verifyV3Sep53({ report, signatureDoc, signer, checked }) {
  let signatureBytes;
  try {
    signatureBytes = parseSep53Signature(signatureDoc.signatureB64);
  } catch (err) {
    report.fail(`Malformed signature: ${err.message}`);
    return;
  }
  const manifestBytes = protectedManifestBytes(signatureDoc.protected);
  checked.messageBytesLength = manifestBytes.length;
  const valid = await verifySep53Message({
    publicKeyBytes: signer.publicBytes,
    messageBytes: manifestBytes,
    signatureBytes,
  });
  if (valid) report.ok('SEP-53 signature over the canonical protected manifest is valid.');
  else report.fail('SEP-53 protected-manifest signature verification failed.');
}

async function verifyV3Xdr({ report, signatureDoc, signer }) {
  let parsed;
  try {
    parsed = parseTransactionEnvelope(signatureDoc.signedXdr);
  } catch (err) {
    report.fail(`Malformed signedXdr: ${err.message}`);
    return;
  }
  const manifestDigest = await protectedManifestSha256(signatureDoc.protected);
  let safe;
  try {
    safe = assertSafeManageDataEnvelope(parsed, {
      expectedEntries: [{ dataName: MANAGE_DATA_NAME.MANIFEST_SHA256, dataValue: manifestDigest }],
    });
  } catch (err) {
    report.fail(err.message);
    return;
  }
  const sourceAddress = encodeEd25519PublicKey(safe.sourceAccount);
  if (sourceAddress !== signer.address) {
    report.fail(`signedXdr sourceAccount mismatch: signer=${signer.address}, sourceAccount=${sourceAddress}.`);
    return;
  }
  const passphrase = signatureDoc.protected.network.passphrase;
  const txHash = await computeTransactionHash(parsed.txXdr, passphrase);
  let match;
  try {
    match = await findValidDecoratedSignature(parsed.signatures, signer.publicBytes, txHash);
  } catch (err) {
    report.fail(`Invalid signedXdr signature set: ${err.message}`);
    return;
  }
  if (match) {
    report.ok('XDR signature and protected-manifest digest binding are valid.');
    return;
  }
  for (const alternative of knownNetworkPassphrases()) {
    if (alternative === passphrase) continue;
    const alternativeHash = await computeTransactionHash(parsed.txXdr, alternative);
    if (await findValidDecoratedSignature(parsed.signatures, signer.publicBytes, alternativeHash)) {
      report.fail('Wrong network passphrase: signature is valid under a different known network passphrase.');
      return;
    }
  }
  report.fail('No valid signer signature found in signedXdr.');
}

async function verifyV2({ report, checked, signatureDoc, inputContext, expectedSigner, strict }) {
  checked.schema = SIGNATURE_SCHEMA_V2;
  const signer = validateSigner({ report, signatureDoc, expectedSigner });
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
  report.warn('Legacy v2 compatibility: only content bytes/digests are authenticated; surrounding metadata is not signed.');

  if (strict) {
    if (!Array.isArray(signatureDoc.hashes)) throw new Error('Legacy hashes must be an array.');
    signatureDoc.hashes.forEach((entry, index) => {
      assertExactKeys(entry, ['alg', 'hex'], `legacy hashes[${index}]`);
    });
  }
  const entries = parseHashEntries(signatureDoc);
  assertExactHashSet(entries);
  checked.hashes = entries.map((entry) => ({ ...entry }));
  for (const entry of entries) {
    const recomputed = digestForHashAlgorithm(inputContext.digests, entry.alg);
    if (entry.hex !== recomputed.hex) report.fail(`Digest mismatch for ${entry.alg}.`);
    else report.ok(`Digest match for ${entry.alg}.`);
  }
  validateLegacyInput(signatureDoc.input, inputContext);

  if (profile.id === 'v2-sep53-content-only') {
    const signatureBytes = parseSep53Signature(signatureDoc.signatureB64);
    const messageBytes = readInputContextBytes(inputContext);
    checked.messageBytesLength = messageBytes.length;
    const valid = await verifySep53Message({
      publicKeyBytes: signer.publicBytes,
      messageBytes,
      signatureBytes,
    });
    if (valid) report.ok('Legacy SEP-53 content signature is valid.');
    else report.fail('SEP-53 content signature verification failed.');
  } else {
    await verifyV2Xdr({ report, signatureDoc, inputContext, signer });
  }
  return report.finish({ signer: signer.address, checked });
}

async function verifyV2Xdr({ report, signatureDoc, inputContext, signer }) {
  assertExactKeys(signatureDoc.network, ['passphrase', 'hint'], 'legacy network');
  assertExactKeys(signatureDoc.manageData, ['entries'], 'legacy manageData');
  if (signatureDoc.txSourceAccount !== signer.address) throw new Error('Legacy txSourceAccount is required and must match signer.');
  const declared = signatureDoc.manageData.entries;
  if (!Array.isArray(declared) || declared.length !== 2) throw new Error('Legacy manageData.entries must contain exactly two entries.');
  const expectedEntries = declared.map((entry, index) => {
    assertExactKeys(entry, ['name', 'alg', 'digestHex'], `legacy manageData.entries[${index}]`);
    const alg = hashAlgorithmFromManageDataName(entry.name);
    if (!alg || alg !== entry.alg) throw new Error('Legacy ManageData name/algorithm mismatch.');
    const digest = digestForHashAlgorithm(inputContext.digests, alg);
    if (entry.digestHex !== digest.hex) throw new Error('Legacy ManageData declared digest mismatch.');
    return { dataName: entry.name, dataValue: digest.bytes };
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
  if (!match) report.fail('No valid signer signature found in legacy signedXdr.');
  else report.ok('Legacy XDR signature and digest operations are valid.');
}

function validateSigner({ report, signatureDoc, expectedSigner }) {
  const address = typeof signatureDoc.signer === 'string' ? signatureDoc.signer : '';
  if (!address || address !== address.trim()) throw new Error('Signer field is missing or non-canonical.');
  const publicBytes = decodeEd25519PublicKey(address);
  assertStrictEd25519PublicKey(publicBytes);
  const expected = String(expectedSigner || '').trim();
  if (expected && expected !== address) report.fail(`Wrong signer: expected ${expected}, got ${address}.`);
  else report.ok('Signer address and Ed25519 public point are valid.');
  return { address, publicBytes };
}

function validateLegacyInput(input, inputContext) {
  if (!isPlainObject(input)) throw new Error('Legacy input descriptor is required.');
  if (input.type === 'file') {
    assertExactKeys(input, ['type', 'name', 'size'], 'legacy input');
    if (inputContext.type !== 'file') throw new Error('Legacy input type mismatch.');
    if (input.name !== inputContext.fileName) throw new Error('Legacy input filename mismatch.');
  } else if (input.type === 'text') {
    assertExactKeys(input, ['type', 'size'], 'legacy input');
    if (inputContext.type !== 'text') throw new Error('Legacy input type mismatch.');
  } else {
    throw new Error('Legacy input type is invalid.');
  }
  if (!Number.isSafeInteger(input.size) || input.size !== inputContext.fileSize) {
    throw new Error('Legacy input size mismatch.');
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
  return {
    ok(message) {
      details.push(`OK: ${message}`);
    },
    fail(message) {
      details.push(`FAIL: ${message}`);
      errors.push(message);
    },
    warn(message) {
      details.push(`WARN: ${message}`);
      warnings.push(message);
    },
    finish({ signer, checked }) {
      return {
        valid: errors.length === 0,
        signer,
        checked,
        details,
        errors,
        warnings,
        summary: errors.length === 0 ? 'VALID' : 'INVALID',
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
  const lines = [
    `Result: ${report.valid ? 'VALID' : 'INVALID'}`,
    `Signer: ${report.signer || '-'}`,
    `Schema: ${report.checked?.schema || '-'}`,
    `Proof Type: ${report.checked?.proofType || '-'}`,
    `Payload Type: ${report.checked?.payloadType || '-'}`,
    `Signature Scheme: ${report.checked?.signatureScheme || '-'}`,
    `Mode: ${report.checked?.mode || '-'}`,
  ];
  if (report.checked?.hashes?.length) {
    lines.push('Hashes:');
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

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
