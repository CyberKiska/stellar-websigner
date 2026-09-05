import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { canonicalBase64ToBytes, safeJsonParse } from '../../src/core/bytes.js';
import { canonicalJsonStringify } from '../../src/core/canonical-json.js';
import { createFileInputContext, createTextInputContext } from '../../src/core/input-context.js';
import { createLocalSep53MessageSignature } from '../../src/core/signing.js';
import { createXdrProofDraft, finalizeXdrProof } from '../../src/core/xdr-proof.js';
import { diagnosticsForDisplay, verifyDetachedSignature } from '../../src/core/verify.js';
import { encodeEd25519PublicKey } from '../../src/core/strkey.js';
import { parseTransactionEnvelope } from '../../src/core/xdr.js';
import { MANAGE_DATA_NAME, TESTNET_NETWORK_PASSPHRASE } from '../../src/core/constants.js';
import { readFileText } from '../../src/ui/common.js';

// Fixed synthetic seed; the independent writer follows Stellar-transaction.x.
const seed = new Uint8Array(32).fill(1);
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicBytes = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
const signer = encodeEd25519PublicKey(publicBytes);
const context = await createTextInputContext('abc');
const local = await createLocalSep53MessageSignature({ seedBytes: seed, inputContext: context });
const draft = await createXdrProofDraft({ inputContext: context, signerAddress: signer, networkPassphrase: TESTNET_NETWORK_PASSPHRASE });
const hash = (bytes) => createHash('sha256').update(bytes).digest();
const u32 = (n) => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(n); return bytes; };
const opaque = (bytes) => Buffer.concat([u32(bytes.length), bytes, Buffer.alloc((4 - bytes.length % 4) % 4)]);

function signedXdr(name = Buffer.from(MANAGE_DATA_NAME.MANIFEST_SHA256)) {
  const tx = Buffer.concat([
    u32(0), publicBytes, u32(8000), Buffer.alloc(8), u32(0), u32(0), u32(1),
    u32(0), u32(10), opaque(name), u32(1), opaque(draft.manifestDigest), u32(0),
  ]);
  const txHash = hash(Buffer.concat([hash(Buffer.from(TESTNET_NETWORK_PASSPHRASE)), u32(2), tx]));
  const signature = sign(null, txHash, key);
  return Buffer.concat([u32(2), tx, u32(1), publicBytes.subarray(28), opaque(signature)]).toString('base64');
}
const xdrDoc = { schema: 'stellar-signature/v3', signer, protected: draft.protectedManifest, signedXdr: signedXdr() };
const verify = (signatureDoc, inputContext = context, extra = {}) => verifyDetachedSignature({ signatureDoc, inputContext, expectedSigner: signer, ...extra });

test('independent XDR fixture agrees with the draft and verifies normally', async () => {
  assert.deepEqual(parseTransactionEnvelope(xdrDoc.signedXdr).txXdr, draft.txXdr);
  assert.equal((await verify(xdrDoc)).summary, 'VALID');
});

test('signer assurance distinguishes absent, matching, malformed and mismatching expectations', async () => {
  const absent = await verify(local.doc, context, { expectedSigner: '' });
  assert.equal(absent.signatureValid, true);
  assert.equal(absent.inputMatches, true);
  assert.equal(absent.contextMatches, null);
  assert.equal(absent.valid, false);
  assert.equal(absent.summary, 'SIGNER_UNCONFIRMED');
  assert.match(diagnosticsForDisplay(absent), /Expected Signer Matches: NOT SUPPLIED/);
  assert.equal((await verify(local.doc)).summary, 'VALID');
  const otherKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), new Uint8Array(32).fill(2)]), format: 'der', type: 'pkcs8' });
  const otherSigner = encodeEd25519PublicKey(createPublicKey(otherKey).export({ format: 'der', type: 'spki' }).subarray(-32));
  for (const expectedSigner of ['malformed', [signer], otherSigner]) {
    const report = await verify(local.doc, context, { expectedSigner });
    assert.equal(report.signatureValid, true);
    assert.equal(report.contextMatches, false);
    assert.equal(report.summary, 'MISMATCH');
  }
  const changedInput = await verify(local.doc, await createTextInputContext('abd'), { expectedSigner: '' });
  assert.equal(changedInput.summary, 'MISMATCH');
  const invalid = await verify({ ...local.doc, signatureB64: 'AA==' }, context, { expectedSigner: '' });
  assert.equal(invalid.summary, 'INVALID');
  assert.match(diagnosticsForDisplay(invalid), /Expected Signer Matches: NOT CHECKED/);
});

test('genuinely signed XDR names reject BOMs, invalid UTF-8, aliases and old digest names', async () => {
  for (const name of [
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(MANAGE_DATA_NAME.MANIFEST_SHA256)]),
    Buffer.concat([Buffer.from([0xff]), Buffer.from(MANAGE_DATA_NAME.MANIFEST_SHA256)]),
    Buffer.from(MANAGE_DATA_NAME.MANIFEST_SHA256 + '\0'),
    Buffer.from('ws.sha256'), Buffer.from('ws.sha3-512'), Buffer.alloc(65, 0x61),
  ]) {
    const report = await verify({ ...xdrDoc, signedXdr: signedXdr(name) });
    assert.equal(report.summary, 'INVALID', name.toString('hex'));
    assert.equal(report.signatureValid, false);
    assert.equal(report.inputMatches, null);
  }
});

test('proof fields require strings without JavaScript coercion', async () => {
  for (const [doc, field] of [[local.doc, 'signatureB64'], [xdrDoc, 'signedXdr']]) {
    for (const value of [[doc[field]], [[doc[field]]], null, false, 123, {}, new Uint8Array(64)]) {
      const report = await verify({ ...doc, [field]: value });
      assert.equal(report.summary, 'INVALID');
      assert.equal(report.signatureValid, false);
      assert.match(report.errors.join(' '), /must be a string/);
    }
  }
  for (const value of [['Zg=='], null, false, 123, {}]) assert.throws(() => canonicalBase64ToBytes(value), /string/);
  await assert.rejects(() => finalizeXdrProof({ inputContext: context, signedXdr: [xdrDoc.signedXdr], draft }), /string/);
});

test('protected filename and network fields require strings before proof verification', async () => {
  const fileContext = await createFileInputContext(new File(['abc'], 'a.txt'));
  const file = await createLocalSep53MessageSignature({ seedBytes: seed, inputContext: fileContext });
  for (const value of [['a.txt'], {}, 123, null]) {
    const report = await verify({ ...file.doc, protected: { ...file.doc.protected, input: { ...file.doc.protected.input, name: value } } }, fileContext);
    assert.equal(report.signatureValid, false);
    assert.match(report.errors.join(' '), /filename must be a string/);
  }
  for (const value of [[TESTNET_NETWORK_PASSPHRASE], {}, 123, null]) {
    const report = await verify({ ...xdrDoc, protected: { ...xdrDoc.protected, network: { ...xdrDoc.protected.network, passphrase: value } } });
    assert.equal(report.signatureValid, false);
    assert.match(report.errors.join(' '), /network passphrase is invalid/);
  }
});

test('all I-JSON noncharacters are rejected in names and values, including escaped input', async () => {
  const codes = [
    ...Array.from({ length: 32 }, (_, i) => 0xfdd0 + i),
    ...Array.from({ length: 17 }, (_, plane) => [plane * 65536 + 0xfffe, plane * 65536 + 0xffff]).flat(),
  ];
  for (const code of codes) {
    const text = String.fromCodePoint(code);
    for (const value of [{ value: text }, { [text]: 'value' }]) {
      assert.throws(() => canonicalJsonStringify(value), /noncharacter/);
      assert.throws(() => safeJsonParse(JSON.stringify(value)), /noncharacter/);
    }
    const escaped = text.split('').map((unit) => '\\u' + unit.charCodeAt(0).toString(16).padStart(4, '0')).join('');
    assert.throws(() => safeJsonParse('{"value":"' + escaped + '"}'), /noncharacter/);
  }
  assert.equal(safeJsonParse('{"value":"\ufffd\ud83d\ude00"}').value, '\ufffd\ud83d\ude00');
  // Arbitrary text content is UTF-8 data, not an I-JSON metadata string.
  assert.equal((await createTextInputContext('\ufdd0')).fileSize, 3);
});

test('malformed UTF-8 signature files are rejected instead of repaired', async () => {
  const inputContext = await createFileInputContext(new File(['abc'], '\ufffd.txt'));
  const signed = await createLocalSep53MessageSignature({ seedBytes: seed, inputContext });
  const encoded = Buffer.from(signed.json);
  const at = encoded.indexOf(Buffer.from('\ufffd'));
  assert(at >= 0);
  const malformed = Buffer.concat([encoded.subarray(0, at), Buffer.from([0xff]), encoded.subarray(at + 3)]);
  await assert.rejects(() => readFileText(new File([malformed], 'invalid.sig')));
  assert.deepEqual(safeJsonParse(await readFileText(new File([encoded], 'valid.sig'))), signed.doc);
  const bom = new File([Buffer.from([0xef, 0xbb, 0xbf]), encoded], 'bom.sig');
  assert.throws(() => safeJsonParse('\ufeff' + signed.json), /Malformed JSON/);
  assert.equal((await readFileText(bom)).codePointAt(0), 0xfeff);
});

test('legacy content-only signatures and permissive verifier options cannot bypass v3 requirements', async () => {
  const legacy = {
    schema: 'stellar-signature/v2', signer, proofType: 'sep53-message-signature',
    payloadType: 'raw-bytes', signatureScheme: 'sep53-sha256-ed25519',
    input: { type: 'text', size: 3 }, hashes: local.doc.protected.hashes,
    signatureB64: sign(null, hash(Buffer.from('Stellar Signed Message:\nabc')), key).toString('base64'),
  };
  for (const doc of [legacy, { ...xdrDoc, schema: 'stellar-signature/v2' }]) {
    const report = await verify(doc, context, { strict: false });
    assert.equal(report.summary, 'INVALID');
    assert.equal(report.signatureValid, false);
    assert.match(report.errors.join(' '), /Unsupported schema/);
  }
  const report = await verify({ ...local.doc, unsignedMetadata: 'ignored?' }, context, { strict: false });
  assert.equal(report.summary, 'INVALID');
  assert.match(report.errors.join(' '), /unknown fields/);
});
