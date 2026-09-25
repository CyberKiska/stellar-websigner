import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createSha3_512Stream, sha256 } from '../../src/core/hash.js';
import { createSigningKeySession, derivePublicKeyFromSeed, generateKeypair, signatureHint, verifyBytesWithPublic } from '../../src/core/ed25519.js';
import { decodeEd25519PublicKey } from '../../src/core/strkey.js';
import { canonicalBase64ToBytes, safeJsonParse } from '../../src/core/bytes.js';
import { canonicalJsonStringify } from '../../src/core/canonical-json.js';
import { parseTransactionEnvelope } from '../../src/core/xdr.js';

const hash = (algorithm, bytes) => createHash(algorithm).update(bytes).digest();
const u32 = (n) => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(n); return bytes; };
const opaque = (bytes) => Buffer.concat([u32(bytes.length), bytes, Buffer.alloc((4 - bytes.length % 4) % 4)]);
const privateKey = (seed) => createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der', type: 'pkcs8',
});
const rawPublicKey = (key) => createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);

test('provider SHA-256 and bundled streaming SHA3-512 match independent OpenSSL hashes across 266 sizes', async () => {
  const sizes = [
    ...Array.from({ length: 256 }, (_, i) => i),
    1024, 4095, 4096, 4097, 65535, 65536, 65537, 4194303, 4194304, 4194305,
  ];
  for (const size of sizes) {
    const bytes = Uint8Array.from({ length: size }, (_, i) => (i * 131 + 17) & 255);
    const sha3 = createSha3_512Stream();
    for (let offset = 0; offset < size;) {
      const chunk = bytes.subarray(offset, Math.min(size, offset + (offset < 200 ? 7 : 65537)));
      sha3.update(chunk);
      offset += chunk.length;
    }
    assert.deepEqual(Buffer.from(await sha256(bytes)), hash('sha256', bytes), `SHA-256: ${size}`);
    assert.deepEqual(Buffer.from(await sha3.finish()), hash('sha3-512', bytes), `SHA3-512: ${size}`);
  }
});

test('owned key copies preserve caller Buffer values and session public keys', async () => {
  const seed = Buffer.alloc(32, 1);
  const expectedSeed = Buffer.from(seed);
  const key = privateKey(seed);
  const publicBytes = rawPublicKey(key);
  const expectedPublic = Buffer.from(publicBytes);
  assert.deepEqual(Buffer.from(await derivePublicKeyFromSeed(seed)), expectedPublic);
  assert.deepEqual(seed, expectedSeed);
  const session = await createSigningKeySession(seed, { publicBytes });
  try {
    assert.deepEqual(seed, expectedSeed);
    assert.deepEqual(publicBytes, expectedPublic);
    const message = Buffer.from('owned seed');
    assert.equal(verify(null, message, createPublicKey(key), await session.sign(message)), true);
    const hint = signatureHint(publicBytes);
    hint.fill(0);
    publicBytes.fill(0);
    assert.deepEqual(Buffer.from(session.publicBytes), expectedPublic);
  } finally {
    session.destroy();
  }
  await assert.rejects(() => session.sign(Buffer.alloc(0)), /no longer active/);
});

test('generated PKCS8 buffers are wiped on success and failed public-key validation', async () => {
  const seed = Buffer.alloc(32, 1);
  const key = privateKey(seed);
  const publicBytes = rawPublicKey(key);
  for (const outcome of ['success', 'export failure', 'invalid public key', 'invalid private encoding']) {
    const pkcs8 = new Uint8Array(key.export({ format: 'der', type: 'pkcs8' }));
    if (outcome === 'invalid private encoding') pkcs8[0] = 0;
    const subtle = {
      generateKey: async () => ({ privateKey: {}, publicKey: {} }),
      exportKey: async (format) => {
        if (format === 'pkcs8') return pkcs8.buffer;
        if (outcome === 'export failure') throw new Error('synthetic export failure');
        return new Uint8Array(outcome === 'invalid public key' ? 32 : publicBytes).buffer;
      },
    };
    if (outcome === 'success') {
      const generated = await generateKeypair({ subtle });
      assert.deepEqual(Buffer.from(generated.seedBytes), seed);
      assert.deepEqual(Buffer.from(generated.publicBytes), publicBytes);
      generated.seedBytes.fill(0);
    } else {
      await assert.rejects(() => generateKeypair({ subtle }));
    }
    assert(pkcs8.every((byte) => byte === 0), outcome);
  }
});

test('Ed25519 rejects invalid A/R points, noncanonical scalars and signature bit flips', async () => {
  const seed = new Uint8Array(32).fill(1); // Synthetic; never a production credential.
  const key = privateKey(seed);
  const publicBytes = rawPublicKey(key);
  assert.deepEqual(Buffer.from(await derivePublicKeyFromSeed(seed)), publicBytes);
  const message = Buffer.from('ed25519-regression');
  const good = sign(null, message, key);
  assert.equal(await verifyBytesWithPublic(publicBytes, message, good), true);
  const littleEndian = (value) => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < bytes.length; i += 1) { bytes[i] = Number(value & 255n); value >>= 8n; }
    return bytes;
  };
  const p = 2n ** 255n - 19n;
  const order = 2n ** 252n + 27742317777372353535851937790883648493n;
  const points = [
    ['identity', littleEndian(1n)], ['order four', littleEndian(0n)],
    ['order two', littleEndian(p - 1n)], ['noncanonical y', littleEndian(p)],
    ['all FF', new Uint8Array(32).fill(255)], ['negative zero', littleEndian(1n + 2n ** 255n)],
    ['off curve', littleEndian(2n)],
    ['mixed order', Buffer.from('9599999999999999999999999999999999999999999999999999999999999999', 'hex')],
  ];
  for (const [name, point] of points) {
    assert.equal(await verifyBytesWithPublic(point, message, good), false, `${name}: A`);
    const signature = Buffer.from(good);
    signature.set(point);
    assert.equal(await verifyBytesWithPublic(publicBytes, message, signature), false, `${name}: R`);
  }
  for (const scalar of [order, order + 1n, 2n ** 256n - 1n]) {
    const signature = Buffer.from(good);
    signature.set(littleEndian(scalar), 32);
    assert.equal(await verifyBytesWithPublic(publicBytes, message, signature), false);
  }
  for (let i = 0; i < good.length; i += 1) {
    const signature = Buffer.from(good);
    signature[i] ^= 1;
    assert.equal(await verifyBytesWithPublic(publicBytes, message, signature), false, `bit flip: ${i}`);
  }
  const forged = new Uint8Array(64);
  forged[0] = 1;
  assert.equal(await verifyBytesWithPublic(littleEndian(1n), message, forged), false);
});

test('published SEP-53 and XDR vectors agree with independent signing and transaction encoding', async () => {
  const { vectors } = JSON.parse(await readFile(new URL('../../test-vectors.json', import.meta.url), 'utf8'));
  // Independent canonical encoding for these fixed fixtures (all property names are ASCII).
  const canonical = (value) => {
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    if (value && typeof value === 'object') {
      return '{' + Object.keys(value).sort().map((name) => JSON.stringify(name) + ':' + canonical(value[name])).join(',') + '}';
    }
    return JSON.stringify(value);
  };
  let xdrCount = 0;
  for (const vector of vectors) {
    const publicBytes = Buffer.from(decodeEd25519PublicKey(vector.signer));
    const publicKey = createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicBytes]), format: 'der', type: 'spki',
    });
    const input = vector.input.text !== undefined ? Buffer.from(vector.input.text)
      : vector.input.messageB64 !== undefined ? Buffer.from(vector.input.messageB64, 'base64')
      : Buffer.from(vector.input.fileContentUtf8);
    assert.equal(hash('sha256', input).toString('hex'), vector.digests.sha256Hex, vector.id);
    assert.equal(hash('sha3-512', input).toString('hex'), vector.digests.sha3_512Hex, vector.id);
    if (!vector.unsignedXdr) {
      const message = vector.doc ? Buffer.from(canonical(vector.doc.protected)) : input;
      const digest = hash('sha256', Buffer.concat([Buffer.from('Stellar Signed Message:\n'), message]));
      assert.equal(verify(null, digest, publicKey, Buffer.from(vector.signatureB64, 'base64')), true, vector.id);
      if (vector.seedHex) {
        assert.equal(sign(null, digest, privateKey(Buffer.from(vector.seedHex, 'hex'))).toString('base64'), vector.signatureB64);
      }
      continue;
    }
    xdrCount += 1;
    const manifestDigest = hash('sha256', Buffer.from(canonical(vector.doc.protected)));
    const name = 'org.stellar-websigner.manifest.sha256';
    assert.deepEqual(vector.manageData.entries, [{ name, alg: 'SHA-256', valueHex: manifestDigest.toString('hex') }]);
    // Stellar-transaction.x: V1, Ed25519 source, fee 8000, sequence zero,
    // no preconditions/memo, one source-less ManageData, no extension.
    const tx = Buffer.concat([
      u32(0), publicBytes, u32(8000), Buffer.alloc(8), u32(0), u32(0), u32(1),
      u32(0), u32(10), opaque(Buffer.from(name)), u32(1), opaque(manifestDigest), u32(0),
    ]);
    const unsigned = Buffer.concat([u32(2), tx, u32(0)]);
    assert.equal(unsigned.toString('base64'), vector.unsignedXdr, vector.id);
    assert.deepEqual(Buffer.from(parseTransactionEnvelope(vector.unsignedXdr).txXdr), tx);
    const callerBytes = Buffer.from(unsigned);
    const parsed = parseTransactionEnvelope(callerBytes);
    callerBytes.fill(0);
    assert.deepEqual(Buffer.from(parsed.envelopeXdr), unsigned);
    assert.deepEqual(Buffer.from(parsed.txXdr), tx);
    assert.deepEqual(Buffer.from(parsed.transaction.sourceAccount), publicBytes);
    const digest = hash('sha256', Buffer.concat([hash('sha256', Buffer.from(vector.networkPassphrase)), u32(2), tx]));
    assert.equal(digest.toString('hex'), vector.txHashHex);
    const signature = sign(null, digest, privateKey(Buffer.from(vector.seedHex, 'hex')));
    assert.equal(signature.toString('base64'), vector.txSignatureB64);
    assert.equal(verify(null, digest, publicKey, signature), true);
    const signed = Buffer.concat([u32(2), tx, u32(1), publicBytes.subarray(28), opaque(signature)]).toString('base64');
    assert.equal(signed, vector.signedXdr);
    assert.equal(signed, vector.doc.signedXdr);
  }
  assert.equal(xdrCount, 2);
});

test('canonical JSON and Base64 reject ambiguous encodings and enforce bounds', () => {
  for (const text of [
    '{"x":1,"\\u0078":2}', '{"outer":{"a":1,"a":2}}', '[1,]', '{"x":1e400}',
    '{"x":"\\ud800"}', '['.repeat(18) + '0' + ']'.repeat(18), ' '.repeat(262145),
  ]) assert.throws(() => safeJsonParse(text));
  for (const text of ['Zh==', 'Zg=', 'Zg', ' Zg==', 'Zg==\n', 'Zg===', '_w==', 'Z=g=']) {
    assert.throws(() => canonicalBase64ToBytes(text));
  }
  assert.equal(Buffer.from(canonicalBase64ToBytes('Zg==')).toString(), 'f');
  assert.equal(canonicalJsonStringify({ z: -0, a: [1e30, 1e-7, 1e-6] }), '{"a":[1e+30,1e-7,0.000001],"z":0}');
  assert.equal(canonicalJsonStringify({ '\u20ac': 1, '\r': 2, '\ufb33': 3, '1': 4, '\ud83d\ude00': 5, '\u0080': 6, '\u00f6': 7 }),
    '{"\\r":2,"1":4,"\u0080":6,"\u00f6":7,"\u20ac":1,"\ud83d\ude00":5,"\ufb33":3}');
});
