import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import { decodeEd25519SecretSeed } from '../../src/core/strkey.js';
import { encodeSignedTxEnvelope, parseTransactionEnvelope } from '../../src/core/xdr.js';

// Public SEP-53 fixture only; never substitute a production seed in this suite.
const SEED = 'SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW';
const SIGNER = 'GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L';
const PUBLIC_NETWORK = 'Public Global Stellar Network ; September 2015';
const TEST_NETWORK = 'Test SDF Network ; September 2015';
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), decodeEd25519SecretSeed(SEED)]),
  format: 'der', type: 'pkcs8',
});
const publicKey = createPublicKey(privateKey);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
// Independent serialization for the fixture's plain objects, strings, integers, and arrays.
const canonical = (value) => Array.isArray(value)
  ? `[${value.map(canonical).join(',')}]`
  : value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value);

test.beforeEach(async ({ page, browserName }) => {
  await page.goto('/');
  await expect(page.locator('#sys-status-text')).not.toHaveText('Checking cryptography…');
  if (await page.locator('#sys-status-text').textContent() === 'Cryptography unavailable') {
    expect(browserName).toBe('webkit');
    await expect(page.locator('.startup-failure')).toContainText('Ed25519 startup');
    test.skip(true, 'Actual provider fails the startup KAT; application correctly disables all flows.');
  }
});

async function loadKey(page, secret = false) {
  await page.locator(secret ? '#keys-seed-input' : '#keys-g-input').fill(secret ? SEED : SIGNER);
  await page.locator(secret ? '#keys-load-seed' : '#keys-load-g').click();
  await expect(page.locator('#keys-generated-g')).toHaveValue(SIGNER);
}

async function verifyFile(page, doc, { name = 'report.txt', mimeType = 'text/plain', content = 'abc' } = {}) {
  await page.locator('#nav-verify').click();
  await page.locator('#verify-file-input').setInputFiles({ name, mimeType, buffer: Buffer.from(content) });
  await page.locator('#verify-sig-file').setInputFiles({
    name: 'report.txt.sig', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(doc)),
  });
  await expect(page.locator('#verify-run')).toBeEnabled();
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-run')).toHaveText('Verify Signature');
}

test('text DOM bytes, independent SEP-53 verification, download, and key cleanup', async ({ page }) => {
  await loadKey(page, true);
  await expect(page.locator('#keys-seed-input')).toHaveValue('');
  await expect(page.locator('#keys-generated-seed')).toHaveText('');
  const actionRequests = [];
  page.on('request', (request) => actionRequests.push(request.url()));
  await page.locator('#nav-sign').click();
  await page.locator('#sign-mode-text').check();
  await expect(page.locator('#sign-local-run')).toBeDisabled(); // Empty text is a UI limitation.
  await page.locator('#sign-text-input').fill('a\r\nb\rc');
  await expect(page.locator('#sign-text-input')).toHaveValue('a\nb\nc');
  await expect(page.locator('#sign-local-run')).toBeEnabled();
  await page.locator('#sign-local-run').click();
  await expect(page.locator('#sign-status')).toContainText('Content signature created locally');
  const doc = JSON.parse(await page.locator('#sign-output-json').inputValue());
  expect(doc.protected.input.size).toBe(5);
  expect(doc.protected.hashes[0].hex).toBe(sha256('a\nb\nc').toString('hex'));
  expect(doc.protected.hashes[1].hex).toBe(createHash('sha3-512').update('a\nb\nc').digest('hex'));
  const messageHash = sha256(Buffer.concat([
    Buffer.from('Stellar Signed Message:\n'), Buffer.from(canonical(doc.protected)),
  ]));
  expect(verify(null, messageHash, publicKey, Buffer.from(doc.signatureB64, 'base64'))).toBe(true);
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#sign-download').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('plain-text.sig');
  expect(await readFile(await download.path(), 'utf8')).toBe(canonical(doc));
  expect(actionRequests).toEqual([]);
  await page.locator('#nav-keys').click();
  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('#keys-clear').click();
  await expect(page.locator('#sys-status-text')).toHaveText('No key loaded');
  await page.locator('#nav-sign').click();
  await expect(page.locator('#sign-download')).toBeDisabled();
  // End Session releases the key; it is not a full document/form eraser.
  await expect(page.locator('#sign-text-input')).toHaveValue('a\nb\nc');
});

test('file identity, advisory MIME warning, stale result, and tampered manifest', async ({ page }) => {
  await loadKey(page, true);
  await page.locator('#nav-sign').click();
  await page.locator('#sign-file-input').setInputFiles({
    name: 'report.txt', mimeType: 'text/plain', buffer: Buffer.from('abc'),
  });
  await expect(page.locator('#sign-local-run')).toBeEnabled();
  await page.locator('#sign-local-run').click();
  await expect(page.locator('#sign-status')).toContainText('Content signature created locally');
  const doc = JSON.parse(await page.locator('#sign-output-json').inputValue());
  await verifyFile(page, doc);
  await expect(page.locator('#verify-result-badge')).toHaveText('VALID');
  await expect(page.locator('#verify-expected-signer')).toHaveValue(SIGNER);
  await page.locator('#verify-file-input').setInputFiles({
    name: 'renamed.txt', mimeType: 'text/plain', buffer: Buffer.from('abc'),
  });
  await expect(page.locator('#verify-run')).toBeEnabled();
  // Characterization: documentation must require a fresh run after any input edit.
  await expect(page.locator('#verify-result-badge')).toHaveText('VALID');
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-result-badge')).toHaveText('MISMATCH');
  await expect(page.locator('#verify-details')).toHaveValue(/Protected filename mismatch/);
  await verifyFile(page, doc, { mimeType: 'application/octet-stream' });
  await expect(page.locator('#verify-result-badge')).toHaveText('WARNING');
  await expect(page.locator('#verify-details')).toHaveValue(/Result: VALID_WITH_WARNINGS/);
  await expect(page.locator('#verify-details')).toHaveValue(/Selected Input Matches: YES/);
  await page.locator('#verify-expected-signer').fill('');
  await page.locator('#verify-run').click();
  // A self-asserted signer is never presented as VALID.
  await expect(page.locator('#verify-result-badge')).toHaveText('UNVERIFIED SIGNER');
  await expect(page.locator('#verify-result-title')).toHaveText('Valid Signature, Signer Not Verified');
  await expect(page.locator('#verify-details')).toHaveValue(/Result: SIGNER_UNVERIFIED/);
  await expect(page.locator('#verify-details')).toHaveValue(/No expected signer was supplied/);
  await expect(page.locator('#verify-details')).toHaveValue(/Expected Signer Matches: NOT CHECKED/);
  const tampered = structuredClone(doc);
  tampered.protected.input.name = 'renamed.txt';
  await verifyFile(page, tampered, { name: 'renamed.txt' });
  await expect(page.locator('#verify-result-badge')).toHaveText('INVALID');
  await expect(page.locator('#verify-details')).toHaveValue(/Selected Input Matches: NOT CHECKED/);
  await expect(page.locator('#verify-result-signer-label')).toHaveText('Claimed Signer (not authenticated)');
  await expect(page.locator('#verify-result-checked')).toHaveValue('-');
});

test('external XDR handoff with independent signing, wrong network, and stale output', async ({ page }) => {
  await loadKey(page);
  await page.locator('#nav-sign').click();
  await page.locator('#sign-mode-text').check();
  await page.locator('#sign-text-input').fill('abc');
  await expect(page.locator('#sign-xdr-generate')).toBeEnabled();
  await page.locator('#sign-xdr-generate').click();
  await expect(page.locator('#sign-xdr-unsigned-xdr')).not.toHaveValue('');
  const draft = parseTransactionEnvelope(await page.locator('#sign-xdr-unsigned-xdr').inputValue());
  expect(draft.transaction.sequence).toBe(0n);
  expect(draft.transaction.fee).toBe(8000);
  expect(draft.transaction.operations).toHaveLength(1);
  expect(draft.transaction.operations[0].body.dataName).toBe('org.stellar-websigner.manifest.sha256');
  const signedXdr = (network, txXdr = draft.txXdr) => {
    const txHash = sha256(Buffer.concat([sha256(network), Buffer.from([0, 0, 0, 2]), txXdr]));
    return Buffer.from(encodeSignedTxEnvelope({
      txXdr, signatures: [{ hint: draft.transaction.sourceAccount.slice(28), signature: sign(null, txHash, privateKey) }],
    })).toString('base64');
  };
  await page.locator('#sign-xdr-signed-xdr').fill(signedXdr(TEST_NETWORK));
  await page.locator('#sign-xdr-create').click();
  await expect(page.locator('#sign-status')).toContainText('wrong network');
  await expect(page.locator('#sign-download')).toBeDisabled();
  const correct = signedXdr(PUBLIC_NETWORK);
  await page.locator('#sign-xdr-signed-xdr').fill(correct);
  await page.locator('#sign-xdr-create').click();
  await expect(page.locator('#sign-status')).toHaveText('XDR proof created from signed XDR.');
  const doc = JSON.parse(await page.locator('#sign-output-json').inputValue());
  expect(doc.signedXdr).toBe(correct);
  expect(doc.signatureB64).toBeUndefined();
  expect(doc.protected.network).toEqual({ passphrase: PUBLIC_NETWORK, hint: 'pubnet' });
  expect(Buffer.from(draft.transaction.operations[0].body.dataValue)).toEqual(sha256(canonical(doc.protected)));
  const changedTx = draft.txXdr.slice();
  new DataView(changedTx.buffer).setUint32(36, 8001, false);
  await page.locator('#sign-xdr-signed-xdr').fill(signedXdr(PUBLIC_NETWORK, changedTx));
  await page.locator('#sign-xdr-create').click();
  await expect(page.locator('#sign-status')).toContainText('differs from the exact unsigned draft');
  // Characterization: a failed repeat does not invalidate the earlier downloadable .sig.
  await expect(page.locator('#sign-download')).toBeEnabled();
  expect(JSON.parse(await page.locator('#sign-output-json').inputValue())).toEqual(doc);
  await page.locator('#nav-verify').click();
  await page.locator('#verify-mode-text').check();
  await page.locator('#verify-text-input').fill('abc');
  await page.locator('#verify-sig-file').setInputFiles({
    name: 'plain-text.sig', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(doc)),
  });
  await expect(page.locator('#verify-run')).toBeEnabled();
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-result-badge')).toHaveText('VALID');
});
