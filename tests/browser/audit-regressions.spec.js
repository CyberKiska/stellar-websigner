import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { mkdir, writeFile, utimes } from 'node:fs/promises';
import path from 'node:path';
import { createTextInputContext } from '../../src/core/input-context.js';
import { createLocalSep53MessageSignature } from '../../src/core/signing.js';
import { derivePublicKeyFromSeed } from '../../src/core/ed25519.js';
import { encodeEd25519PublicKey } from '../../src/core/strkey.js';

const seed = 'SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW';
const fixture = await createLocalSep53MessageSignature({
  seedBytes: new Uint8Array(32).fill(1),
  inputContext: await createTextInputContext('abc'),
});
const otherSigner = encodeEd25519PublicKey(await derivePublicKeyFromSeed(new Uint8Array(32).fill(2)));
const sha256 = (text) => createHash('sha256').update(text).digest('hex');

test.beforeEach(async ({ page, browserName }) => {
  await page.goto('/');
  await expect(page.locator('#sys-status-text')).not.toHaveText('Checking cryptography…');
  if (await page.locator('#sys-status-text').textContent() === 'Cryptography unavailable') {
    expect(browserName).toBe('webkit');
    await expect(page.locator('.startup-failure')).toContainText('Ed25519 startup');
    await expect(page.locator('#keys-load-seed')).toBeDisabled();
    test.skip(true, 'This provider fails the startup Ed25519 KAT; the production-security suite checks fail-closed behavior.');
  }
});

test('file replacement cannot sign bytes different from the reviewed digests', async ({ page }, testInfo) => {
  const inputPath = testInfo.outputPath('mutable.txt');
  await mkdir(path.dirname(inputPath), { recursive: true });
  const timestamp = new Date('2026-01-01T00:00:00.000Z');
  await writeFile(inputPath, 'abc');
  await utimes(inputPath, timestamp, timestamp);
  await page.locator('#keys-seed-input').fill(seed);
  await page.locator('#keys-load-seed').click();
  await expect(page.locator('#sys-status-text')).toHaveText('Signing key active');
  await page.locator('#nav-sign').click();
  await page.locator('#sign-file-input').setInputFiles(inputPath);
  await expect(page.locator('#sign-sha256-hex')).toHaveValue(sha256('abc'));
  await expect(page.locator('#sign-local-run')).toBeEnabled();

  await writeFile(inputPath, 'abd');
  await utimes(inputPath, timestamp, timestamp);
  await page.locator('#sign-local-run').click();
  await expect(page.locator('#sign-local-run')).toHaveText('Sign Locally');
  const output = await page.locator('#sign-output-json').inputValue();
  if (output) {
    // A browser may retain an immutable snapshot of the original file.
    expect(JSON.parse(output).protected.hashes[0].hex).toBe(sha256('abc'));
    await expect(page.locator('#sign-sha256-hex')).toHaveValue(sha256('abc'));
  } else {
    await expect(page.locator('#sign-download')).toBeDisabled();
    if ((await page.locator('#sign-status').textContent()).includes('Input changed')) {
      await expect(page.locator('#sign-status')).toContainText('Review the updated digests and sign again');
      await expect(page.locator('#sign-sha256-hex')).toHaveValue(sha256('abd'));
      await page.locator('#sign-local-run').click();
      await expect(page.locator('#sign-status')).toContainText('Content signature created locally');
      expect(JSON.parse(await page.locator('#sign-output-json').inputValue()).protected.hashes[0].hex).toBe(sha256('abd'));
    } else {
      // Other browsers refuse to read a file whose backing storage changed.
      await expect(page.locator('#sign-status')).toHaveClass(/invalid/);
    }
  }
});

test('verification results and diagnostics clear on every context change', async ({ page }) => {
  const upload = async (doc = fixture.doc) => page.locator('#verify-sig-file').setInputFiles({
    name: 'abc.sig', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(doc)),
  });
  const prepare = async () => {
    await page.locator('#verify-mode-text').check();
    await page.locator('#verify-text-input').fill('abc');
    await page.locator('#verify-expected-signer').fill(fixture.signer);
    await upload();
    await expect(page.locator('#verify-run')).toBeEnabled();
    await page.locator('#verify-run').click();
    await expect(page.locator('#verify-result-badge')).toHaveText('VALID');
  };
  await page.locator('#nav-verify').click();
  for (const change of [
    () => page.locator('#verify-text-input').fill('abd'),
    () => page.locator('#verify-expected-signer').fill(otherSigner),
    () => upload({}),
    () => page.locator('#verify-mode-file').check(),
    async () => {
      await page.evaluate(() => Object.defineProperty(navigator.clipboard, 'readText', { configurable: true, value: async () => 'abd' }));
      await page.locator('#verify-text-paste').click();
    },
    () => page.evaluate(() => window.dispatchEvent(new CustomEvent('keys:updated'))),
    () => page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))),
  ]) {
    await prepare();
    await change();
    await expect(page.locator('#verify-result-card')).toBeHidden();
    await expect(page.locator('#verify-result-badge')).toHaveText('');
    await expect(page.locator('#verify-result-signer')).toHaveValue('');
    await expect(page.locator('#verify-details')).toHaveValue('');
    await expect(page.locator('#verify-copy-signer')).toBeDisabled();
  }
  // A replacement File object must invalidate a completed result too.
  await page.locator('#verify-mode-file').check();
  await page.locator('#verify-file-input').setInputFiles({ name: 'abc.txt', buffer: Buffer.from('abc'), mimeType: 'text/plain' });
  await upload();
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-result-card')).toBeVisible();
  await page.locator('#verify-file-input').setInputFiles({ name: 'abc.txt', buffer: Buffer.from('abd'), mimeType: 'text/plain' });
  await expect(page.locator('#verify-result-card')).toBeHidden();
});

test('an obsolete signature-file read cannot overwrite a newer verification result', async ({ page }) => {
  await page.locator('#nav-verify').click();
  await page.locator('#verify-mode-text').check();
  await page.locator('#verify-text-input').fill('abc');
  await page.locator('#verify-expected-signer').fill(fixture.signer);
  await page.evaluate(() => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    window.releaseSignatureRead = release;
    for (const method of ['text', 'arrayBuffer']) {
      const original = File.prototype[method];
      File.prototype[method] = async function (...args) {
        if (this.name === 'delayed.sig') {
          window.signatureReadStarted = true;
          await gate;
        }
        return original.apply(this, args);
      };
    }
  });
  await page.locator('#verify-sig-file').setInputFiles({ name: 'delayed.sig', buffer: Buffer.from('{}'), mimeType: 'application/json' });
  await expect(page.locator('#verify-run')).toBeEnabled();
  await page.locator('#verify-run').click();
  await expect.poll(() => page.evaluate(() => window.signatureReadStarted)).toBe(true);
  await page.locator('#verify-text-input').fill('abd');
  await page.locator('#verify-text-input').fill('abc');
  await page.locator('#verify-sig-file').setInputFiles({ name: 'current.sig', buffer: Buffer.from(fixture.json), mimeType: 'application/json' });
  await expect(page.locator('#verify-run')).toBeEnabled();
  await expect(page.locator('#verify-run')).toHaveText('Verify Signature');
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-result-badge')).toHaveText('VALID');
  await page.evaluate(async () => { window.releaseSignatureRead(); await new Promise((resolve) => setTimeout(resolve, 0)); });
  await expect(page.locator('#verify-result-card')).toBeVisible();
  await expect(page.locator('#verify-result-badge')).toHaveText('VALID');
  await expect(page.locator('#verify-run')).toHaveText('Verify Signature');
});

test('cancelled provider signing restores the action and cannot publish an obsolete result', async ({ page }) => {
  await page.locator('#keys-seed-input').fill(seed);
  await page.locator('#keys-load-seed').click();
  await expect(page.locator('#sys-status-text')).toHaveText('Signing key active');
  await page.locator('#nav-sign').click();
  await page.locator('#sign-mode-text').check();
  await page.locator('#sign-text-input').fill('abc');
  await expect(page.locator('#sign-local-run')).toBeEnabled();
  await page.evaluate(() => {
    const original = crypto.subtle.sign.bind(crypto.subtle);
    const gate = new Promise((resolve) => { window.releaseSigning = resolve; });
    crypto.subtle.sign = async (...args) => {
      window.signingStarted = true;
      await gate;
      return original(...args);
    };
  });
  await page.locator('#sign-local-run').click();
  await expect.poll(() => page.evaluate(() => window.signingStarted)).toBe(true);
  await page.locator('#sign-text-input').fill('abd');
  await expect(page.locator('#sign-sha256-hex')).toHaveValue(sha256('abd'));
  await expect(page.locator('#sign-local-run')).toBeEnabled();
  await expect(page.locator('#sign-local-run')).toHaveText('Sign Locally');
  await page.evaluate(() => window.releaseSigning());
  await expect(page.locator('#sign-output-json')).toHaveValue('');
  await expect(page.locator('#sign-download')).toBeDisabled();
  await page.locator('#sign-local-run').click();
  await expect(page.locator('#sign-status')).toContainText('Content signature created locally');
  expect(JSON.parse(await page.locator('#sign-output-json').inputValue()).protected.hashes[0].hex).toBe(sha256('abd'));
});

test('a missing expected signer produces an explicit unconfirmed identity result', async ({ page }) => {
  await page.locator('#nav-verify').click();
  await page.locator('#verify-mode-text').check();
  await page.locator('#verify-text-input').fill('abc');
  await page.locator('#verify-sig-file').setInputFiles({ name: 'abc.sig', buffer: Buffer.from(fixture.json), mimeType: 'application/json' });
  await expect(page.locator('#verify-expected-signer')).toHaveValue('');
  await expect(page.locator('#verify-run')).toBeEnabled();
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-result-badge')).toHaveText('UNCONFIRMED');
  await expect(page.locator('#verify-result-card')).toHaveClass(/warning/);
  await expect(page.locator('#verify-details')).toHaveValue(/Expected Signer Matches: NOT SUPPLIED/);
  await page.locator('#verify-expected-signer').fill(fixture.signer);
  await expect(page.locator('#verify-result-card')).toBeHidden();
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-result-badge')).toHaveText('VALID');
});

test('secret inputs clear and remask with or without a loaded signing session', async ({ page }) => {
  await page.locator('#keys-seed-toggle').click();
  await page.locator('#keys-seed-input').fill(seed);
  await page.locator('#keys-clear').click();
  await expect(page.locator('#keys-seed-input')).toHaveValue('');
  await expect(page.locator('#keys-seed-input')).toHaveAttribute('type', 'password');
  await page.locator('#keys-seed-toggle').click();
  await page.locator('#keys-seed-input').fill(seed);
  await page.locator('#keys-load-seed').click();
  await expect(page.locator('#sys-status-text')).toHaveText('Signing key active');
  await expect(page.locator('#keys-seed-input')).toHaveAttribute('type', 'password');
  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('#keys-clear').click();
  await page.locator('#keys-seed-input').fill(seed);
  await expect(page.locator('#keys-seed-input')).toHaveAttribute('type', 'password');
  await expect(page.locator('#keys-seed-toggle')).toHaveText('Show');
  await page.locator('#keys-clear').click();
  await expect(page.locator('#keys-seed-input')).toHaveValue('');
  await page.locator('#keys-seed-toggle').click();
  await page.locator('#keys-seed-input').fill(seed);
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
  await expect(page.locator('#keys-seed-input')).toHaveValue('');
  await expect(page.locator('#keys-seed-input')).toHaveAttribute('type', 'password');
  await expect(page.locator('#keys-generated-seed')).toHaveAttribute('type', 'password');
});
