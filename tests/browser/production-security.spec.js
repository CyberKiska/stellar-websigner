import { expect, test } from '@playwright/test';

const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const SHA3_512_ABC =
  'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0';
const SEP53_TEST_SEED = 'SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW';
const SEP53_TEST_SIGNER = 'GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L';

test('deployment sends required headers and refuses framing', async ({ page, request, baseURL }) => {
  const response = await request.get('/');
  expect(response.ok()).toBeTruthy();
  const headers = response.headers();
  expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
  expect(headers['content-security-policy']).toContain("connect-src 'none'");
  expect(headers['x-frame-options']).toBe('DENY');
  expect(headers['cross-origin-opener-policy']).toBe('same-origin');
  expect(headers['cross-origin-resource-policy']).toBe('same-origin');
  expect(headers['referrer-policy']).toBe('no-referrer');

  await page.goto('/');
  await page.evaluate((src) => {
    document.body.replaceChildren();
    const iframe = document.createElement('iframe');
    iframe.title = 'framed-signer';
    iframe.src = src;
    document.body.append(iframe);
  }, `${baseURL}/`);
  await page.waitForTimeout(1_000);
  const framedApplication = page.frames().find((frame) => frame !== page.mainFrame());
  const framedHeadingCount = framedApplication
    ? await Promise.race([
        framedApplication.locator('h1').count(),
        new Promise((resolve) => setTimeout(() => resolve(0), 1_000)),
      ])
    : 0;
  expect(framedHeadingCount).toBe(0);
});

test('external-wallet build disables local-secret controls in the browser', async ({ page, browserName }) => {
  await page.goto('http://127.0.0.1:4174/');
  const startupStatus = await page.locator('#sys-status-text').textContent();
  if (startupStatus === 'Cryptography unavailable') {
    expect(browserName).toBe('webkit');
    await expect(page.locator('.startup-failure')).toContainText('all operations are disabled');
    await expect(page.locator('.startup-failure')).toContainText('Ed25519 startup');
    return;
  }

  await expect(page.locator('meta[name="local-secret-operations"]')).toHaveAttribute('content', 'disabled');
  await expect(page.locator('#keys-generate')).toBeDisabled();
  await expect(page.locator('#keys-seed-input')).toBeDisabled();
  await expect(page.locator('#keys-load-seed')).toBeDisabled();
  await expect(page.locator('#keys-copy-seed')).toBeDisabled();
  await expect(page.locator('#keys-g-input')).toBeEnabled();
  await expect(page.locator('#keys-load-g')).toBeEnabled();
});

test('local-secret flow, operation gate, hashing cancellation, signing, and lifecycle cleanup', async ({
  page,
  browserName,
}) => {
  const pageErrors = [];
  page.on('pageerror', (err) => pageErrors.push(err.message));

  await page.goto('/');
  const startupStatus = await page.locator('#sys-status-text').textContent();
  if (startupStatus === 'Cryptography unavailable') {
    expect(browserName).toBe('webkit');
    await expect(page.locator('.startup-failure')).toContainText('all operations are disabled');
    await expect(page.locator('.startup-failure')).toContainText('Ed25519 startup');
    await expect(page.locator('#keys-generate')).toBeDisabled();
    await expect(page.locator('#keys-load-seed')).toBeDisabled();
    await expect(page.locator('#keys-load-g')).toBeDisabled();
    await expect(page.locator('#sign-local-run')).toBeDisabled();
    await expect(page.locator('#verify-run')).toBeDisabled();
    expect(pageErrors.some((message) => message.includes('Ed25519 startup'))).toBeTruthy();
    return;
  }

  await expect(page.locator('#sys-status-text')).toHaveText('No key loaded');
  await expect(page.locator('#keys-generate')).toBeEnabled();

  const providerDelayInstalled = await page.evaluate(() => {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle || typeof subtle.generateKey !== 'function') return false;
    const original = subtle.generateKey.bind(subtle);
    try {
      Object.defineProperty(subtle, 'generateKey', {
        configurable: true,
        value: async (...args) => {
          await new Promise((resolve) => setTimeout(resolve, 350));
          return original(...args);
        },
      });
      return true;
    } catch {
      return false;
    }
  });
  expect(providerDelayInstalled).toBeTruthy();

  await page.evaluate(() => document.querySelector('#keys-generate').click());
  await expect(page.locator('#keys-generate')).toBeDisabled();
  await expect(page.locator('#keys-seed-input')).toBeDisabled();
  await expect(page.locator('#keys-g-input')).toBeDisabled();
  await expect(page.locator('#keys-load-g')).toBeDisabled();
  await expect(page.locator('#keys-clear')).toBeDisabled();

  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
  await page.waitForTimeout(500);
  await expect(page.locator('#keys-generated-g')).toHaveValue('');
  await expect(page.locator('#keys-generated-seed')).toHaveValue('');
  await expect(page.locator('#keys-generate')).toBeEnabled();

  await page.locator('#keys-generate').click();
  await expect(page.locator('#keys-generated-g')).toHaveValue(/^G[A-Z2-7]{55}$/, { timeout: 15_000 });
  await expect(page.locator('#keys-generated-seed')).toHaveValue(/^S[A-Z2-7]{55}$/);
  let signer = await page.locator('#keys-generated-g').inputValue();
  await expect(page.locator('#keys-load-g')).toBeEnabled();

  await page.locator('#keys-seed-input').fill(SEP53_TEST_SEED);
  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('#keys-load-seed').click();
  await expect(page.locator('#keys-generated-g')).toHaveValue(SEP53_TEST_SIGNER, { timeout: 15_000 });
  await expect(page.locator('#keys-generated-seed')).toHaveValue('');
  signer = SEP53_TEST_SIGNER;

  await page.locator('#nav-sign').click();
  await page.locator('#sign-mode-text').check();

  await page.locator('#sign-text-input').fill('x'.repeat(512 * 1024));
  await expect(page.locator('#sign-cancel')).toBeVisible({ timeout: 3_000 });
  await page.locator('#sign-text-input').fill('abc');
  await expect(page.locator('#sign-sha256-hex')).toHaveValue(SHA256_ABC, { timeout: 10_000 });
  await expect(page.locator('#sign-sha3-hex')).toHaveValue(SHA3_512_ABC);

  await expect(page.locator('#sign-local-run')).toBeEnabled();
  await page.locator('#sign-local-run').click();
  await expect(page.locator('#sign-status')).toContainText('Content signature created locally', { timeout: 10_000 });
  const signatureDocument = JSON.parse(await page.locator('#sign-output-json').inputValue());
  expect(signatureDocument.schema).toBe('stellar-signature/v3');
  expect(signatureDocument.signer).toBe(signer);
  expect(signatureDocument.protected.hashes).toEqual([
    { alg: 'SHA-256', hex: SHA256_ABC },
    { alg: 'SHA3-512', hex: SHA3_512_ABC },
  ]);

  await page.locator('#nav-verify').click();
  await page.locator('#verify-mode-text').check();
  await page.locator('#verify-text-input').fill('abd');
  await page.locator('#verify-sig-file').setInputFiles({
    name: 'abc.sig',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(signatureDocument)),
  });
  await expect(page.locator('#verify-run')).toBeEnabled({ timeout: 10_000 });
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-result-badge')).toHaveText('MISMATCH', { timeout: 10_000 });
  await expect(page.locator('#verify-result-title')).toHaveText('Valid Signature, Context Mismatch');
  await expect(page.locator('#verify-details')).toHaveValue(/Signature Valid: YES/);
  await expect(page.locator('#verify-details')).toHaveValue(/Selected Input Matches: NO/);

  await page.locator('#verify-text-input').fill('abc');
  await expect(page.locator('#verify-run')).toBeEnabled({ timeout: 10_000 });
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-result-badge')).toHaveText('VALID', { timeout: 10_000 });

  await page.goto('/missing');
  await page.goBack();
  await expect(page.locator('#sys-status-text')).toHaveText('No key loaded');
  await expect(page.locator('#keys-generated-g')).toHaveValue('');
  await expect(page.locator('#keys-generated-seed')).toHaveValue('');
  expect(pageErrors).toEqual([]);
});
