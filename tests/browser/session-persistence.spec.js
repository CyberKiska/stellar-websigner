import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { expect, test } from '@playwright/test';

// Regression for browser session-restore persistence: form-control state that is not opted out is
// serialized to the profile on disk (Chromium Sessions/*, Firefox sessionstore*.jsonlz4) and survives
// the application's own wipe. Uses a throwaway profile and a freshly generated key.
const MARKER = 'session-persistence-marker-4c1d9e';

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
  const nested = await Promise.all(entries.map((entry) => {
    const absolute = path.join(directory, entry.name);
    return entry.isDirectory() ? listFiles(absolute) : [absolute];
  }));
  return nested.flat();
}

// Firefox stores session files as "mozLz40\0" + uint32le length + one LZ4 block.
function decodeMozLz4(buffer) {
  if (buffer.subarray(0, 8).toString('latin1') !== 'mozLz40\0') return buffer;
  const source = buffer.subarray(12);
  const output = Buffer.alloc(buffer.readUInt32LE(8));
  let input = 0;
  let written = 0;
  while (input < source.length) {
    const token = source[input++];
    let literals = token >> 4;
    if (literals === 15) for (let b = 255; b === 255; literals += b) b = source[input++];
    source.copy(output, written, input, input + literals);
    input += literals;
    written += literals;
    if (input >= source.length) break;
    const offset = source[input] | (source[input + 1] << 8);
    input += 2;
    let length = (token & 15) + 4;
    if ((token & 15) === 15) for (let b = 255; b === 255; length += b) b = source[input++];
    for (let i = 0; i < length; i += 1) output[written + i] = output[written - offset + i];
    written += length;
  }
  return output.subarray(0, written);
}

async function filesContaining(directory, needle) {
  const hits = [];
  for (const file of await listFiles(directory)) {
    // The HTTP cache legitimately holds the application bundle and is not session state.
    if (/[\\/](Cache|cache2)[\\/]/.test(file)) continue;
    const bytes = await readFile(file).catch(() => null);
    if (!bytes) continue;
    const decoded = decodeMozLz4(bytes);
    if (decoded.includes(Buffer.from(needle, 'latin1')) || decoded.includes(Buffer.from(needle, 'utf16le'))) {
      hits.push(path.relative(directory, file));
    }
  }
  return hits;
}

test('revealed seeds and typed content are not written to browser session-restore state', async (
  { playwright, browserName, baseURL },
  testInfo
) => {
  test.skip(browserName === 'webkit', 'WebKit fails the startup Ed25519 KAT, so no key can be generated.');
  test.setTimeout(90_000);
  const profile = testInfo.outputPath('profile');
  const context = await playwright[browserName].launchPersistentContext(profile, {
    baseURL,
    // Full Chromium (not the headless shell) includes the session-restore service.
    ...(browserName === 'chromium' ? { channel: 'chromium' } : {}),
    ...(browserName === 'firefox' ? { firefoxUserPrefs: { 'browser.sessionstore.interval': 1000 } } : {}),
  });
  let seed = '';
  try {
    const page = context.pages()[0] || (await context.newPage());
    await page.goto('/');
    await expect(page.locator('#sys-status-text')).toHaveText('No key loaded');
    await page.locator('#keys-generate').click();
    await expect(page.locator('#keys-generated-seed-toggle')).toBeEnabled({ timeout: 15_000 });
    await expect(page.locator('#keys-generated-seed')).toHaveText('');
    await page.locator('#keys-generated-seed-toggle').click();
    await expect(page.locator('#keys-generated-seed')).toHaveText(/^S[A-Z2-7]{55}$/);
    seed = await page.locator('#keys-generated-seed').textContent();

    await page.locator('#nav-sign').click();
    await page.locator('#sign-mode-text').check();
    await page.locator('#sign-text-input').fill(MARKER);
    await page.locator('#sign-xdr-panel > summary').click();
    await page.locator('#sign-xdr-signed-xdr').fill(MARKER);
    await page.locator('#nav-verify').click();
    await page.locator('#verify-mode-text').check();
    await page.locator('#verify-text-input').fill(MARKER);
    // Chromium syncs page state within ~1 s; Firefox collects at the configured interval.
    await page.waitForTimeout(6_000);
    expect(await filesContaining(profile, seed)).toEqual([]);
    expect(await filesContaining(profile, MARKER)).toEqual([]);
  } finally {
    await context.close();
  }
  expect(await filesContaining(profile, seed)).toEqual([]);
  expect(await filesContaining(profile, MARKER)).toEqual([]);
});
