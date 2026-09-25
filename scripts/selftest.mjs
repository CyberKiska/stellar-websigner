import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runSelfTest } from '../src/core/selftest.js';
import { resolveBuildOutputDirectory } from './build.mjs';
import { HTTP_CSP, META_CSP, SECURITY_HEADERS, securityHeadersText } from './security-headers.mjs';
import { resolveSafeFilePath } from './dev.mjs';
import { verifyArtifactManifest } from './verify-artifact-manifest.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

async function main() {
  const report = await runSelfTest();
  const scriptResults = await runScriptSelfTests();
  const results = [...report.results, ...scriptResults];
  const passed = results.filter((item) => item.ok).length;
  const ok = passed === results.length;

  console.log(`Self-test: ${ok ? 'PASS' : 'FAIL'} (${passed}/${results.length})`);
  for (const item of results) {
    if (item.ok) console.log(`  OK   ${item.name}`);
    else console.log(`  FAIL ${item.name}: ${item.error}`);
  }
  if (!ok) process.exit(1);
}

async function runScriptSelfTests() {
  const tests = [
    ['security headers and meta CSP', assertSecurityHeaders],
    ['form controls opt out of browser form-state persistence', assertFormControlsNotPersisted],
    ['development server path containment', assertDevServerPathContainment],
    ['test build output variant containment', assertBuildVariantContainment],
    ['artifact manifest exact-set and digest verification', assertArtifactManifestVerification],
  ];
  const results = [];
  for (const [name, fn] of tests) {
    try {
      await fn();
      results.push({ name, ok: true });
    } catch (err) {
      results.push({ name, ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return results;
}

async function assertArtifactManifestVerification() {
  const directory = await mkdtemp(path.join(tmpdir(), 'stellar-websigner-artifact-'));
  try {
    await writeFile(path.join(directory, 'payload.txt'), 'abc', 'utf8');
    await writeFile(
      path.join(directory, 'artifact-manifest.sha256'),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  payload.txt\n',
      'utf8'
    );
    await verifyArtifactManifest(directory);
    await writeFile(path.join(directory, 'payload.txt'), 'tampered', 'utf8');
    let rejected = false;
    try {
      await verifyArtifactManifest(directory);
    } catch (err) {
      rejected = String(err?.message || err).includes('Artifact digest mismatch');
    }
    if (!rejected) throw new Error('Artifact verifier accepted a tampered build file.');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function assertBuildVariantContainment() {
  const expected = path.join(root, '.playwright-dist', 'browser-enabled');
  if (resolveBuildOutputDirectory('browser-enabled') !== expected) {
    throw new Error('Build variant did not resolve inside the dedicated test output directory.');
  }
  for (const unsafe of ['..', '../dist', '/tmp/output', 'browser/enabled', '']) {
    if (unsafe === '') continue;
    let rejected = false;
    try {
      resolveBuildOutputDirectory(unsafe);
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error(`Unsafe build variant was accepted: ${unsafe}`);
  }
}

async function assertDevServerPathContainment() {
  const dist = path.join(root, 'dist');
  const expected = path.join(dist, 'index.html');
  if (resolveSafeFilePath('/?cache=1', dist) !== expected) {
    throw new Error('Development server did not resolve root index safely.');
  }
  for (const malicious of ['/../dist-evil/secret', '/%2e%2e/dist-evil/secret', '/%2e%2e/%2e%2e/etc/passwd']) {
    if (resolveSafeFilePath(malicious, dist) !== null) {
      throw new Error(`Development server accepted traversal path: ${malicious}`);
    }
  }
}

async function assertFormControlsNotPersisted() {
  const html = await readFile(path.join(root, 'src', 'index.html'), 'utf8');
  const controls = html.match(/<(?:input|textarea|select)\b[^>]*>/g) || [];
  if (controls.length === 0) throw new Error('No form controls found.');
  for (const control of controls) {
    // Browsers save state of controls without autocomplete="off" for session restore and history.
    if (!/\sautocomplete="off"/.test(control)) throw new Error(`Form control lacks autocomplete="off": ${control}`);
  }
  if (/<(?:input|textarea)\b[^>]*id="keys-generated-seed"/.test(html)) {
    throw new Error('The generated secret seed must not be rendered into a form control.');
  }
}

async function assertSecurityHeaders() {
  const html = await readFile(path.join(root, 'src', 'index.html'), 'utf8');
  const match = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/);
  if (!match) {
    throw new Error('Missing meta Content-Security-Policy.');
  }
  if (match[1] !== META_CSP) {
    throw new Error('Meta CSP does not match scripts/security-headers.mjs META_CSP.');
  }
  if (META_CSP.includes('frame-ancestors')) {
    throw new Error('Meta CSP must not contain frame-ancestors; browsers ignore it in meta CSP.');
  }
  for (const directive of ["require-trusted-types-for 'script'", "trusted-types 'none'"]) {
    if (!META_CSP.includes(directive)) {
      throw new Error(`Meta CSP missing ${directive}.`);
    }
  }
  if (!HTTP_CSP.includes("frame-ancestors 'none'")) {
    throw new Error('HTTP CSP missing frame-ancestors.');
  }
  const headerText = securityHeadersText();
  for (const [name, value] of SECURITY_HEADERS) {
    if (!headerText.includes(`  ${name}: ${value}`)) {
      throw new Error(`Generated _headers missing ${name}.`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
