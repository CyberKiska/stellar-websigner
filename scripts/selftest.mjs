import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runSelfTest } from '../src/core/selftest.js';
import { resolveBuildOutputDirectory } from './build.mjs';
import { HTTP_CSP, META_CSP, SECURITY_HEADERS, securityHeadersText } from './security-headers.mjs';
import { resolveSafeFilePath } from './dev.mjs';

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
    ['development server path containment', assertDevServerPathContainment],
    ['test build output variant containment', assertBuildVariantContainment],
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
