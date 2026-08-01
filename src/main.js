/*
    Stellar WebSigner
    Copyright (C) 2026 CyberKiska

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

import { installSessionWipeGuards } from './app/session-wipe.js';
import { assertTopLevelBrowsingContext, FRAMING_POLICY_ERROR_CODE } from './core/deployment-policy.js';
import { assertEd25519RuntimeHealth, assertHashRuntimeHealth, assertWebCryptoAvailable } from './core/runtime-check.js';
import { setupKeysTab } from './ui/keys.js';
import { setupLayout } from './ui/layout.js';
import { setupSignTab } from './ui/sign.js';
import { setupVerifyTab } from './ui/verify.js';

const state = {
  keys: {
    seedBytes: null,
    signingKeySession: null,
    signerAddress: '',
    source: 'none',
  },
  sign: {
    inputContext: null,
    xdrDraft: null,
    lastSignatureDoc: null,
    lastSignatureJson: '',
    lastSignatureFilename: '',
  },
  verify: {
    inputContext: null,
  },
};

async function main() {
  assertTopLevelBrowsingContext({ topWindow: window.top, selfWindow: window.self });
  installSessionWipeGuards();

  assertWebCryptoAvailable();
  await assertHashRuntimeHealth();
  await assertEd25519RuntimeHealth();
  setupLayout(state);
  setupKeysTab(state);
  setupSignTab(state);
  setupVerifyTab(state);
}

try {
  await main();
} catch (err) {
  const message = err instanceof Error ? err.message : String(err);
  const policyBlocked = err?.code === FRAMING_POLICY_ERROR_CODE;
  const unavailableLabel = policyBlocked ? 'Security policy blocked' : 'Cryptography unavailable';
  const statusText = document.getElementById('sys-status-text');
  const statusDot = document.getElementById('sys-status-dot');
  if (statusText) {
    statusText.textContent = unavailableLabel;
    statusText.title = message;
  }
  if (statusDot) statusDot.setAttribute('aria-label', `System status: ${unavailableLabel.toLowerCase()}`);
  for (const control of document.querySelectorAll('button, input, select, textarea')) {
    control.disabled = true;
  }
  const failure = document.createElement('div');
  failure.className = 'startup-failure';
  failure.setAttribute('role', 'alert');
  failure.textContent = policyBlocked
    ? `Application blocked by security policy; all operations are disabled. ${message}`
    : `Cryptography unavailable; all operations are disabled. ${message}`;
  if (policyBlocked) {
    document.title = 'Stellar WebSigner — Security policy blocked';
    document.body.replaceChildren(failure);
  } else {
    document.querySelector('main')?.prepend(failure);
  }
  throw err;
}
