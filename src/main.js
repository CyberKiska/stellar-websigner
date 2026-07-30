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
import { assertEd25519RuntimeHealth, assertRuntimeCryptoHealth } from './core/runtime-check.js';
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
  installSessionWipeGuards();

  assertRuntimeCryptoHealth();
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
  const statusText = document.getElementById('sys-status-text');
  const statusDot = document.getElementById('sys-status-dot');
  if (statusText) {
    statusText.textContent = 'Cryptography unavailable';
    statusText.title = message;
  }
  if (statusDot) statusDot.setAttribute('aria-label', 'System status: cryptography unavailable');
  for (const control of document.querySelectorAll('button, input, select, textarea')) {
    control.disabled = true;
  }
  const failure = document.createElement('div');
  failure.className = 'startup-failure';
  failure.setAttribute('role', 'alert');
  failure.textContent = `Cryptography unavailable; all operations are disabled. ${message}`;
  document.querySelector('main')?.prepend(failure);
  throw err;
}
