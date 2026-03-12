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
import { assertRuntimeCryptoHealth } from './core/runtime-check.js';
import { setupKeysTab } from './ui/keys.js';
import { setupLayout } from './ui/layout.js';
import { setupSignTab } from './ui/sign.js';
import { setupVerifyTab } from './ui/verify.js';
import { showToast } from './ui/common.js';

const state = {
  keys: {
    seedBytes: null,
    signerAddress: '',
    source: 'none',
    exported: false,
  },
  sign: {
    inputContext: null,
    fileContextCache: new Map(),
    xdrDraft: null,
    lastSignatureDoc: null,
    lastSignatureJson: '',
    lastSignatureFilename: '',
  },
  verify: {
    inputContext: null,
  },
};

function main() {
  installSessionWipeGuards();

  setupLayout(state);
  assertRuntimeCryptoHealth();
  setupKeysTab(state);
  setupSignTab(state);
  setupVerifyTab(state);
}

try {
  main();
} catch (err) {
  showToast('error', err instanceof Error ? err.message : String(err));
  throw err;
}
