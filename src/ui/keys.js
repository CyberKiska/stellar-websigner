import { createSigningKeySession, generateKeypair } from '../core/ed25519.js';
import { assertStrictEd25519PublicKey } from '../core/ed25519-validation.js';
import { localSecretOperationsAllowed } from '../core/deployment-policy.js';
import { registerSessionWipeHandler } from '../app/session-wipe.js';
import {
  decodeEd25519PublicKey,
  decodeEd25519SecretSeed,
  encodeEd25519PublicKey,
  encodeEd25519SecretSeed,
} from '../core/strkey.js';
import { wipeBytes } from '../core/bytes.js';
import { byId, copyText, downloadText, friendlyError, safeFileName, showToast } from './common.js';

export function setupKeysTab(state) {
  const generatedSeedEl = byId('keys-generated-seed');
  const generatedGEl = byId('keys-generated-g');

  const seedInput = byId('keys-seed-input');
  const seedToggle = byId('keys-seed-toggle');
  const loadSeedBtn = byId('keys-load-seed');
  const clearSeedFieldBtn = byId('keys-clear-seed-field');

  const gInput = byId('keys-g-input');
  const loadGBtn = byId('keys-load-g');

  const generateBtn = byId('keys-generate');
  const copySeedBtn = byId('keys-copy-seed');
  const copyGBtn = byId('keys-copy-g');

  const exportBtn = byId('keys-export');
  const clearBtn = byId('keys-clear');
  const infoEl = byId('keys-info');
  const localSeedDisabled = !localSecretOperationsAllowed({
    hostname: window.location.hostname,
    isSecureContext: window.isSecureContext,
    buildPolicy: document.querySelector('meta[name="local-secret-operations"]')?.content,
  });

  if (localSeedDisabled) {
    for (const control of [seedInput, seedToggle, loadSeedBtn, clearSeedFieldBtn, generateBtn, copySeedBtn]) {
      control.disabled = true;
    }
    seedInput.placeholder = 'Disabled by deployment security policy';
    generateBtn.title = 'Local secret-key operations are disabled by deployment security policy.';
  }

  function dispatchUpdate() {
    window.dispatchEvent(new CustomEvent('keys:updated'));
  }

  function wipeSessionSeed() {
    state.keys.signingKeySession?.destroy();
    state.keys.signingKeySession = null;
    if (state.keys.seedBytes) {
      wipeBytes(state.keys.seedBytes);
    }
    state.keys.seedBytes = null;
    state.keys.signerAddress = '';
    state.keys.source = 'none';
    seedInput.value = '';
    generatedSeedEl.value = '';
    generatedGEl.value = '';
    generatedSeedEl.type = 'password';
    seedToggle.textContent = 'Show';
  }

  function setState({ seedBytes = null, signingKeySession = null, signerAddress = '', source = 'none' }) {
    wipeSessionSeed();

    state.keys.seedBytes = seedBytes;
    state.keys.signingKeySession = signingKeySession;
    state.keys.signerAddress = signerAddress;
    state.keys.source = source;
    seedInput.value = '';

    render();
    dispatchUpdate();
  }

  function render() {
    const seedVisible = state.keys.seedBytes && state.keys.source === 'generated-seed';
    generatedSeedEl.value = seedVisible ? encodeEd25519SecretSeed(state.keys.seedBytes) : '';
    generatedGEl.value = state.keys.signerAddress || '';

    const lines = [];
    if (!state.keys.signerAddress && !state.keys.signingKeySession) {
      lines.push('No keys loaded in active memory.');
      lines.push('You can load G... for verify-only mode or load/generate S... for signing.');
      if (localSeedDisabled) lines.push('Deployment safety policy: local secret-key operations are disabled; use an external wallet.');
    } else {
      lines.push(`Signer: ${state.keys.signerAddress || '-'}`);
      lines.push(`Mode: ${state.keys.source}`);
      lines.push(`Signing Key: ${state.keys.signingKeySession ? 'Loaded (non-extractable CryptoKey)' : 'Not Loaded'}`);
      lines.push('Cleanup: best-effort on reload/end session; browser memory cannot guarantee zeroization.');
      if (state.keys.seedBytes) {
        lines.push('Warning: generated seed is displayed in memory until this session ends.');
      }
    }

    infoEl.textContent = lines.join('\n');
    exportBtn.disabled = !state.keys.signerAddress;
  }

  function maybeConfirmOverwrite(action) {
    if (!state.keys.signerAddress && !state.keys.signingKeySession) return true;

    let text = 'A session is already loaded. Replace active session?';

    if (state.keys.signingKeySession) {
      if (action === 'generate') {
        text = 'A secret seed is already loaded. Generating a new keypair will overwrite it. Continue?';
      } else if (action === 'import-seed' || action === 'import-signer') {
        text = 'A secret seed is already loaded. Importing will overwrite it. Continue?';
      } else {
        text = 'A secret seed is already loaded. Replace active session?';
      }
    } else if (action === 'import-signer') {
      text = 'A signer is already loaded. Importing will replace the active session. Continue?';
    }

    return window.confirm(text);
  }

  function normalizeStrKeyCandidate(rawValue) {
    const trimmed = String(rawValue || '').trim();
    if (!trimmed) return '';
    const token = trimmed.split(/\s+/)[0];
    return token.replace(/^['"]+|['"]+$/g, '');
  }

  function signerShortToken(signer) {
    const value = String(signer || '').trim();
    if (value.length < 8) return value || 'unknown';
    return `${value.slice(0, 2)}-${value.slice(-6)}`;
  }

  async function loadSeedFromInput({ auto = false } = {}) {
    if (localSeedDisabled) throw new Error('Local secret-key operations are disabled by deployment security policy.');
    const seedStr = seedInput.value.trim();
    if (!seedStr) {
      if (!auto) showToast('warning', 'Enter S... seed first.');
      return false;
    }

    const seedBytes = decodeEd25519SecretSeed(seedStr);
    let signingKeySession = null;
    try {
      signingKeySession = await createSigningKeySession(seedBytes);
    } finally {
      wipeBytes(seedBytes);
      seedInput.value = '';
    }
    const signer = encodeEd25519PublicKey(signingKeySession.publicBytes);

    const existingG = gInput.value.trim();
    if (existingG && existingG !== signer) {
      signingKeySession.destroy();
      throw new Error('G... field does not match signer derived from S...');
    }

    if (!maybeConfirmOverwrite('import-seed')) {
      signingKeySession.destroy();
      return false;
    }

    setState({ signingKeySession, signerAddress: signer, source: 'imported-seed' });
    gInput.value = signer;
    seedInput.value = '';

    showToast('success', auto ? 'Seed pasted and loaded automatically.' : 'Secret seed loaded. Signer derived successfully.');
    return true;
  }

  function loadSignerFromInput({ auto = false } = {}) {
    const g = gInput.value.trim();
    if (!g) {
      if (!auto) showToast('warning', 'Enter G... address first.');
      return false;
    }

    assertStrictEd25519PublicKey(decodeEd25519PublicKey(g));

    if (!maybeConfirmOverwrite('import-signer')) return false;

    setState({ signerAddress: g, source: 'verify-only-g' });
    showToast('success', auto ? 'G... address pasted and loaded automatically.' : 'Public address loaded for verify-only mode.');
    return true;
  }

  generateBtn.addEventListener('click', async () => {
    try {
      if (localSeedDisabled) throw new Error('Local secret-key operations are disabled by deployment security policy.');
      if (!maybeConfirmOverwrite('generate')) return;

      generateBtn.disabled = true;
      generateBtn.textContent = 'Generating...';
      const kp = await generateKeypair();
      const signer = encodeEd25519PublicKey(kp.publicBytes);
      let signingKeySession;
      try {
        signingKeySession = await createSigningKeySession(kp.seedBytes);
      } catch (err) {
        wipeBytes(kp.seedBytes);
        throw err;
      }
      setState({ seedBytes: kp.seedBytes, signingKeySession, signerAddress: signer, source: 'generated-seed' });

      showToast('success', 'New Ed25519 keypair generated in memory.');
    } catch (err) {
      showToast('error', friendlyError(err));
    } finally {
      generateBtn.disabled = localSeedDisabled;
      generateBtn.textContent = 'Generate Keypair';
    }
  });

  loadSeedBtn.addEventListener('click', async () => {
    loadSeedBtn.disabled = true;
    loadSeedBtn.textContent = 'Loading...';
    try {
      await loadSeedFromInput({ auto: false });
    } catch (err) {
      showToast('error', friendlyError(err));
    } finally {
      loadSeedBtn.disabled = localSeedDisabled;
      loadSeedBtn.textContent = 'Load Seed';
    }
  });

  clearSeedFieldBtn.addEventListener('click', () => {
    seedInput.value = '';
    showToast('info', 'Seed input field cleared.');
  });

  loadGBtn.addEventListener('click', () => {
    try {
      loadSignerFromInput({ auto: false });
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  seedInput.addEventListener('paste', (event) => {
    const pasted = event.clipboardData?.getData('text') ?? '';
    const normalized = normalizeStrKeyCandidate(pasted);
    if (normalized) {
      event.preventDefault();
      seedInput.value = normalized;
    }
  });

  gInput.addEventListener('paste', (event) => {
    const pasted = event.clipboardData?.getData('text') ?? '';
    const normalized = normalizeStrKeyCandidate(pasted);
    if (normalized) {
      event.preventDefault();
      gInput.value = normalized;
    }
  });

  exportBtn.addEventListener('click', () => {
    if (!state.keys.signerAddress) return;

    const lines = [];
    lines.push('Stellar WebSigner export');
    lines.push(`createdAt=${new Date().toISOString()}`);
    lines.push(`signer=${state.keys.signerAddress}`);
    lines.push(`mode=${state.keys.source}`);
    lines.push('secretSeed=(never exported by this application)');
    render();

    const fileName = safeFileName(`stellar-keys-export-${signerShortToken(state.keys.signerAddress)}.txt`);
    downloadText(fileName, `${lines.join('\n')}\n`);
    showToast('success', 'Public-only key information downloaded. Secret seed was not included.');
  });

  clearBtn.addEventListener('click', () => {
    if (!state.keys.signerAddress && !state.keys.signingKeySession) return;

    if (state.keys.signingKeySession) {
      const prompt = state.keys.seedBytes
        ? 'End session? Confirm that you recorded the generated seed; it cannot be recovered afterward.'
        : 'End the signing session and release the in-memory signing key?';
      const confirmed = window.confirm(prompt);
      if (!confirmed) return;
    }

    setState({ signerAddress: '', source: 'none' });
    seedInput.value = '';
    gInput.value = '';
    showToast('info', 'Session cleared.');
  });

  copySeedBtn.addEventListener('click', async () => {
    showToast('warning', 'Secret clipboard export is disabled. Record the seed using an offline secure backup procedure.');
  });

  copyGBtn.addEventListener('click', async () => {
    try {
      await copyText(generatedGEl.value);
      showToast('success', 'Signer copied.');
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  seedToggle.addEventListener('click', () => {
    const nextType = seedInput.type === 'password' ? 'text' : 'password';
    seedInput.type = nextType;
    generatedSeedEl.type = nextType;
    seedToggle.textContent = nextType === 'password' ? 'Show' : 'Hide';
  });

  registerSessionWipeHandler(wipeSessionSeed);

  render();

  return {
    clearSensitiveState() {
      wipeSessionSeed();
    },
  };
}
