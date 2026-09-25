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
  const generatedSeedToggle = byId('keys-generated-seed-toggle');
  const copyGBtn = byId('keys-copy-g');

  const exportBtn = byId('keys-export');
  const clearBtn = byId('keys-clear');
  const infoEl = byId('keys-info');
  const localSeedDisabled = !localSecretOperationsAllowed({
    hostname: window.location.hostname,
    isSecureContext: window.isSecureContext,
    buildPolicy: document.querySelector('meta[name="local-secret-operations"]')?.content,
  });
  const secretMutationControls = [seedInput, seedToggle, loadSeedBtn, clearSeedFieldBtn, generateBtn];
  const publicMutationControls = [gInput, loadGBtn];
  let keyOperationEpoch = 0;
  let keyOperationBusy = false;
  // The generated seed is rendered as a text node only while revealed. Form controls are avoided on
  // purpose: browsers persist their state for session restore, outside the application's control.
  let generatedSeedDisplay = '';
  let generatedSeedRevealed = false;

  function updateKeyControls() {
    for (const control of secretMutationControls) {
      control.disabled = localSeedDisabled || keyOperationBusy;
    }
    for (const control of publicMutationControls) {
      control.disabled = keyOperationBusy;
    }
    clearBtn.disabled = keyOperationBusy;
    generatedSeedToggle.disabled = localSeedDisabled || keyOperationBusy || !generatedSeedDisplay;
    if (localSeedDisabled) {
      seedInput.placeholder = 'Disabled by deployment security policy';
      generateBtn.title = 'Local secret-key operations are disabled by deployment security policy.';
    }
  }

  function beginKeyOperation() {
    if (keyOperationBusy) return null;
    keyOperationBusy = true;
    keyOperationEpoch += 1;
    updateKeyControls();
    return keyOperationEpoch;
  }

  function keyOperationIsCurrent(epoch) {
    return keyOperationBusy && keyOperationEpoch === epoch;
  }

  function finishKeyOperation(epoch) {
    if (keyOperationEpoch !== epoch) return;
    keyOperationBusy = false;
    updateKeyControls();
  }

  function invalidateKeyOperations() {
    keyOperationEpoch += 1;
    keyOperationBusy = false;
    updateKeyControls();
  }

  if (localSeedDisabled) {
    seedInput.placeholder = 'Disabled by deployment security policy';
    generateBtn.title = 'Local secret-key operations are disabled by deployment security policy.';
  }

  function dispatchUpdate() {
    window.dispatchEvent(new CustomEvent('keys:updated'));
  }

  function wipeSessionSeed({ invalidateOperations = false } = {}) {
    if (invalidateOperations) invalidateKeyOperations();
    state.keys.signingKeySession?.destroy();
    state.keys.signingKeySession = null;
    if (state.keys.seedBytes) {
      wipeBytes(state.keys.seedBytes);
    }
    state.keys.seedBytes = null;
    state.keys.signerAddress = '';
    state.keys.source = 'none';
    generatedSeedDisplay = '';
    generatedSeedRevealed = false;
    seedInput.value = '';
    seedInput.type = 'password';
    seedToggle.textContent = 'Show';
    generatedSeedEl.textContent = '';
    generatedGEl.value = '';
    renderGeneratedSeed();
  }

  function renderGeneratedSeed() {
    generatedSeedEl.textContent = generatedSeedDisplay && generatedSeedRevealed ? generatedSeedDisplay : '';
    generatedSeedEl.dataset.emptyText = generatedSeedDisplay
      ? 'Hidden. Select Reveal to display it for offline backup.'
      : 'No generated seed';
    generatedSeedToggle.textContent = generatedSeedRevealed ? 'Hide' : 'Reveal';
    generatedSeedToggle.setAttribute('aria-expanded', String(generatedSeedRevealed));
  }

  function setState({ seedBytes = null, signingKeySession = null, signerAddress = '', source = 'none' }) {
    wipeSessionSeed();

    state.keys.seedBytes = seedBytes;
    state.keys.signingKeySession = signingKeySession;
    state.keys.signerAddress = signerAddress;
    state.keys.source = source;
    generatedSeedDisplay =
      seedBytes && source === 'generated-seed' ? encodeEd25519SecretSeed(seedBytes) : '';
    seedInput.value = '';

    render();
    dispatchUpdate();
  }

  function render() {
    renderGeneratedSeed();
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
    updateKeyControls();
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
    if (!maybeConfirmOverwrite('import-seed')) return false;
    const epoch = beginKeyOperation();
    if (epoch === null) return false;
    let seedBytes = null;
    let signingKeySession = null;
    let committed = false;
    try {
      seedBytes = decodeEd25519SecretSeed(seedStr);
      seedInput.value = '';
      signingKeySession = await createSigningKeySession(seedBytes);
      if (!keyOperationIsCurrent(epoch)) return false;
      const signer = encodeEd25519PublicKey(signingKeySession.publicBytes);

      const existingG = gInput.value.trim();
      if (existingG && existingG !== signer) {
        throw new Error('G... field does not match signer derived from S...');
      }

      setState({ signingKeySession, signerAddress: signer, source: 'imported-seed' });
      committed = true;
      gInput.value = signer;
      showToast('success', auto ? 'Seed pasted and loaded automatically.' : 'Secret seed loaded. Signer derived successfully.');
      return true;
    } finally {
      wipeBytes(seedBytes);
      seedInput.value = '';
      if (!committed) signingKeySession?.destroy();
      finishKeyOperation(epoch);
    }
  }

  function loadSignerFromInput({ auto = false } = {}) {
    if (keyOperationBusy) return false;
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
    let epoch = null;
    let kp = null;
    let signingKeySession = null;
    let committed = false;
    try {
      if (localSeedDisabled) throw new Error('Local secret-key operations are disabled by deployment security policy.');
      if (!maybeConfirmOverwrite('generate')) return;

      epoch = beginKeyOperation();
      if (epoch === null) return;
      generateBtn.textContent = 'Generating...';
      kp = await generateKeypair();
      if (!keyOperationIsCurrent(epoch)) return;
      const signer = encodeEd25519PublicKey(kp.publicBytes);
      signingKeySession = await createSigningKeySession(kp.seedBytes, { publicBytes: kp.publicBytes });
      if (!keyOperationIsCurrent(epoch)) return;
      setState({ seedBytes: kp.seedBytes, signingKeySession, signerAddress: signer, source: 'generated-seed' });
      committed = true;

      showToast('success', 'New Ed25519 keypair generated in memory.');
    } catch (err) {
      showToast('error', friendlyError(err));
    } finally {
      if (!committed) {
        signingKeySession?.destroy();
        wipeBytes(kp?.seedBytes);
      }
      if (epoch !== null) finishKeyOperation(epoch);
      generateBtn.textContent = 'Generate Keypair';
      updateKeyControls();
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
      loadSeedBtn.textContent = 'Load Seed';
      updateKeyControls();
    }
  });

  clearSeedFieldBtn.addEventListener('click', () => {
    seedInput.value = '';
    showToast('info', 'Seed input field cleared.');
  });

  loadGBtn.addEventListener('click', () => {
    if (keyOperationBusy) return;
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

    const fileName = safeFileName(`stellar-keys-export-${signerShortToken(state.keys.signerAddress)}.txt`);
    downloadText(fileName, `${lines.join('\n')}\n`);
    showToast('success', 'Public-only key information downloaded. Secret seed was not included.');
  });

  clearBtn.addEventListener('click', () => {
    if (keyOperationBusy) return;
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

  generatedSeedToggle.addEventListener('click', () => {
    if (!generatedSeedDisplay) return;
    generatedSeedRevealed = !generatedSeedRevealed;
    renderGeneratedSeed();
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
    seedToggle.textContent = nextType === 'password' ? 'Show' : 'Hide';
  });

  registerSessionWipeHandler(() => {
    wipeSessionSeed({ invalidateOperations: true });
    render();
  });

  render();

  return {
    clearSensitiveState() {
      wipeSessionSeed();
    },
  };
}
