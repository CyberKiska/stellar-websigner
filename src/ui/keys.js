import { generateKeypair, derivePublicKeyFromSeed } from '../core/ed25519.js';
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

  function dispatchUpdate() {
    window.dispatchEvent(new CustomEvent('keys:updated'));
  }

  function wipeSessionSeed() {
    if (state.keys.seedBytes) {
      wipeBytes(state.keys.seedBytes);
    }
    state.keys.seedBytes = null;
  }

  function setState({ seedBytes = null, signerAddress = '', source = 'none' }) {
    wipeSessionSeed();

    state.keys.seedBytes = seedBytes;
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
    if (!state.keys.signerAddress && !state.keys.seedBytes) {
      lines.push('No keys loaded in active memory.');
      lines.push('You can load G... for verify-only mode or load/generate S... for signing.');
    } else {
      lines.push(`Signer: ${state.keys.signerAddress || '-'}`);
      lines.push(`Mode: ${state.keys.source}`);
      lines.push(`Secret loaded: ${state.keys.seedBytes ? 'YES' : 'NO'}`);
      lines.push('Storage: in-memory only (cleared on reload/end session).');
      if (state.keys.seedBytes) {
        lines.push('Warning: secret seed is active in memory.');
      }
    }

    infoEl.textContent = lines.join('\n');
    exportBtn.disabled = !state.keys.signerAddress;
  }

  function maybeConfirmOverwrite(withSeed = false) {
    if (!state.keys.signerAddress && !state.keys.seedBytes) return true;

    const text = withSeed
      ? 'A session is already loaded. Replace active seed and signer?'
      : 'A session is already loaded. Replace active signer/session?';
    return window.confirm(text);
  }

  function normalizeStrKeyCandidate(rawValue) {
    const trimmed = String(rawValue || '').trim();
    if (!trimmed) return '';
    const token = trimmed.split(/\s+/)[0];
    return token.replace(/^['"]+|['"]+$/g, '');
  }

  async function loadSeedFromInput({ auto = false } = {}) {
    const seedStr = seedInput.value.trim();
    if (!seedStr) {
      if (!auto) showToast('warning', 'Enter S... seed first.');
      return false;
    }

    const seedBytes = decodeEd25519SecretSeed(seedStr);
    const derivedPublic = await derivePublicKeyFromSeed(seedBytes);
    const signer = encodeEd25519PublicKey(derivedPublic);

    const existingG = gInput.value.trim();
    if (existingG && existingG !== signer) {
      throw new Error('G... field does not match signer derived from S...');
    }

    if (!maybeConfirmOverwrite(true)) return false;

    setState({ seedBytes, signerAddress: signer, source: 'imported-seed' });
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

    decodeEd25519PublicKey(g);

    if (!maybeConfirmOverwrite(false)) return false;

    setState({ seedBytes: null, signerAddress: g, source: 'verify-only-g' });
    showToast('success', auto ? 'G... address pasted and loaded automatically.' : 'Public address loaded for verify-only mode.');
    return true;
  }

  generateBtn.addEventListener('click', async () => {
    try {
      if (!maybeConfirmOverwrite(true)) return;

      generateBtn.disabled = true;
      const kp = await generateKeypair();
      const signer = encodeEd25519PublicKey(kp.publicBytes);
      setState({ seedBytes: kp.seedBytes, signerAddress: signer, source: 'generated-seed' });

      showToast('success', 'New Ed25519 keypair generated in memory.');
    } catch (err) {
      showToast('error', friendlyError(err));
    } finally {
      generateBtn.disabled = false;
    }
  });

  loadSeedBtn.addEventListener('click', async () => {
    loadSeedBtn.disabled = true;
    try {
      await loadSeedFromInput({ auto: false });
    } catch (err) {
      showToast('error', friendlyError(err));
    } finally {
      loadSeedBtn.disabled = false;
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

    setTimeout(async () => {
      loadSeedBtn.disabled = true;
      try {
        await loadSeedFromInput({ auto: true });
      } catch (err) {
        showToast('error', friendlyError(err));
      } finally {
        loadSeedBtn.disabled = false;
      }
    }, 0);
  });

  gInput.addEventListener('paste', (event) => {
    const pasted = event.clipboardData?.getData('text') ?? '';
    const normalized = normalizeStrKeyCandidate(pasted);
    if (normalized) {
      event.preventDefault();
      gInput.value = normalized;
    }

    setTimeout(() => {
      try {
        loadSignerFromInput({ auto: true });
      } catch (err) {
        showToast('error', friendlyError(err));
      }
    }, 0);
  });

  exportBtn.addEventListener('click', () => {
    if (!state.keys.signerAddress) return;

    const lines = [];
    lines.push('Stellar WebSigner export');
    lines.push(`createdAt=${new Date().toISOString()}`);
    lines.push(`signer=${state.keys.signerAddress}`);
    lines.push(`mode=${state.keys.source}`);
    if (state.keys.seedBytes) {
      const includeSecret = window.confirm('Include secret seed in export file?');
      lines.push(`secretSeed=${includeSecret ? encodeEd25519SecretSeed(state.keys.seedBytes) : '(redacted)'}`);
    } else {
      lines.push('secretSeed=(not loaded)');
    }

    const fileName = safeFileName(`stellar-keys-${state.keys.signerAddress.slice(0, 8)}.txt`);
    downloadText(fileName, `${lines.join('\n')}\n`);
    showToast('success', 'Key export downloaded.');
  });

  clearBtn.addEventListener('click', () => {
    if (!state.keys.signerAddress && !state.keys.seedBytes) return;

    if (state.keys.seedBytes) {
      const confirmed = window.confirm('End session and wipe secret seed from memory?');
      if (!confirmed) return;
    }

    setState({ seedBytes: null, signerAddress: '', source: 'none' });
    seedInput.value = '';
    gInput.value = '';
    showToast('info', 'Session cleared.');
  });

  copySeedBtn.addEventListener('click', async () => {
    try {
      await copyText(generatedSeedEl.value);
      showToast('success', 'Seed copied.');
    } catch (err) {
      showToast('error', friendlyError(err));
    }
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

  window.addEventListener('beforeunload', () => {
    wipeSessionSeed();
  });

  render();

  return {
    clearSensitiveState() {
      wipeSessionSeed();
    },
  };
}
