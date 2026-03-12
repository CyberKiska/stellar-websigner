import { registerSessionWipeHandler } from '../app/session-wipe.js';
import { base64ToBytes, wipeBytes } from '../core/bytes.js';
import { PUBLIC_NETWORK_PASSPHRASE } from '../core/constants.js';
import { createFileInputContext, createTextInputContext } from '../core/input-context.js';
import { createLocalSep53MessageSignature } from '../core/signing.js';
import { createXdrProofDraft, finalizeXdrProof } from '../core/xdr-proof.js';
import {
  byId,
  appendLog,
  copyText,
  downloadText,
  formatBytes,
  friendlyError,
  setStatusBox,
  showToast,
} from './common.js';

const MAX_FILE_CACHE_ENTRIES = 4;

export function setupSignTab(state) {
  const modeFileEl = byId('sign-mode-file');
  const modeTextEl = byId('sign-mode-text');

  const fileGroupEl = byId('sign-file-group');
  const textGroupEl = byId('sign-text-group');
  const fileInput = byId('sign-file-input');
  const textInput = byId('sign-text-input');
  const textPasteBtn = byId('sign-text-paste');

  const sha256HexEl = byId('sign-sha256-hex');
  const sha3HexEl = byId('sign-sha3-hex');

  const hashProgressEl = byId('sign-hash-progress');
  const hashProgressLabelEl = byId('sign-hash-progress-label');

  const localRunBtn = byId('sign-local-run');
  const localPanelEl = byId('sign-local-panel');
  const xdrPanelEl = byId('sign-xdr-panel');
  const xdrGenerateBtn = byId('sign-xdr-generate');
  const xdrCopyUnsignedBtn = byId('sign-xdr-copy-unsigned');
  const xdrCreateBtn = byId('sign-xdr-create');
  const xdrUnsignedXdrEl = byId('sign-xdr-unsigned-xdr');
  const xdrSignedXdrEl = byId('sign-xdr-signed-xdr');

  const outputSignerEl = byId('sign-output-signer');
  const outputProfileEl = byId('sign-output-profile');
  const outputInputInfoEl = byId('sign-output-input-info');
  const outputHashesEl = byId('sign-output-hashes');
  const outputSizeEl = byId('sign-output-size');
  const outputSignatureEl = byId('sign-output-signature');
  const outputJsonLabelEl = byId('sign-output-json-label');
  const outputJsonEl = byId('sign-output-json');
  const downloadBtn = byId('sign-download');
  const copySignerBtn = byId('sign-copy-signer');
  const copySignatureBtn = byId('sign-copy-signature');
  const statusEl = byId('sign-status');
  const logEl = byId('sign-log');

  const copyMap = [
    ['copy-sign-sha256-hex', sha256HexEl],
    ['copy-sign-sha3-hex', sha3HexEl],
  ];

  let textDigestTimer = null;
  let refreshNonce = 0;
  let contextBusy = false;

  function syncSigningModePanels() {
    const hasSeed = Boolean(state.keys.seedBytes);
    localPanelEl.open = hasSeed;
    xdrPanelEl.open = !hasSeed;
    updateActionAvailability();
  }

  function getInputMode() {
    return modeTextEl.checked ? 'text' : 'file';
  }

  function applyInputModeUi() {
    const mode = getInputMode();
    fileGroupEl.classList.toggle('hidden', mode !== 'file');
    textGroupEl.classList.toggle('hidden', mode !== 'text');
  }

  function clearDigests() {
    sha256HexEl.value = '';
    sha3HexEl.value = '';
  }

  function renderDigests(context) {
    if (!context) {
      clearDigests();
      return;
    }
    sha256HexEl.value = context.digests.sha256.hex;
    sha3HexEl.value = context.digests.sha3_512.hex;
  }

  function resetOutput() {
    state.sign.lastSignatureDoc = null;
    state.sign.lastSignatureJson = '';
    state.sign.lastSignatureFilename = '';
    outputSignerEl.value = '';
    outputProfileEl.value = '';
    outputInputInfoEl.value = '';
    outputHashesEl.value = '';
    outputSizeEl.value = '';
    outputSignatureEl.value = '';
    outputJsonEl.value = '';
    downloadBtn.disabled = true;
  }

  function resetXdrDraft() {
    state.sign.xdrDraft = null;
    xdrUnsignedXdrEl.value = '';
    xdrSignedXdrEl.value = '';
    updateActionAvailability();
  }

  function resetHashProgress() {
    hashProgressEl.classList.add('hidden');
    hashProgressEl.value = 0;
    hashProgressLabelEl.textContent = '';
  }

  function setHashProgress({ phase, loaded = 0, total = 0, message = '' }) {
    hashProgressEl.classList.remove('hidden');

    let value = hashProgressEl.value;
    if (phase === 'read' || phase === 'done') {
      value = total > 0 ? Math.round((loaded / total) * 100) : 100;
    } else if (phase === 'digest') {
      value = Math.max(value, 97);
    } else if (phase === 'start') {
      value = 0;
    }

    hashProgressEl.value = Math.min(100, Math.max(0, value));
    hashProgressLabelEl.textContent = message || '';
  }

  function fileCacheKey(file) {
    return `${file.name}|${file.size}|${file.lastModified}`;
  }

  function getCachedFileContext(file) {
    const key = fileCacheKey(file);
    const cache = state.sign.fileContextCache;
    if (!(cache instanceof Map)) return null;
    const value = cache.get(key) || null;
    if (!value) return null;

    cache.delete(key);
    cache.set(key, value);
    return value;
  }

  function putCachedFileContext(file, context) {
    const key = fileCacheKey(file);
    const cache = state.sign.fileContextCache;
    if (!(cache instanceof Map)) return;

    cache.set(key, context);
    while (cache.size > MAX_FILE_CACHE_ENTRIES) {
      const oldestKey = cache.keys().next().value;
      const oldestValue = cache.get(oldestKey);
      wipeInputBytes(oldestValue);
      cache.delete(oldestKey);
    }
  }

  function wipeInputBytes(context) {
    if (context?.bytes instanceof Uint8Array) {
      wipeBytes(context.bytes);
    }
  }

  function clearCurrentInputContext() {
    wipeInputBytes(state.sign.inputContext);
    state.sign.inputContext = null;
    renderDigests(null);
  }

  function wipeCachedInputContexts() {
    if (!(state.sign.fileContextCache instanceof Map)) return;
    for (const value of state.sign.fileContextCache.values()) {
      wipeInputBytes(value);
    }
    state.sign.fileContextCache.clear();
  }

  function hasReadyInputContext() {
    return Boolean(state.sign.inputContext);
  }

  function setActionButtonState(button, enabled) {
    button.disabled = !enabled;
  }

  function updateActionAvailability() {
    const hasContext = hasReadyInputContext();
    const hasSeed = Boolean(state.keys.seedBytes);
    const hasSigner = Boolean(String(state.keys.signerAddress || '').trim());
    const hasUnsignedXdr = Boolean(xdrUnsignedXdrEl.value.trim());
    const hasSignedXdr = Boolean(xdrSignedXdrEl.value.trim());

    setActionButtonState(localRunBtn, hasSeed && hasContext && !contextBusy);
    setActionButtonState(xdrGenerateBtn, hasContext && hasSigner && !contextBusy);
    setActionButtonState(xdrCopyUnsignedBtn, hasUnsignedXdr && !contextBusy);
    setActionButtonState(
      xdrCreateBtn,
      hasContext && hasSigner && Boolean(state.sign.xdrDraft) && hasSignedXdr && !contextBusy
    );
  }

  async function buildInputContext({ strict = false, requireBytes = false } = {}) {
    const mode = getInputMode();

    if (mode === 'file') {
      const file = fileInput.files?.[0] ?? null;
      if (!file) {
        if (strict) throw new Error('Select file input first.');
        return null;
      }

      if (!requireBytes) {
        const cached = getCachedFileContext(file);
        if (cached) {
          setHashProgress({
            phase: 'done',
            loaded: file.size,
            total: file.size,
            message: `Digests loaded from cache for ${file.name}.`,
          });
          setTimeout(() => resetHashProgress(), 600);
          return cached;
        }
      }

      const context = await createFileInputContext(file, {
        onProgress: setHashProgress,
        keepBytes: requireBytes,
      });

      if (!requireBytes) {
        putCachedFileContext(file, context);
      }
      setTimeout(() => resetHashProgress(), 350);
      return context;
    }

    const text = textInput.value;
    if (!text.length) {
      if (strict) throw new Error('Enter plain text first.');
      return null;
    }
    resetHashProgress();
    return createTextInputContext(text, { keepBytes: requireBytes });
  }

  async function refreshDigestContext({ strict = false, silent = false } = {}) {
    const nonce = ++refreshNonce;
    contextBusy = true;
    updateActionAvailability();
    try {
      const context = await buildInputContext({ strict, requireBytes: false });
      if (nonce !== refreshNonce) return null;

      clearCurrentInputContext();
      state.sign.inputContext = context;
      renderDigests(context);
      return context;
    } catch (err) {
      if (nonce !== refreshNonce) return null;
      clearCurrentInputContext();
      resetHashProgress();
      if (strict) throw err;
      if (!silent) {
        appendLog(logEl, `Digest context reset: ${friendlyError(err)}`);
      }
      return null;
    } finally {
      if (nonce === refreshNonce) {
        contextBusy = false;
        updateActionAvailability();
      }
    }
  }

  function describeInputDescriptor(input) {
    if (input?.type === 'file') {
      return `${input.name || 'file'} (${formatBytes(Number(input.size || 0))})`;
    }
    if (input?.type === 'text') {
      return `Plain Text (${formatBytes(Number(input.size || 0))})`;
    }
    return '-';
  }

  function describeProofProfile(doc) {
    if (doc?.proofType === 'sep53-message-signature') {
      return 'SEP-53 Message / Ed25519';
    }
    if (doc?.proofType === 'xdr-envelope-proof') {
      return 'XDR Envelope Proof / Ed25519';
    }
    return `${doc?.proofType || '-'} / ${doc?.signatureScheme || '-'}`;
  }

  function describeHashes(doc) {
    if (!Array.isArray(doc?.hashes) || doc.hashes.length === 0) return '-';
    return doc.hashes.map((item) => `${item.alg}: ${item.hex}`).join(' | ');
  }

  function describeSignatureSize(signatureB64) {
    try {
      return `${base64ToBytes(signatureB64).length} bytes`;
    } catch {
      return '-';
    }
  }

  function setSignatureOutput(result, statusMessage) {
    state.sign.lastSignatureDoc = result.doc;
    state.sign.lastSignatureJson = result.json;
    state.sign.lastSignatureFilename = result.filename;

    outputSignerEl.value = result.signer || '';
    outputProfileEl.value = describeProofProfile(result.doc);
    outputInputInfoEl.value = describeInputDescriptor(result.doc?.input);
    outputHashesEl.value = describeHashes(result.doc);
    outputSizeEl.value = describeSignatureSize(result.signatureB64 || result.doc?.signatureB64 || '');
    outputSignatureEl.value = result.signatureB64 || '';
    outputJsonEl.value = result.displayJson || result.json;

    downloadBtn.disabled = false;
    setStatusBox(statusEl, 'valid', statusMessage);
  }

  async function runLocalSign() {
    if (!state.keys.seedBytes) {
      showToast('warning', 'Load secret seed in Keys tab first.');
      setStatusBox(statusEl, 'invalid', 'Local signing requires loaded S... seed.');
      return;
    }

    let context = null;
    try {
      context = await buildInputContext({ strict: true, requireBytes: true });
      const result = await createLocalSep53MessageSignature({
        inputContext: context,
        seedBytes: state.keys.seedBytes,
        signerAddress: state.keys.signerAddress,
      });

      const signedHashes = result.doc.hashes.map((item) => item.alg).join(', ');
      setSignatureOutput(result, `Content signature created locally (${signedHashes}).`);
      appendLog(logEl, `Local SEP-53 content signature created. signer=${result.signer} hashes=${signedHashes}`);
      showToast('success', 'Content signature created.');
    } finally {
      wipeInputBytes(context);
    }
  }

  async function runXdrDraft() {
    const context = await refreshDigestContext({ strict: true });
    const draft = createXdrProofDraft({
      inputContext: context,
      signerAddress: state.keys.signerAddress || '',
      networkPassphrase: PUBLIC_NETWORK_PASSPHRASE,
    });

    state.sign.xdrDraft = draft;
    xdrUnsignedXdrEl.value = draft.unsignedXdr;
    appendLog(
      logEl,
      `Unsigned XDR proof generated. signer=${draft.signerAddress} network=public hashes=${draft.boundHashes.map((item) => item.alg).join(', ')}`
    );
    setStatusBox(statusEl, 'neutral', 'Unsigned XDR generated. Sign it in your external wallet and paste the signed XDR.');
    showToast('success', 'Unsigned XDR generated.');
    updateActionAvailability();
  }

  async function runXdrProofCreate() {
    const context = await refreshDigestContext({ strict: true });
    const signedXdr = xdrSignedXdrEl.value.trim();
    if (!signedXdr) {
      throw new Error('Paste signed XDR first.');
    }
    if (!state.sign.xdrDraft) {
      throw new Error('Generate unsigned XDR first.');
    }

    const result = await finalizeXdrProof({
      inputContext: context,
      signedXdr,
      networkPassphrase: state.sign.xdrDraft.networkPassphrase,
      expectedSigner: state.keys.signerAddress,
      expectedManageDataEntries: state.sign.xdrDraft.boundHashes,
      hashSelection: state.sign.xdrDraft.hashSelection,
    });

    setSignatureOutput(result, 'XDR proof created from signed XDR.');
    appendLog(
      logEl,
      `XDR proof created. signer=${result.signer} network=public hashes=${result.doc.hashes.map((item) => item.alg).join(', ')}`
    );
    showToast('success', 'Signature file created from signed XDR.');
  }

  function handleInputChanged() {
    resetOutput();
    resetXdrDraft();
    clearCurrentInputContext();
    updateActionAvailability();
  }

  function handleKeysUpdated() {
    const activeSigner = String(state.keys.signerAddress || '').trim();
    if (state.sign.xdrDraft && state.sign.xdrDraft.signerAddress !== activeSigner) {
      resetXdrDraft();
    }
    syncSigningModePanels();
  }

  modeFileEl.addEventListener('change', async () => {
    applyInputModeUi();
    handleInputChanged();
    await refreshDigestContext({ silent: true });
  });

  modeTextEl.addEventListener('change', async () => {
    applyInputModeUi();
    handleInputChanged();
    await refreshDigestContext({ silent: true });
  });

  fileInput.addEventListener('change', async () => {
    handleInputChanged();
    await refreshDigestContext();
  });

  textInput.addEventListener('input', () => {
    handleInputChanged();
    clearTimeout(textDigestTimer);
    textDigestTimer = setTimeout(() => {
      refreshDigestContext({ silent: true }).catch(() => {});
    }, 180);
  });

  textPasteBtn.addEventListener('click', async () => {
    if (!navigator.clipboard?.readText) {
      showToast('warning', 'Clipboard API is unavailable.');
      return;
    }
    try {
      const value = await navigator.clipboard.readText();
      textInput.value = value;
      modeTextEl.checked = true;
      modeFileEl.checked = false;
      applyInputModeUi();
      handleInputChanged();
      await refreshDigestContext({ silent: true });
      showToast('success', `Pasted ${value.length} characters.`);
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  localRunBtn.addEventListener('click', async () => {
    const previousLabel = localRunBtn.textContent;
    contextBusy = true;
    updateActionAvailability();
    localRunBtn.textContent = 'Signing...';
    try {
      await runLocalSign();
    } catch (err) {
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `Local signing failed: ${msg}`);
      showToast('error', msg);
    } finally {
      contextBusy = false;
      localRunBtn.textContent = previousLabel;
      updateActionAvailability();
    }
  });

  xdrGenerateBtn.addEventListener('click', async () => {
    const previousLabel = xdrGenerateBtn.textContent;
    xdrGenerateBtn.textContent = 'Generating...';
    try {
      await runXdrDraft();
    } catch (err) {
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `Unsigned XDR generation failed: ${msg}`);
      showToast('error', msg);
    } finally {
      xdrGenerateBtn.textContent = previousLabel;
      updateActionAvailability();
    }
  });

  xdrCopyUnsignedBtn.addEventListener('click', async () => {
    try {
      await copyText(xdrUnsignedXdrEl.value);
      showToast('success', 'Unsigned XDR copied.');
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  xdrCreateBtn.addEventListener('click', async () => {
    const previousLabel = xdrCreateBtn.textContent;
    xdrCreateBtn.textContent = 'Creating...';
    try {
      await runXdrProofCreate();
    } catch (err) {
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `XDR proof creation failed: ${msg}`);
      showToast('error', msg);
    } finally {
      xdrCreateBtn.textContent = previousLabel;
      updateActionAvailability();
    }
  });

  xdrSignedXdrEl.addEventListener('input', () => {
    updateActionAvailability();
  });

  copySignerBtn.addEventListener('click', async () => {
    try {
      await copyText(outputSignerEl.value);
      showToast('success', 'Signer copied.');
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  copySignatureBtn.addEventListener('click', async () => {
    try {
      await copyText(outputSignatureEl.value);
      showToast('success', 'Signature copied.');
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  downloadBtn.addEventListener('click', () => {
    if (!state.sign.lastSignatureJson) return;
    downloadText(state.sign.lastSignatureFilename || 'signature.sig', state.sign.lastSignatureJson, 'application/json');
    showToast('success', 'Signature file downloaded.');
  });

  for (const [buttonId, inputEl] of copyMap) {
    byId(buttonId).addEventListener('click', async () => {
      try {
        await copyText(inputEl.value);
        showToast('success', 'Copied.');
      } catch (err) {
        showToast('error', friendlyError(err));
      }
    });
  }

  applyInputModeUi();
  outputJsonLabelEl.textContent = 'Signature JSON';
  clearDigests();
  resetOutput();
  resetHashProgress();
  resetXdrDraft();
  setStatusBox(statusEl, 'neutral', 'Waiting for input.');
  updateActionAvailability();

  registerSessionWipeHandler(() => {
    clearCurrentInputContext();
    wipeCachedInputContexts();
    resetXdrDraft();
  });

  window.addEventListener('keys:updated', handleKeysUpdated);
  syncSigningModePanels();
}
