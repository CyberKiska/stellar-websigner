import { registerSessionWipeHandler } from '../app/session-wipe.js';
import { base64ToBytes, bytesToBase64, bytesToHexLower } from '../core/bytes.js';
import { PUBLIC_NETWORK_PASSPHRASE } from '../core/constants.js';
import {
  createFileInputContext,
  createTextInputContext,
  MAX_TEXT_INPUT_SIZE_BYTES,
} from '../core/input-context.js';
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

export function setupSignTab(state) {
  const modeFileEl = byId('sign-mode-file');
  const modeTextEl = byId('sign-mode-text');

  const fileGroupEl = byId('sign-file-group');
  const textGroupEl = byId('sign-text-group');
  const fileInput = byId('sign-file-input');
  const textInput = byId('sign-text-input');
  const textPasteBtn = byId('sign-text-paste');
  textInput.maxLength = MAX_TEXT_INPUT_SIZE_BYTES;

  const sha256HexEl = byId('sign-sha256-hex');
  const sha3HexEl = byId('sign-sha3-hex');

  const hashProgressEl = byId('sign-hash-progress');
  const hashProgressLabelEl = byId('sign-hash-progress-label');
  const cancelBtn = byId('sign-cancel');

  const localRunBtn = byId('sign-local-run');
  const localPanelEl = byId('sign-local-panel');
  const xdrPanelEl = byId('sign-xdr-panel');
  const xdrGenerateBtn = byId('sign-xdr-generate');
  const xdrCopyUnsignedBtn = byId('sign-xdr-copy-unsigned');
  const xdrCreateBtn = byId('sign-xdr-create');
  const xdrUnsignedXdrEl = byId('sign-xdr-unsigned-xdr');
  const xdrSignedXdrEl = byId('sign-xdr-signed-xdr');
  const xdrManifestDigestEl = byId('sign-xdr-manifest-digest');

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
  let operationEpoch = 0;
  let contextBusy = false;
  let xdrOperationBusy = false;
  let activeAbortController = null;
  let progressResetTimer = null;

  function syncSigningModePanels() {
    const hasSeed = Boolean(state.keys.signingKeySession?.active);
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
    setStatusBox(statusEl, 'neutral', 'Waiting for input.');
  }

  function resetXdrDraft() {
    state.sign.xdrDraft = null;
    xdrUnsignedXdrEl.value = '';
    xdrManifestDigestEl.textContent = '';
    xdrSignedXdrEl.value = '';
    updateActionAvailability();
  }

  function resetHashProgress() {
    clearTimeout(progressResetTimer);
    hashProgressEl.classList.add('hidden');
    hashProgressEl.value = 0;
    hashProgressLabelEl.textContent = '';
  }

  function scheduleHashProgressReset(delay = 350) {
    clearTimeout(progressResetTimer);
    progressResetTimer = setTimeout(() => resetHashProgress(), delay);
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

  function isAbortError(err) {
    return err?.name === 'AbortError';
  }

  function makeAbortError(message = 'Operation cancelled.') {
    const err = new Error(message);
    err.name = 'AbortError';
    return err;
  }

  function beginAbortableOperation() {
    if (activeAbortController) {
      activeAbortController.abort(makeAbortError());
    }
    const controller = new AbortController();
    activeAbortController = controller;
    cancelBtn.classList.remove('hidden');
    cancelBtn.disabled = false;
    return controller;
  }

  function finishAbortableOperation(controller) {
    if (activeAbortController !== controller) return;
    activeAbortController = null;
    cancelBtn.classList.add('hidden');
    cancelBtn.disabled = true;
  }

  function cancelActiveOperation() {
    if (!activeAbortController) return;
    const controller = activeAbortController;
    controller.abort(makeAbortError());
    cancelBtn.disabled = true;
    contextBusy = false;
    clearCurrentInputContext();
    updateActionAvailability();
    requestAnimationFrame(() => {
      if (activeAbortController === controller) {
        cancelBtn.classList.add('hidden');
        resetHashProgress();
      }
    });
  }

  function throwIfAborted(signal) {
    if (!signal?.aborted) return;
    throw signal.reason instanceof Error ? signal.reason : makeAbortError();
  }

  function clearCurrentInputContext() {
    state.sign.inputContext = null;
    renderDigests(null);
  }

  function hasReadyInputContext() {
    return Boolean(state.sign.inputContext);
  }

  function setActionButtonState(button, enabled) {
    button.disabled = !enabled;
  }

  function updateActionAvailability() {
    const busy = contextBusy || xdrOperationBusy;
    const hasContext = hasReadyInputContext();
    const hasSeed = Boolean(state.keys.signingKeySession?.active);
    const hasSigner = Boolean(String(state.keys.signerAddress || '').trim());
    const hasUnsignedXdr = Boolean(xdrUnsignedXdrEl.value.trim());
    const hasSignedXdr = Boolean(xdrSignedXdrEl.value.trim());

    setActionButtonState(localRunBtn, hasSeed && hasContext && !busy);
    setActionButtonState(xdrGenerateBtn, hasContext && hasSigner && !busy);
    setActionButtonState(xdrCopyUnsignedBtn, hasUnsignedXdr && !busy);
    setActionButtonState(
      xdrCreateBtn,
      hasContext && hasSigner && Boolean(state.sign.xdrDraft) && hasSignedXdr && !busy
    );
  }

  async function buildInputContext({ strict = false, signal = null } = {}) {
    const mode = getInputMode();
    throwIfAborted(signal);

    if (mode === 'file') {
      const file = fileInput.files?.[0] ?? null;
      if (!file) {
        if (strict) throw new Error('Select file input first.');
        return null;
      }

      const context = await createFileInputContext(file, {
        onProgress: setHashProgress,
        signal,
      });
      throwIfAborted(signal);

      scheduleHashProgressReset();
      return context;
    }

    const text = textInput.value;
    if (!text.length) {
      if (strict) throw new Error('Enter plain text first.');
      return null;
    }
    resetHashProgress();
    return createTextInputContext(text, { signal });
  }

  async function refreshDigestContext({ strict = false, silent = false } = {}) {
    const nonce = ++refreshNonce;
    const controller = beginAbortableOperation();
    contextBusy = true;
    updateActionAvailability();
    try {
      const context = await buildInputContext({ strict, signal: controller.signal });
      if (nonce !== refreshNonce) return null;

      clearCurrentInputContext();
      state.sign.inputContext = context;
      renderDigests(context);
      return context;
    } catch (err) {
      if (nonce !== refreshNonce) return null;
      clearCurrentInputContext();
      resetHashProgress();
      if (isAbortError(err)) {
        if (!silent) appendLog(logEl, 'Digest operation cancelled.');
        return null;
      }
      if (strict) throw err;
      if (!silent) {
        appendLog(logEl, `Digest context reset: ${friendlyError(err)}`);
      }
      return null;
    } finally {
      if (nonce === refreshNonce) {
        contextBusy = false;
        finishAbortableOperation(controller);
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
    if (doc?.protected?.proofType === 'sep53-message-signature') {
      return 'Protected Manifest / SEP-53 / Ed25519';
    }
    if (doc?.protected?.proofType === 'xdr-envelope-proof') {
      return 'Protected Manifest / XDR Envelope / Ed25519';
    }
    return `${doc?.protected?.proofType || '-'} / ${doc?.protected?.signatureScheme || '-'}`;
  }

  function describeHashes(doc) {
    if (!Array.isArray(doc?.protected?.hashes) || doc.protected.hashes.length === 0) return '-';
    return doc.protected.hashes.map((item) => `${item.alg}: ${item.hex}`).join(' | ');
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
    outputInputInfoEl.value = describeInputDescriptor(result.doc?.protected?.input);
    outputHashesEl.value = describeHashes(result.doc);
    outputSizeEl.value = describeSignatureSize(result.signatureB64 || result.doc?.signatureB64 || '');
    outputSignatureEl.value = result.signatureB64 || '';
    outputJsonEl.value = result.displayJson || result.json;

    downloadBtn.disabled = false;
    setStatusBox(statusEl, 'valid', statusMessage);
  }

  async function runLocalSign(signal) {
    const signingKeySession = state.keys.signingKeySession;
    if (!signingKeySession?.active) {
      showToast('warning', 'Load secret seed in Keys tab first.');
      setStatusBox(statusEl, 'invalid', 'Local signing requires loaded S... seed.');
      return;
    }

    resetOutput();
    const context = await buildInputContext({ strict: true, signal });
    throwIfAborted(signal);
    setHashProgress({
      phase: 'digest',
      loaded: context.fileSize,
      total: context.fileSize,
      message: 'Signing content...',
    });
    const result = await createLocalSep53MessageSignature({
      inputContext: context,
      signingKeySession,
      signerAddress: state.keys.signerAddress,
    });
    throwIfAborted(signal);
    if (state.keys.signingKeySession !== signingKeySession || !signingKeySession.active) {
      throw new Error('Signing key changed during the operation; result discarded.');
    }

    const signedHashes = result.doc.protected.hashes.map((item) => item.alg).join(', ');
    setSignatureOutput(result, `Content signature created locally (${signedHashes}).`);
    appendLog(logEl, `Local SEP-53 content signature created. signer=${result.signer} hashes=${signedHashes}`);
    showToast('success', 'Content signature created.');
  }

  async function runXdrDraft() {
    resetOutput();
    const epoch = operationEpoch;
    const signerAddress = state.keys.signerAddress || '';
    const context = await refreshDigestContext({ strict: true });
    if (!context) throw makeAbortError();
    if (epoch !== operationEpoch || signerAddress !== state.keys.signerAddress || state.sign.inputContext !== context) {
      throw makeAbortError('Input or signer changed while generating unsigned XDR.');
    }
    const draft = await createXdrProofDraft({
      inputContext: context,
      signerAddress,
      networkPassphrase: PUBLIC_NETWORK_PASSPHRASE,
    });
    if (epoch !== operationEpoch || signerAddress !== state.keys.signerAddress || state.sign.inputContext !== context) {
      throw makeAbortError('Input or signer changed while generating unsigned XDR.');
    }

    state.sign.xdrDraft = draft;
    xdrUnsignedXdrEl.value = draft.unsignedXdr;
    xdrManifestDigestEl.textContent = [
      `name:   ${draft.dataName}`,
      `base64: ${bytesToBase64(draft.manifestDigest)}`,
      `hex:    ${bytesToHexLower(draft.manifestDigest)}`,
    ].join('\n');
    appendLog(
      logEl,
      `Unsigned XDR proof generated. operation=${draft.operationId} signer=${draft.signerAddress} network=public hashes=${draft.boundHashes.map((item) => item.alg).join(', ')}`
    );
    setStatusBox(statusEl, 'neutral', 'Unsigned XDR generated. Sign it in your external wallet and paste the signed XDR.');
    showToast('success', 'Unsigned XDR generated.');
    updateActionAvailability();
  }

  async function runXdrProofCreate() {
    resetOutput();
    const epoch = operationEpoch;
    const draft = state.sign.xdrDraft;
    const expectedSigner = state.keys.signerAddress;
    const signedXdr = xdrSignedXdrEl.value.trim();
    if (!signedXdr) {
      throw new Error('Paste signed XDR first.');
    }
    if (!draft) {
      throw new Error('Generate unsigned XDR first.');
    }
    const context = await refreshDigestContext({ strict: true });
    if (!context) throw makeAbortError();
    if (
      epoch !== operationEpoch ||
      draft !== state.sign.xdrDraft ||
      expectedSigner !== state.keys.signerAddress ||
      signedXdr !== xdrSignedXdrEl.value.trim() ||
      state.sign.inputContext !== context
    ) {
      throw makeAbortError('Input, signer, draft, or signed XDR changed during finalization.');
    }

    const result = await finalizeXdrProof({
      inputContext: context,
      signedXdr,
      draft,
      expectedSigner,
    });
    if (
      epoch !== operationEpoch ||
      draft !== state.sign.xdrDraft ||
      expectedSigner !== state.keys.signerAddress ||
      signedXdr !== xdrSignedXdrEl.value.trim() ||
      state.sign.inputContext !== context
    ) {
      throw makeAbortError('Input, signer, draft, or signed XDR changed during finalization.');
    }

    setSignatureOutput(result, 'XDR proof created from signed XDR.');
    appendLog(
      logEl,
      `XDR proof created. signer=${result.signer} network=public hashes=${result.doc.protected.hashes.map((item) => item.alg).join(', ')}`
    );
    showToast('success', 'Signature file created from signed XDR.');
  }

  function handleInputChanged() {
    operationEpoch += 1;
    cancelActiveOperation();
    resetOutput();
    resetXdrDraft();
    clearCurrentInputContext();
    updateActionAvailability();
  }

  function handleKeysUpdated() {
    operationEpoch += 1;
    cancelActiveOperation();
    resetOutput();
    resetXdrDraft();
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
      if (value.length > MAX_TEXT_INPUT_SIZE_BYTES) {
        throw new Error(`Text input is too large. Maximum supported UTF-8 size is ${MAX_TEXT_INPUT_SIZE_BYTES} bytes.`);
      }
      textInput.value = value;
      modeTextEl.checked = true;
      modeFileEl.checked = false;
      applyInputModeUi();
      handleInputChanged();
      const context = await refreshDigestContext({ strict: true, silent: true });
      if (!context) throw new Error('Pasted text could not be prepared for signing.');
      showToast('success', `Pasted ${value.length} characters.`);
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  localRunBtn.addEventListener('click', async () => {
    const previousLabel = localRunBtn.textContent;
    const controller = beginAbortableOperation();
    contextBusy = true;
    updateActionAvailability();
    localRunBtn.textContent = 'Signing...';
    try {
      await runLocalSign(controller.signal);
    } catch (err) {
      if (isAbortError(err)) {
        resetOutput();
        setStatusBox(statusEl, 'neutral', 'Signing cancelled.');
        appendLog(logEl, 'Local signing cancelled.');
        showToast('warning', 'Signing cancelled.');
        return;
      }
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `Local signing failed: ${msg}`);
      showToast('error', msg);
    } finally {
      contextBusy = false;
      finishAbortableOperation(controller);
      resetHashProgress();
      localRunBtn.textContent = previousLabel;
      updateActionAvailability();
    }
  });

  xdrGenerateBtn.addEventListener('click', async () => {
    const previousLabel = xdrGenerateBtn.textContent;
    xdrOperationBusy = true;
    updateActionAvailability();
    xdrGenerateBtn.textContent = 'Generating...';
    try {
      await runXdrDraft();
    } catch (err) {
      if (isAbortError(err)) {
        setStatusBox(statusEl, 'neutral', 'Unsigned XDR generation cancelled.');
        appendLog(logEl, 'Unsigned XDR generation cancelled.');
        showToast('warning', 'Operation cancelled.');
        return;
      }
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `Unsigned XDR generation failed: ${msg}`);
      showToast('error', msg);
    } finally {
      xdrOperationBusy = false;
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
    xdrOperationBusy = true;
    updateActionAvailability();
    xdrCreateBtn.textContent = 'Creating...';
    try {
      await runXdrProofCreate();
    } catch (err) {
      if (isAbortError(err)) {
        setStatusBox(statusEl, 'neutral', 'XDR proof creation cancelled.');
        appendLog(logEl, 'XDR proof creation cancelled.');
        showToast('warning', 'Operation cancelled.');
        return;
      }
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `XDR proof creation failed: ${msg}`);
      showToast('error', msg);
    } finally {
      xdrOperationBusy = false;
      xdrCreateBtn.textContent = previousLabel;
      updateActionAvailability();
    }
  });

  xdrSignedXdrEl.addEventListener('input', () => {
    operationEpoch += 1;
    resetOutput();
    updateActionAvailability();
  });

  cancelBtn.addEventListener('click', cancelActiveOperation);

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
    cancelActiveOperation();
    clearCurrentInputContext();
    resetXdrDraft();
  });

  window.addEventListener('keys:updated', handleKeysUpdated);
  syncSigningModePanels();
}
