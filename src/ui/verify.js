import { registerSessionWipeHandler } from '../app/session-wipe.js';
import {
  createFileInputContext,
  createTextInputContext,
  MAX_TEXT_INPUT_SIZE_BYTES,
} from '../core/input-context.js';
import { safeJsonParse } from '../core/bytes.js';
import { decodeEd25519PublicKey } from '../core/strkey.js';
import { diagnosticsForDisplay, verifyDetachedSignature } from '../core/verify.js';
import { byId, appendLog, copyText, friendlyError, readFileText, showToast } from './common.js';

export function setupVerifyTab(state) {
  const modeFileEl = byId('verify-mode-file');
  const modeTextEl = byId('verify-mode-text');
  const fileGroupEl = byId('verify-file-group');
  const textGroupEl = byId('verify-text-group');

  const fileInput = byId('verify-file-input');
  const textInput = byId('verify-text-input');
  const textPasteBtn = byId('verify-text-paste');
  textInput.maxLength = MAX_TEXT_INPUT_SIZE_BYTES;

  const sigFileInput = byId('verify-sig-file');
  const expectedSignerEl = byId('verify-expected-signer');
  const runBtn = byId('verify-run');
  const cancelBtn = byId('verify-cancel');
  const progressEl = byId('verify-progress');
  const progressLabelEl = byId('verify-progress-label');

  const resultCard = byId('verify-result-card');
  const resultTitle = byId('verify-result-title');
  const resultBadge = byId('verify-result-badge');
  const resultMessage = byId('verify-result-message');
  const resultSigner = byId('verify-result-signer');
  const resultSignerLabel = byId('verify-result-signer-label');
  const resultChecked = byId('verify-result-checked');
  const resultDetails = byId('verify-details');

  const copySignerBtn = byId('verify-copy-signer');
  const logEl = byId('verify-log');

  let refreshNonce = 0;
  let verificationEpoch = 0;
  let contextBusy = false;
  let autoExpectedSigner = '';
  let expectedSignerOverridden = false;
  let activeAbortController = null;

  function setResultCardMode(mode) {
    resultCard.classList.remove('valid', 'invalid', 'warning');
    if (mode) resultCard.classList.add(mode);
  }

  function invalidateResult() {
    resultCard.classList.add('hidden');
    setResultCardMode(null);
    resultMessage.textContent = '';
    resultSigner.value = '';
    resultChecked.value = '';
    resultDetails.value = '';
  }

  // A verdict describes the inputs it was computed from; any edit retracts it.
  function inputsChanged() {
    verificationEpoch += 1;
    invalidateResult();
  }

  function getMode() {
    return modeTextEl.checked ? 'text' : 'file';
  }

  function selectedFile() {
    return fileInput.files?.[0] ?? null;
  }

  function applyModeUi() {
    const mode = getMode();
    fileGroupEl.classList.toggle('hidden', mode !== 'file');
    textGroupEl.classList.toggle('hidden', mode !== 'text');
  }

  function clearInputContext() {
    state.verify.inputContext = null;
  }

  function hasSignatureReady() {
    return Boolean(sigFileInput.files?.[0]);
  }

  function hasReadyInputContext() {
    return Boolean(state.verify.inputContext);
  }

  function updateRunAvailability() {
    runBtn.disabled = contextBusy || !hasReadyInputContext() || !hasSignatureReady();
  }

  function resetProgress() {
    progressEl.classList.add('hidden');
    progressEl.value = 0;
    progressLabelEl.textContent = '';
  }

  function setProgress({ phase, loaded = 0, total = 0, message = '' }) {
    progressEl.classList.remove('hidden');
    let value = progressEl.value;
    if (phase === 'read' || phase === 'done') {
      value = total > 0 ? Math.round((loaded / total) * 100) : 100;
    } else if (phase === 'digest') {
      value = Math.max(value, 97);
    } else if (phase === 'start') {
      value = 0;
    }
    progressEl.value = Math.min(100, Math.max(0, value));
    progressLabelEl.textContent = message || '';
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
    clearInputContext();
    updateRunAvailability();
    requestAnimationFrame(() => {
      if (activeAbortController === controller) {
        cancelBtn.classList.add('hidden');
        resetProgress();
      }
    });
  }

  function throwIfAborted(signal) {
    if (!signal?.aborted) return;
    throw signal.reason instanceof Error ? signal.reason : makeAbortError();
  }

  function syncExpectedSignerFromSession() {
    const loadedSigner = String(state.keys.signerAddress || '').trim();
    if (!expectedSignerOverridden || expectedSignerEl.value.trim() === autoExpectedSigner) {
      expectedSignerEl.value = loadedSigner;
      autoExpectedSigner = loadedSigner;
      expectedSignerOverridden = false;
    }
  }

  async function buildInputContext({ strict = false, signal = null } = {}) {
    throwIfAborted(signal);
    if (getMode() === 'file') {
      const file = selectedFile();
      if (!file) {
        if (strict) throw new Error('Select original file for verification.');
        return null;
      }
      const context = await createFileInputContext(file, { onProgress: setProgress, signal });
      throwIfAborted(signal);
      return context;
    }

    const text = textInput.value;
    if (!text.length) {
      if (strict) throw new Error('Enter original plain text for verification.');
      return null;
    }
    return createTextInputContext(text, { signal });
  }

  async function refreshDigestContext({ strict = false, signal = null, silent = false } = {}) {
    const nonce = ++refreshNonce;
    const controller = signal ? null : beginAbortableOperation();
    const opSignal = signal || controller.signal;
    if (controller) {
      contextBusy = true;
      updateRunAvailability();
    }
    try {
      const context = await buildInputContext({ strict, signal: opSignal });
      if (nonce !== refreshNonce) return null;
      clearInputContext();
      state.verify.inputContext = context;
      return context;
    } catch (err) {
      if (nonce !== refreshNonce) return null;
      clearInputContext();
      resetProgress();
      if (isAbortError(err)) {
        if (!silent) appendLog(logEl, 'Digest operation cancelled.');
        return null;
      }
      if (strict) throw err;
      return null;
    } finally {
      if (nonce === refreshNonce) {
        if (controller) contextBusy = false;
        if (controller) finishAbortableOperation(controller);
        updateRunAvailability();
      }
    }
  }

  async function readSignatureDoc() {
    const file = sigFileInput.files?.[0] ?? null;
    if (!file) {
      throw new Error('Select signature .sig file.');
    }
    return safeJsonParse(await readFileText(file, { maxBytes: 256 * 1024 }), {
      maxLength: 256 * 1024,
      maxDepth: 16,
    });
  }

  function setResult(mode, title, badge, message) {
    setResultCardMode(mode === 'neutral' ? null : mode);
    resultTitle.textContent = title;
    resultBadge.textContent = badge;
    resultBadge.className = `badge ${mode}`;
    resultBadge.setAttribute('aria-label', `Verification result: ${badge.toLowerCase()}`);
    resultMessage.textContent = message;
  }

  function renderReport(report) {
    resultCard.classList.remove('hidden');
    // Metadata of a failed proof is attacker-controlled; never present it as the signer or checked data.
    const authenticated = report.signatureValid === true;
    resultSignerLabel.textContent = authenticated ? 'Signer' : 'Claimed Signer (not authenticated)';
    resultSigner.value = report.signer || '';
    resultChecked.value =
      authenticated && Array.isArray(report.checked?.hashes) && report.checked.hashes.length > 0
        ? report.checked.hashes.map((item) => `${item.alg}: ${item.hex}`).join(' | ')
        : '-';
    resultDetails.value = diagnosticsForDisplay(report);

    switch (report.summary) {
      case 'VALID':
        setResult('valid', 'Signature Valid', 'VALID', 'Signature is valid for the selected input and the expected signer.');
        showToast('success', 'Verification successful.');
        return;
      case 'VALID_WITH_WARNINGS':
        setResult('warning', 'Verification Warning', 'WARNING', report.warnings[0]);
        showToast('warning', 'Verification completed with warnings.');
        return;
      case 'SIGNER_UNVERIFIED':
        setResult(
          'warning',
          'Valid Signature, Signer Not Verified',
          'UNVERIFIED SIGNER',
          `The signature is valid for the selected input, but no expected signer was supplied. It only shows that the holder of ${report.signer} signed it. Enter the signer's G... address obtained from a trusted source and verify again.`
        );
        showToast('warning', 'Signature valid; signer identity was not checked.');
        return;
      case 'MISMATCH':
        setResult(
          'warning',
          'Valid Signature, Context Mismatch',
          'MISMATCH',
          report.contextErrors?.[0] ||
            report.inputErrors?.[0] ||
            'The signature is cryptographically valid, but it is not valid for the selected input or expected signer.'
        );
        showToast('warning', 'Signature valid; selected verification context does not match.');
        return;
      default:
        setResult('invalid', 'Signature Invalid', 'INVALID', report.signatureErrors?.[0] || report.errors[0] || 'Signature verification failed.');
        showToast('error', 'Signature verification failed.');
    }
  }

  modeFileEl.addEventListener('change', async () => {
    inputsChanged();
    cancelActiveOperation();
    applyModeUi();
    clearInputContext();
    updateRunAvailability();
    if (selectedFile()) {
      await refreshDigestContext({ silent: true });
    }
  });

  modeTextEl.addEventListener('change', async () => {
    inputsChanged();
    cancelActiveOperation();
    applyModeUi();
    clearInputContext();
    updateRunAvailability();
    if (modeTextEl.checked) {
      await refreshDigestContext({ silent: true });
    }
  });

  fileInput.addEventListener('change', async () => {
    inputsChanged();
    cancelActiveOperation();
    clearInputContext();
    updateRunAvailability();
    if (selectedFile()) {
      await refreshDigestContext({ silent: true });
    }
  });

  textInput.addEventListener('input', async () => {
    inputsChanged();
    cancelActiveOperation();
    clearInputContext();
    updateRunAvailability();
    await refreshDigestContext({ silent: true });
  });

  sigFileInput.addEventListener('change', () => {
    inputsChanged();
    updateRunAvailability();
  });

  textPasteBtn.addEventListener('click', async () => {
    if (!navigator.clipboard?.readText) {
      showToast('warning', 'Clipboard API is unavailable.');
      return;
    }
    try {
      const text = await navigator.clipboard.readText();
      if (text.length > MAX_TEXT_INPUT_SIZE_BYTES) {
        throw new Error(`Text input is too large. Maximum supported UTF-8 size is ${MAX_TEXT_INPUT_SIZE_BYTES} bytes.`);
      }
      textInput.value = text;
      modeTextEl.checked = true;
      modeFileEl.checked = false;
      inputsChanged();
      cancelActiveOperation();
      applyModeUi();
      clearInputContext();
      const context = await refreshDigestContext({ strict: true, silent: true });
      if (!context) throw new Error('Pasted text could not be prepared for verification.');
      showToast('success', `Pasted ${text.length} characters.`);
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  expectedSignerEl.addEventListener('input', () => {
    inputsChanged();
    expectedSignerOverridden = expectedSignerEl.value.trim() !== autoExpectedSigner;
  });

  runBtn.addEventListener('click', async () => {
    const previousLabel = runBtn.textContent;
    const epoch = verificationEpoch;
    const controller = beginAbortableOperation();
    contextBusy = true;
    runBtn.disabled = true;
    runBtn.textContent = 'Verifying...';
    resultCard.classList.add('hidden');

    try {
      setProgress({ phase: 'start', message: 'Preparing verification...' });
      const signatureDoc = await readSignatureDoc();
      throwIfAborted(controller.signal);
      const operationContext = await refreshDigestContext({ strict: true, signal: controller.signal });
      if (!operationContext) throw makeAbortError();
      throwIfAborted(controller.signal);

      const expectedSigner = expectedSignerEl.value.trim();
      if (expectedSigner) {
        decodeEd25519PublicKey(expectedSigner);
      }
      throwIfAborted(controller.signal);
      setProgress({
        phase: 'digest',
        loaded: operationContext.fileSize,
        total: operationContext.fileSize,
        message: 'Verifying signature...',
      });

      const report = await verifyDetachedSignature({
        signatureDoc,
        inputContext: operationContext,
        expectedSigner,
      });
      throwIfAborted(controller.signal);
      if (epoch !== verificationEpoch) {
        throw makeAbortError('Verification inputs changed during the operation.');
      }

      renderReport(report);
      appendLog(
        logEl,
        `Verification completed: ${report.summary} signer=${report.signer || '-'} expected=${expectedSigner || '-'}`
      );
    } catch (err) {
      if (isAbortError(err)) {
        resultCard.classList.add('hidden');
        appendLog(logEl, 'Verification cancelled.');
        showToast('warning', 'Verification cancelled.');
        return;
      }
      const message = friendlyError(err);
      resultCard.classList.remove('hidden');
      setResult('invalid', 'Verification Failed', 'INVALID', message);
      resultSignerLabel.textContent = 'Signer';
      resultSigner.value = '';
      resultChecked.value = '-';
      resultDetails.value = `Result: INVALID\n\nFAIL: ${message}`;
      appendLog(logEl, `Verification error: ${message}`);
      showToast('error', message);
    } finally {
      contextBusy = false;
      finishAbortableOperation(controller);
      resetProgress();
      runBtn.textContent = previousLabel;
      updateRunAvailability();
    }
  });

  cancelBtn.addEventListener('click', cancelActiveOperation);

  copySignerBtn.addEventListener('click', async () => {
    try {
      await copyText(resultSigner.value);
      showToast('success', 'Signer copied.');
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  window.addEventListener('keys:updated', () => {
    inputsChanged();
    syncExpectedSignerFromSession();
  });
  registerSessionWipeHandler(() => {
    cancelActiveOperation();
    clearInputContext();
    invalidateResult();
  });

  applyModeUi();
  syncExpectedSignerFromSession();
  resultBadge.setAttribute('aria-label', 'Verification result: neutral');
  resetProgress();
  updateRunAvailability();
}
