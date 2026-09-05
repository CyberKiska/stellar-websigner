import { registerSessionWipeHandler } from '../app/session-wipe.js';
import {
  createFileInputContext,
  createTextInputContext,
  MAX_TEXT_INPUT_SIZE_BYTES,
} from '../core/input-context.js';
import { safeJsonParse, wipeBytes } from '../core/bytes.js';
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
  const runLabel = runBtn.textContent;
  const cancelBtn = byId('verify-cancel');
  const progressEl = byId('verify-progress');
  const progressLabelEl = byId('verify-progress-label');

  const resultCard = byId('verify-result-card');
  const resultTitle = byId('verify-result-title');
  const resultBadge = byId('verify-result-badge');
  const resultMessage = byId('verify-result-message');
  const resultSigner = byId('verify-result-signer');
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

  function clearReport() {
    resultCard.classList.add('hidden');
    setResultCardMode('');
    resultTitle.textContent = '';
    resultBadge.textContent = '';
    resultBadge.className = 'badge';
    resultBadge.setAttribute('aria-label', 'Verification result: not checked');
    resultMessage.textContent = '';
    resultSigner.value = '';
    resultChecked.value = '';
    resultDetails.value = '';
    copySignerBtn.disabled = true;
  }

  function invalidateVerification() {
    verificationEpoch += 1;
    clearReport();
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

  function wipeInputBytes(context) {
    if (context?.bytes instanceof Uint8Array) {
      wipeBytes(context.bytes);
    }
  }

  function clearInputContext() {
    wipeInputBytes(state.verify.inputContext);
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
      const context = await createFileInputContext(file, { keepBytes: false, onProgress: setProgress, signal });
      throwIfAborted(signal);
      return context;
    }

    const text = textInput.value;
    if (!text.length) {
      if (strict) throw new Error('Enter original plain text for verification.');
      return null;
    }
    return createTextInputContext(text, { keepBytes: false, signal });
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

  function renderReport(report) {
    resultCard.classList.remove('hidden');
    resultSigner.value = report.signer || '';
    copySignerBtn.disabled = !report.signer;

    if (Array.isArray(report.checked?.hashes) && report.checked.hashes.length > 0) {
      resultChecked.value = report.checked.hashes.map((item) => `${item.alg}: ${item.hex}`).join(' | ');
    } else if (Number.isInteger(report.checked?.messageBytesLength)) {
      resultChecked.value = `SEP-53 raw bytes: ${report.checked.messageBytesLength}`;
    } else {
      resultChecked.value = '-';
    }

    resultDetails.value = diagnosticsForDisplay(report);

    if (report.signatureValid && (!report.inputMatches || !report.contextMatches)) {
      setResultCardMode('warning');
      resultTitle.textContent = 'Valid Signature, Context Mismatch';
      resultBadge.textContent = 'MISMATCH';
      resultBadge.className = 'badge warning';
      resultBadge.setAttribute('aria-label', 'Verification result: valid signature with context mismatch');
      resultMessage.textContent =
        report.contextErrors?.[0] ||
        report.inputErrors?.[0] ||
        'The signature is cryptographically valid, but it is not valid for the selected input or expected signer.';
      showToast('warning', 'Signature valid; selected verification context does not match.');
      return;
    }

    if (report.valid) {
      if (Array.isArray(report.warnings) && report.warnings.length > 0) {
        setResultCardMode('warning');
        resultTitle.textContent = 'Verification Warning';
        resultBadge.textContent = 'WARNING';
        resultBadge.className = 'badge warning';
        resultBadge.setAttribute('aria-label', 'Verification result: warning');
        resultMessage.textContent = report.warnings[0];
        showToast('warning', 'Verification completed with warnings.');
        return;
      }

      setResultCardMode('valid');
      resultTitle.textContent = 'Signature Valid';
      resultBadge.textContent = 'VALID';
      resultBadge.className = 'badge valid';
      resultBadge.setAttribute('aria-label', 'Verification result: valid');
      resultMessage.textContent = 'Signature is valid for the supplied input and signer.';
      showToast('success', 'Verification successful.');
      return;
    }

    setResultCardMode('invalid');
    resultTitle.textContent = 'Signature Invalid';
    resultBadge.textContent = 'INVALID';
    resultBadge.className = 'badge invalid';
    resultBadge.setAttribute('aria-label', 'Verification result: invalid');
    resultMessage.textContent = report.signatureErrors?.[0] || report.errors[0] || 'Signature verification failed.';
    showToast('error', 'Signature verification failed.');
  }

  modeFileEl.addEventListener('change', async () => {
    invalidateVerification();
    cancelActiveOperation();
    applyModeUi();
    clearInputContext();
    updateRunAvailability();
    if (selectedFile()) {
      await refreshDigestContext({ silent: true });
    }
  });

  modeTextEl.addEventListener('change', async () => {
    invalidateVerification();
    cancelActiveOperation();
    applyModeUi();
    clearInputContext();
    updateRunAvailability();
    if (modeTextEl.checked) {
      await refreshDigestContext({ silent: true });
    }
  });

  fileInput.addEventListener('change', async () => {
    invalidateVerification();
    cancelActiveOperation();
    clearInputContext();
    updateRunAvailability();
    if (selectedFile()) {
      await refreshDigestContext({ silent: true });
    }
  });

  textInput.addEventListener('input', async () => {
    invalidateVerification();
    cancelActiveOperation();
    clearInputContext();
    updateRunAvailability();
    await refreshDigestContext({ silent: true });
  });

  sigFileInput.addEventListener('change', () => {
    invalidateVerification();
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
      invalidateVerification();
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
    invalidateVerification();
    expectedSignerOverridden = expectedSignerEl.value.trim() !== autoExpectedSigner;
  });

  runBtn.addEventListener('click', async () => {
    const epoch = verificationEpoch;
    const controller = beginAbortableOperation();
    let operationContext = null;
    contextBusy = true;
    runBtn.disabled = true;
    runBtn.textContent = 'Verifying...';
    clearReport();

    try {
      setProgress({ phase: 'start', message: 'Preparing verification...' });
      const signatureDoc = await readSignatureDoc();
      throwIfAborted(controller.signal);
      operationContext = await refreshDigestContext({ strict: true, signal: controller.signal });
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
      if (activeAbortController !== controller) return;
      if (isAbortError(err) || epoch !== verificationEpoch) {
        clearReport();
        appendLog(logEl, 'Verification cancelled.');
        showToast('warning', 'Verification cancelled.');
        return;
      }
      const message = friendlyError(err);
      resultCard.classList.remove('hidden');
      setResultCardMode('invalid');
      resultTitle.textContent = 'Verification Failed';
      resultBadge.textContent = 'INVALID';
      resultBadge.className = 'badge invalid';
      resultBadge.setAttribute('aria-label', 'Verification result: invalid');
      resultMessage.textContent = message;
      resultSigner.value = '';
      resultChecked.value = '-';
      resultDetails.value = `Result: INVALID\n\nFAIL: ${message}`;
      appendLog(logEl, `Verification error: ${message}`);
      showToast('error', message);
    } finally {
      if (operationContext && operationContext !== state.verify.inputContext) {
        wipeInputBytes(operationContext);
      }
      if (activeAbortController === controller) {
        contextBusy = false;
        finishAbortableOperation(controller);
        resetProgress();
        runBtn.textContent = runLabel;
        updateRunAvailability();
      }
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
    invalidateVerification();
    syncExpectedSignerFromSession();
  });
  registerSessionWipeHandler(() => {
    invalidateVerification();
    cancelActiveOperation();
    clearInputContext();
  });

  applyModeUi();
  clearReport();
  syncExpectedSignerFromSession();
  resultBadge.setAttribute('aria-label', 'Verification result: neutral');
  resetProgress();
  updateRunAvailability();
}
