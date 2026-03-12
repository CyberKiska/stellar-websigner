import { registerSessionWipeHandler } from '../app/session-wipe.js';
import { createFileInputContext, createTextInputContext } from '../core/input-context.js';
import { safeJsonParse, wipeBytes } from '../core/bytes.js';
import { decodeEd25519PublicKey } from '../core/strkey.js';
import { diagnosticsForDisplay, signatureDocRequiresInputBytes, verifyDetachedSignature } from '../core/verify.js';
import { byId, appendLog, copyText, friendlyError, readFileText, showToast } from './common.js';

export function setupVerifyTab(state) {
  const modeFileEl = byId('verify-mode-file');
  const modeTextEl = byId('verify-mode-text');
  const fileGroupEl = byId('verify-file-group');
  const textGroupEl = byId('verify-text-group');

  const fileInput = byId('verify-file-input');
  const textInput = byId('verify-text-input');
  const textPasteBtn = byId('verify-text-paste');

  const sigFileInput = byId('verify-sig-file');
  const expectedSignerEl = byId('verify-expected-signer');
  const runBtn = byId('verify-run');

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
  let contextBusy = false;
  let autoExpectedSigner = '';
  let expectedSignerOverridden = false;

  function setResultCardMode(mode) {
    resultCard.classList.remove('valid', 'invalid', 'warning');
    if (mode) resultCard.classList.add(mode);
  }

  function getMode() {
    return modeTextEl.checked ? 'text' : 'file';
  }

  function selectedFile() {
    return fileInput.files?.[0] ?? null;
  }

  function fileContextMatchesSelection(context, file) {
    if (!context || context.type !== 'file' || !file) return false;
    return (
      context.fileName === String(file.name || '') &&
      context.fileSize === Number(file.size || 0) &&
      context.fileLastModified === Number(file.lastModified || 0)
    );
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

  function syncExpectedSignerFromSession() {
    const loadedSigner = String(state.keys.signerAddress || '').trim();
    if (!expectedSignerOverridden || expectedSignerEl.value.trim() === autoExpectedSigner) {
      expectedSignerEl.value = loadedSigner;
      autoExpectedSigner = loadedSigner;
      expectedSignerOverridden = false;
    }
  }

  async function buildInputContext({ strict = false, requireBytes = false } = {}) {
    if (getMode() === 'file') {
      const file = selectedFile();
      if (!file) {
        if (strict) throw new Error('Select original file for verification.');
        return null;
      }
      if (
        !requireBytes &&
        fileContextMatchesSelection(state.verify.inputContext, file) &&
        !(state.verify.inputContext?.bytes instanceof Uint8Array && state.verify.inputContext.bytes.length > 0)
      ) {
        return state.verify.inputContext;
      }
      return createFileInputContext(file, { keepBytes: requireBytes });
    }

    const text = textInput.value;
    if (!text.length) {
      if (strict) throw new Error('Enter original plain text for verification.');
      return null;
    }
    return createTextInputContext(text, { keepBytes: requireBytes });
  }

  async function refreshDigestContext({ strict = false } = {}) {
    const nonce = ++refreshNonce;
    contextBusy = true;
    updateRunAvailability();
    try {
      const context = await buildInputContext({ strict, requireBytes: false });
      if (nonce !== refreshNonce) return null;
      clearInputContext();
      state.verify.inputContext = context;
      return context;
    } catch (err) {
      if (nonce !== refreshNonce) return null;
      clearInputContext();
      if (strict) throw err;
      return null;
    } finally {
      if (nonce === refreshNonce) {
        contextBusy = false;
        updateRunAvailability();
      }
    }
  }

  async function readSignatureDoc() {
    const file = sigFileInput.files?.[0] ?? null;
    if (!file) {
      throw new Error('Select signature .sig file.');
    }
    return safeJsonParse(await readFileText(file));
  }

  function renderReport(report) {
    resultCard.classList.remove('hidden');
    resultSigner.value = report.signer || '';

    if (Array.isArray(report.checked?.hashes) && report.checked.hashes.length > 0) {
      resultChecked.value = report.checked.hashes.map((item) => `${item.alg}: ${item.hex}`).join(' | ');
    } else if (Number.isInteger(report.checked?.messageBytesLength)) {
      resultChecked.value = `SEP-53 raw bytes: ${report.checked.messageBytesLength}`;
    } else {
      resultChecked.value = '-';
    }

    resultDetails.value = diagnosticsForDisplay(report);

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
    resultTitle.textContent = 'Verification Failed';
    resultBadge.textContent = 'INVALID';
    resultBadge.className = 'badge invalid';
    resultBadge.setAttribute('aria-label', 'Verification result: invalid');
    resultMessage.textContent = report.errors[0] || 'Verification failed.';
    showToast('error', 'Verification failed.');
  }

  modeFileEl.addEventListener('change', async () => {
    applyModeUi();
    clearInputContext();
    updateRunAvailability();
    if (selectedFile()) {
      await refreshDigestContext();
    }
  });

  modeTextEl.addEventListener('change', async () => {
    applyModeUi();
    clearInputContext();
    updateRunAvailability();
    if (modeTextEl.checked) {
      await refreshDigestContext();
    }
  });

  fileInput.addEventListener('change', async () => {
    clearInputContext();
    updateRunAvailability();
    if (selectedFile()) {
      await refreshDigestContext();
    }
  });

  textInput.addEventListener('input', async () => {
    clearInputContext();
    updateRunAvailability();
    await refreshDigestContext();
  });

  sigFileInput.addEventListener('change', () => {
    updateRunAvailability();
  });

  textPasteBtn.addEventListener('click', async () => {
    if (!navigator.clipboard?.readText) {
      showToast('warning', 'Clipboard API is unavailable.');
      return;
    }
    try {
      const text = await navigator.clipboard.readText();
      textInput.value = text;
      modeTextEl.checked = true;
      modeFileEl.checked = false;
      applyModeUi();
      clearInputContext();
      await refreshDigestContext();
      showToast('success', `Pasted ${text.length} characters.`);
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  expectedSignerEl.addEventListener('input', () => {
    expectedSignerOverridden = expectedSignerEl.value.trim() !== autoExpectedSigner;
  });

  runBtn.addEventListener('click', async () => {
    const previousLabel = runBtn.textContent;
    let operationContext = null;
    runBtn.disabled = true;
    runBtn.textContent = 'Verifying...';
    resultCard.classList.add('hidden');

    try {
      const signatureDoc = await readSignatureDoc();
      const requiresBytes = signatureDocRequiresInputBytes(signatureDoc);
      operationContext = requiresBytes
        ? await buildInputContext({ strict: true, requireBytes: true })
        : await refreshDigestContext({ strict: true });

      const expectedSigner = expectedSignerEl.value.trim();
      if (expectedSigner) {
        decodeEd25519PublicKey(expectedSigner);
      }

      const report = await verifyDetachedSignature({
        signatureDoc,
        inputContext: operationContext,
        expectedSigner,
      });

      renderReport(report);
      appendLog(
        logEl,
        `Verification completed: ${report.summary} signer=${report.signer || '-'} expected=${expectedSigner || '-'}`
      );
    } catch (err) {
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
      runBtn.textContent = previousLabel;
      updateRunAvailability();
    }
  });

  copySignerBtn.addEventListener('click', async () => {
    try {
      await copyText(resultSigner.value);
      showToast('success', 'Signer copied.');
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  window.addEventListener('keys:updated', syncExpectedSignerFromSession);
  registerSessionWipeHandler(clearInputContext);

  applyModeUi();
  syncExpectedSignerFromSession();
  resultBadge.setAttribute('aria-label', 'Verification result: neutral');
  updateRunAvailability();
}
