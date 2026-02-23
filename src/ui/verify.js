import { createFileInputContext, createTextInputContext } from '../core/input-context.js';
import { safeJsonParse } from '../core/bytes.js';
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

  const sigFileInput = byId('verify-sig-file');
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

  function setResultCardMode(mode) {
    resultCard.classList.remove('valid', 'invalid');
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

  async function buildInputContext({ strict = false } = {}) {
    if (getMode() === 'file') {
      const file = selectedFile();
      if (!file) {
        if (strict) throw new Error('Select original file for verification.');
        return null;
      }
      if (fileContextMatchesSelection(state.verify.inputContext, file)) {
        return state.verify.inputContext;
      }
      return createFileInputContext(file);
    }

    const text = textInput.value;
    if (!text.length) {
      if (strict) throw new Error('Enter original plain text for verification.');
      return null;
    }
    return createTextInputContext(text);
  }

  async function refreshInputContext({ strict = false } = {}) {
    const nonce = ++refreshNonce;
    try {
      const context = await buildInputContext({ strict });
      if (nonce !== refreshNonce) return null;
      state.verify.inputContext = context;
      return context;
    } catch (err) {
      if (nonce !== refreshNonce) return null;
      state.verify.inputContext = null;
      if (strict) throw err;
      return null;
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
    } else {
      resultChecked.value = '-';
    }

    resultDetails.value = diagnosticsForDisplay(report);

    if (report.valid) {
      setResultCardMode('valid');
      resultTitle.textContent = 'Signature Valid';
      resultBadge.textContent = 'VALID';
      resultBadge.className = 'badge valid';
      resultMessage.textContent = 'Signature is valid for supplied input and signer constraints.';
      showToast('success', 'Verification successful.');
      return;
    }

    setResultCardMode('invalid');
    resultTitle.textContent = 'Verification Failed';
    resultBadge.textContent = 'INVALID';
    resultBadge.className = 'badge invalid';
    resultMessage.textContent = report.errors[0] || 'Verification failed.';
    showToast('error', 'Verification failed.');
  }

  modeFileEl.addEventListener('change', async () => {
    applyModeUi();
    state.verify.inputContext = null;
  });

  modeTextEl.addEventListener('change', async () => {
    applyModeUi();
    if (modeTextEl.checked) {
      await refreshInputContext();
      return;
    }
    state.verify.inputContext = null;
  });

  fileInput.addEventListener('change', () => {
    state.verify.inputContext = null;
  });

  textInput.addEventListener('input', async () => {
    await refreshInputContext();
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
      await refreshInputContext();
      showToast('success', `Pasted ${text.length} characters.`);
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  runBtn.addEventListener('click', async () => {
    runBtn.disabled = true;
    resultCard.classList.add('hidden');

    try {
      const inputContext = await refreshInputContext({ strict: true });
      const signatureDoc = await readSignatureDoc();

      const report = await verifyDetachedSignature({
        signatureDoc,
        inputContext,
        expectedSigner: state.keys.signerAddress || '',
      });

      renderReport(report);
      appendLog(
        logEl,
        `Verification completed: ${report.summary} signer=${report.signer || '-'} expected=${state.keys.signerAddress || '-'}`
      );
    } catch (err) {
      const message = friendlyError(err);
      resultCard.classList.remove('hidden');
      setResultCardMode('invalid');
      resultTitle.textContent = 'Verification Failed';
      resultBadge.textContent = 'INVALID';
      resultBadge.className = 'badge invalid';
      resultMessage.textContent = message;
      resultSigner.value = '';
      resultChecked.value = '-';
      resultDetails.value = `Result: INVALID\n\nFAIL: ${message}`;
      appendLog(logEl, `Verification error: ${message}`);
      showToast('error', message);
    } finally {
      runBtn.disabled = false;
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

  applyModeUi();
}
