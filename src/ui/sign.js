import { HASH_SELECTION, PUBLIC_NETWORK_PASSPHRASE } from '../core/constants.js';
import { wipeBytes } from '../core/bytes.js';
import { createFileInputContext, createTextInputContext } from '../core/input-context.js';
import {
  createLocalDetachedSignature,
  createSep7DetachedSignature,
  createSep7Draft,
} from '../core/signing.js';
import { byId, appendLog, copyText, downloadText, friendlyError, pickOriginDomain, setStatusBox, showToast } from './common.js';

const MAX_FILE_CACHE_ENTRIES = 4;

export function setupSignTab(state) {
  const modeFileEl = byId('sign-mode-file');
  const modeTextEl = byId('sign-mode-text');
  const hashSelectionEl = byId('sign-hash-selection');

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
  const sep7PanelEl = byId('sign-sep7-panel');

  const sep7GenerateBtn = byId('sign-sep7-generate');
  const sep7OpenBtn = byId('sign-sep7-open');
  const sep7CopyBtn = byId('sign-sep7-copy');
  const sep7CreateBtn = byId('sign-sep7-create');
  const sep7UnsignedXdrEl = byId('sign-sep7-unsigned-xdr');
  const sep7UriEl = byId('sign-sep7-uri');
  const sep7SignedXdrEl = byId('sign-sep7-signed-xdr');

  const outputSignerEl = byId('sign-output-signer');
  const outputSignatureEl = byId('sign-output-signature');
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

  function dispatchKeysUpdated() {
    window.dispatchEvent(new CustomEvent('keys:updated'));
  }

  function syncSigningModePanels() {
    const hasSeed = Boolean(state.keys.seedBytes);
    localPanelEl.open = hasSeed;
    sep7PanelEl.open = !hasSeed;
  }

  function getInputMode() {
    return modeTextEl.checked ? 'text' : 'file';
  }

  function getHashSelection() {
    const value = hashSelectionEl.value;
    if (value === HASH_SELECTION.SHA256) return HASH_SELECTION.SHA256;
    if (value === HASH_SELECTION.SHA3_512) return HASH_SELECTION.SHA3_512;
    return HASH_SELECTION.BOTH;
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
    outputSignatureEl.value = '';
    outputJsonEl.value = '';
    downloadBtn.disabled = true;
  }

  function resetSep7Draft() {
    state.sign.sep7Draft = null;
    sep7UnsignedXdrEl.value = '';
    sep7UriEl.value = '';
    sep7SignedXdrEl.value = '';
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

    // bump recency for simple LRU behavior
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

  async function buildInputContext({ strict = false } = {}) {
    const mode = getInputMode();

    if (mode === 'file') {
      const file = fileInput.files?.[0] ?? null;
      if (!file) {
        if (strict) throw new Error('Select file input first.');
        return null;
      }

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

      const context = await createFileInputContext(file, {
        onProgress: setHashProgress,
        keepBytes: false,
      });

      putCachedFileContext(file, context);
      setTimeout(() => resetHashProgress(), 350);
      return context;
    }

    const text = textInput.value;
    if (!text.length) {
      if (strict) throw new Error('Enter plain text first.');
      return null;
    }
    resetHashProgress();
    return createTextInputContext(text);
  }

  async function refreshContextFromUi({ strict = false, silent = false } = {}) {
    const nonce = ++refreshNonce;
    try {
      const context = await buildInputContext({ strict });
      if (nonce !== refreshNonce) return null;

      wipeInputBytes(state.sign.inputContext);
      state.sign.inputContext = context;
      renderDigests(context);
      return context;
    } catch (err) {
      if (nonce !== refreshNonce) return null;
      state.sign.inputContext = null;
      renderDigests(null);
      resetHashProgress();
      if (strict) throw err;
      if (!silent) {
        appendLog(logEl, `Digest context reset: ${friendlyError(err)}`);
      }
      return null;
    }
  }

  function setSignatureOutput(result, statusMessage) {
    state.sign.lastSignatureDoc = result.doc;
    state.sign.lastSignatureJson = result.json;
    state.sign.lastSignatureFilename = result.filename;

    outputSignerEl.value = result.signer || '';
    outputSignatureEl.value = result.signatureB64 || '';
    outputJsonEl.value = result.json;

    downloadBtn.disabled = false;
    setStatusBox(statusEl, 'valid', statusMessage);
  }

  async function runLocalSign() {
    if (!state.keys.seedBytes) {
      showToast('warning', 'Load secret seed in Keys tab first.');
      setStatusBox(statusEl, 'invalid', 'Local signing requires loaded S... seed.');
      return;
    }

    const context = await refreshContextFromUi({ strict: true });
    const hashSelection = getHashSelection();

    const result = await createLocalDetachedSignature({
      inputContext: context,
      seedBytes: state.keys.seedBytes,
      signerAddress: state.keys.signerAddress,
      hashSelection,
    });

    const signedHashes = result.doc.hashes.map((item) => item.alg).join(', ');
    setSignatureOutput(result, `SEP-53 signature created (${signedHashes}).`);
    appendLog(logEl, `Local SEP-53 signature created. signer=${result.signer} hashes=${signedHashes}`);
    showToast('success', 'Detached signature created.');
  }

  async function runSep7Draft() {
    const context = await refreshContextFromUi({ strict: true });
    const hashSelection = getHashSelection();

    const draft = createSep7Draft({
      inputContext: context,
      signerAddress: state.keys.signerAddress || '',
      networkPassphrase: PUBLIC_NETWORK_PASSPHRASE,
      originDomain: pickOriginDomain(),
      hashSelection,
    });

    state.sign.sep7Draft = draft;
    sep7UnsignedXdrEl.value = draft.unsignedXdrB64;
    sep7UriEl.value = draft.sep7Uri;

    appendLog(
      logEl,
      `SEP-7 draft generated. hashes=${draft.boundHashes.map((item) => item.alg).join(', ')} placeholder=${draft.placeholderMode}`
    );

    setStatusBox(statusEl, 'neutral', 'SEP-7 URI generated. Sign in wallet and paste signedXDR.');
    showToast('success', 'SEP-7 URI generated.');
  }

  async function runSep7SignatureCreate() {
    const context = await refreshContextFromUi({ strict: true });
    const signedXdr = sep7SignedXdrEl.value.trim();
    if (!signedXdr) {
      throw new Error('Paste signedXDR first.');
    }

    const result = await createSep7DetachedSignature({
      inputContext: context,
      signedXdr,
      networkPassphrase: state.sign.sep7Draft?.networkPassphrase || PUBLIC_NETWORK_PASSPHRASE,
      expectedSigner: state.keys.signerAddress || state.sign.sep7Draft?.signerAddress || '',
      expectedManageDataEntries: state.sign.sep7Draft?.boundHashes,
      hashSelection: state.sign.sep7Draft?.hashSelection || getHashSelection(),
    });

    setSignatureOutput(result, 'SEP-7 detached signature created from signedXDR.');
    appendLog(logEl, `SEP-7 signature created. signer=${result.signer} network=public`);

    if (!state.keys.signerAddress) {
      state.keys.signerAddress = result.signer;
      state.keys.source = 'wallet-signer';
      dispatchKeysUpdated();
    }

    showToast('success', 'Signature file created from signedXDR.');
  }

  async function ensureSep7UriReady() {
    if (sep7UriEl.value.trim()) return;
    await runSep7Draft();
  }

  modeFileEl.addEventListener('change', async () => {
    applyInputModeUi();
    await refreshContextFromUi({ silent: true });
  });

  modeTextEl.addEventListener('change', async () => {
    applyInputModeUi();
    await refreshContextFromUi({ silent: true });
  });

  hashSelectionEl.addEventListener('change', () => {
    resetOutput();
    resetSep7Draft();
  });

  fileInput.addEventListener('change', async () => {
    resetOutput();
    resetSep7Draft();
    await refreshContextFromUi();
  });

  textInput.addEventListener('input', () => {
    resetOutput();
    resetSep7Draft();

    clearTimeout(textDigestTimer);
    textDigestTimer = setTimeout(() => {
      refreshContextFromUi({ silent: true }).catch(() => {});
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
      await refreshContextFromUi({ silent: true });
      showToast('success', `Pasted ${value.length} characters.`);
    } catch (err) {
      showToast('error', friendlyError(err));
    }
  });

  localRunBtn.addEventListener('click', async () => {
    localRunBtn.disabled = true;
    try {
      await runLocalSign();
    } catch (err) {
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `Local signing failed: ${msg}`);
      showToast('error', msg);
    } finally {
      localRunBtn.disabled = false;
    }
  });

  sep7GenerateBtn.addEventListener('click', async () => {
    sep7GenerateBtn.disabled = true;
    try {
      await runSep7Draft();
    } catch (err) {
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `SEP-7 draft failed: ${msg}`);
      showToast('error', msg);
    } finally {
      sep7GenerateBtn.disabled = false;
    }
  });

  sep7CreateBtn.addEventListener('click', async () => {
    sep7CreateBtn.disabled = true;
    try {
      await runSep7SignatureCreate();
    } catch (err) {
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `SEP-7 .sig creation failed: ${msg}`);
      showToast('error', msg);
    } finally {
      sep7CreateBtn.disabled = false;
    }
  });

  sep7OpenBtn.addEventListener('click', async () => {
    sep7OpenBtn.disabled = true;
    try {
      await ensureSep7UriReady();
      window.location.href = sep7UriEl.value.trim();
    } catch (err) {
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `SEP-7 open failed: ${msg}`);
      showToast('error', msg);
    } finally {
      sep7OpenBtn.disabled = false;
    }
  });

  sep7CopyBtn.addEventListener('click', async () => {
    sep7CopyBtn.disabled = true;
    try {
      await ensureSep7UriReady();
      await copyText(sep7UriEl.value.trim());
      showToast('success', 'SEP-7 URI copied.');
    } catch (err) {
      const msg = friendlyError(err);
      setStatusBox(statusEl, 'invalid', msg);
      appendLog(logEl, `SEP-7 copy failed: ${msg}`);
      showToast('error', msg);
    } finally {
      sep7CopyBtn.disabled = false;
    }
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
    showToast('success', 'Detached signature downloaded.');
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
  clearDigests();
  resetOutput();
  resetHashProgress();
  setStatusBox(statusEl, 'neutral', 'Waiting for input.');

  window.addEventListener('beforeunload', () => {
    wipeInputBytes(state.sign.inputContext);
    if (state.sign.fileContextCache instanceof Map) {
      for (const value of state.sign.fileContextCache.values()) {
        wipeInputBytes(value);
      }
    }
  });

  window.addEventListener('keys:updated', syncSigningModePanels);
  syncSigningModePanels();
}
