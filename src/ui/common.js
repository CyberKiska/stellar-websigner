export function byId(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el;
}

export function showToast(type, message) {
  window.dispatchEvent(
    new CustomEvent('toast', {
      detail: {
        type,
        message,
      },
    })
  );
}

export function formatBytes(size) {
  if (!Number.isFinite(size)) return '-';
  if (size < 1024) return `${size} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = size;
  let idx = -1;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[idx]}`;
}

export function safeFileName(name, fallback = 'download.txt') {
  const trimmed = String(name || '').trim();
  if (!trimmed) return fallback;
  return trimmed.replace(/[^a-zA-Z0-9._-]+/g, '_');
}

export function downloadText(filename, text, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 200);
}

export async function copyText(value) {
  const text = String(value || '');
  if (!text) throw new Error('Nothing to copy.');

  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const tmp = document.createElement('textarea');
  tmp.value = text;
  document.body.append(tmp);
  tmp.select();
  document.execCommand('copy');
  tmp.remove();
}

export async function readFileText(file) {
  if (!file) throw new Error('File is missing.');
  return file.text();
}

export function appendLog(textarea, message) {
  const prefix = new Date().toISOString();
  const line = `[${prefix}] ${message}`;
  textarea.value = textarea.value ? `${textarea.value}\n${line}` : line;
  textarea.scrollTop = textarea.scrollHeight;
}

export function clearLog(textarea) {
  textarea.value = '';
}

export function friendlyError(error) {
  if (!error) return 'Unknown error.';
  if (typeof error === 'string') return error;
  if (error instanceof Error && error.message) return error.message;
  return String(error);
}

export function setStatusBox(el, mode, text) {
  el.classList.remove('valid', 'invalid', 'neutral');
  el.classList.add(mode);
  el.textContent = text;
}

export function pickOriginDomain() {
  const protocol = window.location.protocol;
  if (protocol === 'http:' || protocol === 'https:') {
    return window.location.hostname;
  }
  return '';
}
