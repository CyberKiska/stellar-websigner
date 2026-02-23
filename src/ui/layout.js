import { runSelfTest } from '../core/selftest.js';
import { byId, showToast } from './common.js';

export function setupLayout(state) {
  const navItems = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.tab-panel');

  const statusDot = byId('sys-status-dot');
  const statusText = byId('sys-status-text');
  const signerEl = byId('ctx-signer');
  const seedEl = byId('ctx-seed');
  const selfTestBtn = byId('sidebar-selftest');

  const toastContainer = byId('toast-container');

  function activateTab(tabName) {
    navItems.forEach((item) => item.classList.toggle('active', item.dataset.tab === tabName));
    panels.forEach((panel) => panel.classList.toggle('active', panel.id === `tab-${tabName}`));
  }

  navItems.forEach((item) => {
    item.addEventListener('click', () => {
      activateTab(item.dataset.tab);
    });
  });

  window.addEventListener('toast', (event) => {
    const { type, message } = event.detail;
    const toast = document.createElement('div');
    toast.className = `toast ${type || 'info'}`;
    toast.textContent = message;
    toastContainer.append(toast);

    setTimeout(() => {
      toast.classList.add('fade-out');
      setTimeout(() => toast.remove(), 220);
    }, 3500);
  });

  function setContextTone(el, tone) {
    el.classList.remove('status-success', 'status-warning', 'status-muted');
    el.classList.add(`status-${tone}`);
  }

  function refreshSecurityContext() {
    const signer = String(state.keys.signerAddress || '').trim();
    const seedLoaded = Boolean(state.keys.seedBytes);

    if (signer) {
      signerEl.textContent = shortSigner(signer);
      signerEl.title = signer;
      setContextTone(signerEl, 'success');
    } else {
      signerEl.textContent = 'Not Loaded';
      signerEl.title = '';
      setContextTone(signerEl, 'muted');
    }

    if (seedLoaded) {
      seedEl.textContent = 'Loaded';
      setContextTone(seedEl, 'warning');
    } else {
      seedEl.textContent = 'Not Loaded';
      setContextTone(seedEl, 'muted');
    }

    if (seedLoaded) {
      statusDot.className = 'status-indicator warning';
      statusText.textContent = 'Armed';
      return;
    }

    if (signer) {
      statusDot.className = 'status-indicator secure';
      statusText.textContent = 'Verify-Ready';
      return;
    }

    statusDot.className = 'status-indicator';
    statusText.textContent = 'Ready';
  }

  window.addEventListener('keys:updated', refreshSecurityContext);
  refreshSecurityContext();

  selfTestBtn.addEventListener('click', async () => {
    selfTestBtn.disabled = true;
    showToast('info', 'Self-test started...');
    try {
      const report = await runSelfTest();
      if (report.ok) {
        showToast('success', `Self-test PASS (${report.passed}/${report.total}).`);
      } else {
        const firstFailure = report.results.find((item) => !item.ok);
        const suffix = firstFailure ? ` First fail: ${firstFailure.name}.` : '';
        showToast('error', `Self-test FAIL (${report.passed}/${report.total}).${suffix}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      showToast('error', `Self-test error: ${message}`);
    } finally {
      selfTestBtn.disabled = false;
    }
  });

  return {
    activateTab,
    refreshSecurityContext,
  };
}

function shortSigner(value) {
  if (!value || value.length < 16) return value;
  return `${value.slice(0, 8)}...${value.slice(-8)}`;
}
