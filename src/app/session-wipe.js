const wipeHandlers = new Set();
let guardsInstalled = false;

function runHandlers() {
  for (const handler of wipeHandlers) {
    try {
      handler();
    } catch {
      // Best-effort wipe only.
    }
  }
}

export function registerSessionWipeHandler(handler) {
  if (typeof handler !== 'function') {
    throw new Error('Session wipe handler must be a function.');
  }

  wipeHandlers.add(handler);
  return () => wipeHandlers.delete(handler);
}

export function wipeSessionSecrets() {
  runHandlers();
}

export function installSessionWipeGuards() {
  if (guardsInstalled || typeof window === 'undefined') {
    return;
  }

  const onUnload = () => {
    runHandlers();
  };

  window.addEventListener('beforeunload', onUnload, { capture: true });
  window.addEventListener('pagehide', onUnload, { capture: true });

  guardsInstalled = true;
}
