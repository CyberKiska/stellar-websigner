export function localSecretOperationsAllowed({ hostname, isSecureContext, buildPolicy = 'enabled' }) {
  const host = String(hostname || '').trim().toLowerCase();
  if (buildPolicy !== 'enabled') return false;
  if (!isSecureContext) return false;
  if (/(?:^|\.)github\.io$/.test(host)) return false;
  return true;
}
