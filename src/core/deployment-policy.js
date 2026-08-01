export const FRAMING_POLICY_ERROR_CODE = 'ERR_FRAMING_FORBIDDEN';

export function assertTopLevelBrowsingContext({ topWindow, selfWindow }) {
  if (!topWindow || !selfWindow || topWindow !== selfWindow) {
    const error = new Error('Framing is not permitted. Open Stellar WebSigner directly in a top-level tab.');
    error.name = 'SecurityPolicyError';
    error.code = FRAMING_POLICY_ERROR_CODE;
    throw error;
  }
}

export function localSecretOperationsAllowed({ hostname, isSecureContext, buildPolicy = 'enabled' }) {
  const host = String(hostname || '').trim().toLowerCase();
  if (buildPolicy !== 'enabled') return false;
  if (!isSecureContext) return false;
  if (/(?:^|\.)github\.io$/.test(host)) return false;
  return true;
}
