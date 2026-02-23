import {
  NETWORK_HINT,
  PUBLIC_NETWORK_PASSPHRASE,
  SEP7_SOURCE_PLACEHOLDER,
  TESTNET_NETWORK_PASSPHRASE,
} from './constants.js';

export function networkHintFromPassphrase(passphrase) {
  const value = String(passphrase || '');
  if (value === PUBLIC_NETWORK_PASSPHRASE) return NETWORK_HINT.PUBLIC;
  if (value === TESTNET_NETWORK_PASSPHRASE) return NETWORK_HINT.TESTNET;
  return NETWORK_HINT.CUSTOM;
}

export function knownNetworkPassphrases() {
  return [PUBLIC_NETWORK_PASSPHRASE, TESTNET_NETWORK_PASSPHRASE];
}

export function buildSep7Uri({
  unsignedXdrB64,
  networkPassphrase,
  message,
  signerAddress,
  originDomain,
}) {
  if (!String(unsignedXdrB64 || '').trim()) {
    throw new Error('Unsigned XDR is required.');
  }
  if (!String(networkPassphrase || '').trim()) {
    throw new Error('Network passphrase is required.');
  }

  const params = new URLSearchParams();
  params.set('xdr', String(unsignedXdrB64).trim());
  params.set('network_passphrase', networkPassphrase);
  params.set('msg', String(message || 'Sign detached digest'));

  if (String(originDomain || '').trim()) {
    params.set('origin_domain', String(originDomain).trim());
  }

  const signer = String(signerAddress || '').trim();
  if (signer) {
    params.set('pubkey', signer);
  } else {
    params.set('replace', `sourceAccount:${SEP7_SOURCE_PLACEHOLDER}:wallet account to sign`);
  }

  return `web+stellar:tx?${params.toString()}`;
}

export function defaultNetworkPassphrase(networkKind) {
  const kind = String(networkKind || 'public').toLowerCase();
  if (kind === 'testnet') return TESTNET_NETWORK_PASSPHRASE;
  return PUBLIC_NETWORK_PASSPHRASE;
}
