import {
  NETWORK_HINT,
  PUBLIC_NETWORK_PASSPHRASE,
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
