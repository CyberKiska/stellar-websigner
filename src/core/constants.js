export const SIGNATURE_SCHEMA = 'stellar-file-signature/v1';
export const SEP53_PREFIX = 'Stellar Signed Message:\n';
export const SIGNATURE_MESSAGE_MAGIC = 'STELLAR-WSIGN/v1';

export const PUBLIC_NETWORK_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
export const TESTNET_NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';

export const NETWORK_HINT = Object.freeze({
  PUBLIC: 'pubnet',
  TESTNET: 'testnet',
  CUSTOM: 'custom',
});

export const SEP7_SOURCE_PLACEHOLDER = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

export const HASH_ALG = Object.freeze({
  SHA256: 'SHA-256',
  SHA3_512: 'SHA3-512',
});

export const MODE = Object.freeze({
  SEP53: 'sep53',
  SEP7_TX: 'sep7-tx',
});

export const MANAGE_DATA_NAME = Object.freeze({
  SHA256: 'ws.sha256',
  SHA3_512: 'ws.sha3-512',
});

export const HASH_SELECTION = Object.freeze({
  BOTH: 'both',
  SHA256: 'sha256',
  SHA3_512: 'sha3-512',
});
