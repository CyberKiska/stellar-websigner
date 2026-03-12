export const SIGNATURE_SCHEMA_V2 = 'stellar-signature/v2';
export const SEP53_PREFIX = 'Stellar Signed Message:\n';

export const PUBLIC_NETWORK_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
export const TESTNET_NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';

export const NETWORK_HINT = Object.freeze({
  PUBLIC: 'pubnet',
  TESTNET: 'testnet',
  CUSTOM: 'custom',
});

export const HASH_ALG = Object.freeze({
  SHA256: 'SHA-256',
  SHA3_512: 'SHA3-512',
});

export const PROOF_TYPE = Object.freeze({
  SEP53_MESSAGE: 'sep53-message-signature',
  XDR_ENVELOPE: 'xdr-envelope-proof',
});

export const PAYLOAD_TYPE = Object.freeze({
  RAW_BYTES: 'raw-bytes',
  DETACHED_DIGESTS: 'detached-digests',
});

export const SIGNATURE_SCHEME = Object.freeze({
  SEP53_SHA256_ED25519: 'sep53-sha256-ed25519',
  TX_ENVELOPE_ED25519: 'tx-envelope-ed25519',
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
