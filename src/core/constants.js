export const SIGNATURE_SCHEMA_V3 = 'stellar-signature/v3';
export const SIGNATURE_APPLICATION = 'stellar-websigner';
export const SIGNATURE_PURPOSE = 'detached-content-authentication';
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
  PROTECTED_MANIFEST: 'protected-manifest',
});

export const SIGNATURE_SCHEME = Object.freeze({
  SEP53_SHA256_ED25519: 'sep53-sha256-ed25519',
  TX_ENVELOPE_ED25519: 'tx-envelope-ed25519',
});

// ManageData name carrying SHA-256 of the canonical protected manifest in the XDR proof profile.
export const MANIFEST_DATA_NAME = 'org.stellar-websigner.manifest.sha256';
