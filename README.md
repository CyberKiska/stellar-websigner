# Stellar WebSigner
## Digital signature tool

Static client-only web app for Stellar (Ed25519) content signatures and XDR proofs (`.sig`) using pure HTML/CSS/JS.

[Features](#features) | [Architecture](#architecture) | [Development](#development) | [License](#license)

------------

## Features

1. Key management: generate/import Ed25519 (Stellar) keys and export public information only.
2. Sign locally: select file/text, sign a protected manifest through SEP-53, download `.sig`.
3. Sign with external wallet: generate unsigned XDR proof, sign externally, paste signed XDR, download `.sig`.
4. Verify: select original input + `.sig`, get `VALID`/`INVALID` with technical details.

------------

## Architecture

### Algorithms and standards alignment

We aim to implement
* Ed25519 according to [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) and [FIPS 186-5](https://doi.org/10.6028/NIST.FIPS.186-5)
* SHA-256 according to [RFC 4634](https://www.rfc-editor.org/rfc/rfc4634)
* SHA3-512 according to [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202)
* Message signing with Stellar according to [SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md), especially its Signing Procedure
* Detached XDR proof verification according to Stellar transaction hashing/signature rules

SEP-53 signs `SHA-256("Stellar Signed Message:\n" || messageBytes)` with Ed25519. This is not Ed25519ph. In schema v3, `messageBytes` is the RFC 8785 serialization of the protected manifest; the manifest contains the detached content digests.

Verification performs provider-independent Ed25519 checks before Web Crypto: canonical point encodings, prime-order subgroup membership for the public key and `R`, rejection of the identity point, and canonical `S < L`. A startup RFC 8032 known-answer test exercises the actual Web Crypto provider.

### Security model

- No backend.
- No runtime network calls.
- No CDN.
- No telemetry.
- No persistent secret storage. Imported seed bytes are decoded into a single non-extractable signing `CryptoKey` and temporary byte buffers are cleared in `finally` blocks.
- Plaintext secret download and secret clipboard export are disabled.
- Secret form controls and key state are cleared on session end, unload/pagehide, and BFCache restoration.

Cleanup is best effort, not guaranteed zeroization: JavaScript strings, browser form history, discarded `CryptoKey` material, the OS clipboard, and browser memory are outside the application's complete control.

This app protects against accidental network disclosure, malformed signature documents, unsafe XDR proof envelopes, and common deployment mistakes when the required headers are installed. It does not protect a secret seed from a compromised browser, malicious extension, malicious same-origin release, compromised deployment pipeline, or operating-system compromise. Online JavaScript origin integrity is private-key integrity. Prefer the external-wallet flow; use local-seed signing only from an independently verified offline artifact on a dedicated device/origin.

Key generation uses `subtle.generateKey('Ed25519')` and therefore relies on the browser and operating system random-bit generator. Browser JavaScript cannot inspect raw noise samples or establish SP 800-90B/90C, SP 800-133, FIPS 186-5, or FIPS 140 validation status. The startup check is a capability/KAT check, not entropy certification.

### Non-goals

- Not a timestamping authority.
- Not a revocation system.
- Not a general PKI or identity verification service.
- Not anti-exfiltration against a compromised tab.
- Not a replacement for hardware wallets or multisig operational controls.

### Signature format choice

New signatures use JSON schema `stellar-signature/v3`. Schema v2 remains verification-only compatibility and is reported with a warning because it authenticates content bytes/digests, not its surrounding metadata.

- `protected` binds application, format version, purpose, signer, proof profile, exact input role/name/size/media policy, and exactly SHA-256 plus SHA3-512;
- protected bytes use RFC 8785 canonical JSON and reject non-I-JSON strings/numbers;
- JSON parsing rejects duplicate members, excessive size/depth, unknown fields, and missing fields;
- binary fields require canonical padded RFC 4648 Base64.

Text mode signs UTF-8 of the textarea DOM value, with no Unicode normalization and with the browser's textarea newline behavior; unpaired UTF-16 surrogates are rejected. Verifiers must supply the same DOM text value.

For local signing, the protected manifest itself is the SEP-53 message. For external signing, SHA-256 of that manifest is stored in the namespaced `org.stellar-websigner.manifest.sha256` `ManageData` entry. These are detached immutable-content proofs; they have no freshness, expiry, relying-party challenge, or anti-replay semantics and must not be treated as fresh authorization.

### External wallet XDR proof boundaries

Implemented as unsigned XDR generation + pasted `signedXDR`.

Supported assumptions:
- `ENVELOPE_TYPE_TX` only.
- every operation type must be `ManageData`. This avoids unsafe XDR behavior (payments, account merge, setOptions, etc.);
- operation-level source account is rejected;
- preconditions/memo extensions outside `NONE` are rejected;
- the single `ManageData` value must equal the protected-manifest SHA-256 digest;
- the wallet-returned transaction bytes must exactly equal the generated unsigned draft (only the envelope signature may be added);
- exactly one canonical 64-byte Ed25519 decorated signature is allowed and its hint must match the signer;
- XDR bounds and zero padding required by the Stellar schema and RFC 4506 are enforced;
- signer signature must be cryptographically valid for the transaction hash and protected network passphrase;
- transaction source must exactly match the protected signer.

------------

## Development

### Install

```bash
npm install
```

### Run locally

```bash
npm run dev
```

Open: `http://localhost:5173`

### Build

```bash
npm run build
```

By default build uses bundle mode when `esbuild` is available.
You can force simple copy mode (no bundler dependency):

```bash
BUILD_MODE=copy npm run build
```

### GitHub Pages preview (external wallet only)

GitHub Pages is not an acceptable production secret-key origin: it cannot supply the required response headers and project sites share a `<user>.github.io` origin. The workflow is manual-only and builds with `LOCAL_SECRET_POLICY=disabled`; the application also independently disables seed generation/import on `*.github.io` and insecure origins. Pages is an external-wallet/verification preview only, including on custom Pages domains.

1. Push repository to GitHub.
2. In repository settings open `Pages`, set `Build and deployment` source to `GitHub Actions`.
3. Keep workflow file `.github/workflows/pages.yml` in `main`.
4. Run the workflow manually from the `Actions` tab.

The workflow builds `dist/` and deploys it as the Pages artifact.

For production, use a dedicated origin containing no unrelated applications and a host or edge proxy that sets the headers below. Do not accept a production seed until deployed headers and iframe denial have been tested. A meta CSP cannot enforce `frame-ancestors`.

Required security headers:

```http
Content-Security-Policy: default-src 'self'; connect-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'; trusted-types 'none'; frame-ancestors 'none'
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: clipboard-read=(self), clipboard-write=(self)
```

`frame-ancestors` must be delivered as an HTTP header; browsers ignore that directive in a meta CSP. The in-document meta CSP intentionally keeps `connect-src 'none'` and adds Trusted Types for script sinks.

Deployment verification checklist:

```bash
curl -I https://example.invalid/
```

Confirm the response includes the headers above and that the page cannot be embedded in an iframe.

Builds display the package version and commit identifier, use content-addressed JavaScript filenames, and emit `artifact-manifest.sha256`. That manifest detects accidental artifact drift but is not an authenticity proof when served from the same origin. Production releases should additionally use signed tags and an out-of-band signed attestation/checksum.

### Self-test

```bash
npm run selftest
```

Covers:
- StrKey roundtrip;
- local SEP-53 sign/verify;
- local SEP-53 negative cases;
- XDR proof signedXDR verification;
- wrong network passphrase detection;
- strict signature profile and ManageData coverage checks.
- RFC 8785/duplicate-key/Base64/XDR canonicality rejection;
- exact unsigned-XDR round-trip binding and stale-file-context rejection;
- malformed/extra XDR signature rejection;
- strict Ed25519 identity/small-order/canonicality policy.

------------

## License

This project is distributed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for the full text.
