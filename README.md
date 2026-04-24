# Stellar WebSigner
## Digital signature tool

Static client-only web app for Stellar (Ed25519) content signatures and XDR proofs (`.sig`) using pure HTML/CSS/JS.

[Features](#features) | [Architecture](#architecture) | [Development](#development) | [License](#license)

------------

## Features

1. Key management: generate/import/export Ed25519 (Stellar) keypairs.
2. Sign locally: select file/text, create SEP-53 content signature, download `.sig`.
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

SEP-53 signs `SHA-256("Stellar Signed Message:\n" || messageBytes)` with Ed25519. This is not Ed25519ph. The SHA-256 step is part of the Stellar SEP-53 message construction, not the RFC 8032 prehash signing variant.

### Security model

- No backend.
- No runtime network calls.
- No CDN.
- No telemetry.
- No persistent secret storage (`S...` is memory-only).
- Session seed wipe is attempted on clear/unload.

This app protects against accidental network disclosure, malformed signature documents, unsafe XDR proof envelopes, and common deployment mistakes when the required headers are installed. It does not protect a secret seed from a compromised browser, malicious extension, injected script already running in the tab, or an operating system compromise.

### Non-goals

- Not a timestamping authority.
- Not a revocation system.
- Not a general PKI or identity verification service.
- Not anti-exfiltration against a compromised tab.
- Not a replacement for hardware wallets or multisig operational controls.

### Signature format choice

Detached signature format is JSON (`schema = stellar-signature/v2`) for deterministic parsing and auditability.

- human-readable and diff-friendly;
- explicit `hashes[]` block;
- explicit proof profile metadata for reproducible verification;
- defensive verification with field-by-field diagnostics.

### External wallet XDR proof boundaries

Implemented as unsigned XDR generation + pasted `signedXDR`.

Supported assumptions:
- `ENVELOPE_TYPE_TX` only.
- every operation type must be `ManageData`. This avoids unsafe XDR behavior (payments, account merge, setOptions, etc.);
- operation-level source account is rejected;
- preconditions/memo extensions outside `NONE` are rejected;
- every signed digest must match corresponding `ManageData` value;
- signer signature must be cryptographically valid for tx hash and selected network passphrase.
- `txSourceAccount` must exactly match `signer`.

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

### Deploy to GitHub Pages

This app is already a single-page static app, so it can be hosted directly on Pages.

1. Push repository to GitHub.
2. In repository settings open `Pages`, set `Build and deployment` source to `GitHub Actions`.
3. Keep workflow file `.github/workflows/pages.yml` in `main`.
4. Push to `main` (or run workflow manually via `Actions` tab).

The workflow builds `dist/` and deploys it as the Pages artifact.

GitHub Pages does not support custom HTTP response headers. For production use, place Pages behind a host or edge proxy that can set the headers below, or deploy `dist/` to a host that honors `_headers`.

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

------------

## License

This project is distributed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for the full text.
