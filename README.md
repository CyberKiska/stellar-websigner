# Stellar WebSigner
## Digital signature tool

Static client-only web app for Stellar (Ed25519) detached signatures (`.sig`) using pure HTML/CSS/JS.

[Features](#features) | [Architecture](#architecture) | [Development](#development) | [License](#license)

------------

## Features

1. Key management: generate/import/export Ed25519 (Stellar) key pairs.
2. Sign: select a file, create detached signature, download `.sig`.
3. Verify: select original file + `.sig`, get `VALID`/`INVALID` with technical details.

------------

## Architecture

### Algorithms and standards alignment

We aim to implement
* Ed25519 according to RFC8032 and FIPS 186-5
* SHA-256 according to RFC 4634
* SHA3-512 according to FIPS 202
* Signing with Stellar according to SEP-07 and SEP-53

### Security model

- No backend.
- No runtime network calls.
- No CDN.
- No telemetry.
- No persistent secret storage (`S...` is memory-only).
- Session seed wipe is attempted on clear/unload.

### Signature format choice

Detached signature format is JSON (`schema = stellar-file-signature/v1`) for deterministic parsing and auditability.

- human-readable and diff-friendly;
- explicit `hashes[]` block;
- deterministic message payload for reproducible signing;
- defensive verification with field-by-field diagnostics.

### SEP-7 wallet compatibility boundaries

Implemented as wallet-agnostic SEP-7 URI + pasted `signedXDR`.

Supported assumptions:
- `ENVELOPE_TYPE_TX` only.
- every operation type must be `ManageData`. This avoids unsafe XDR behavior (payments, account merge, setOptions, etc.);
- operation-level source account is rejected;
- preconditions/memo extensions outside `NONE` are rejected;
- every signed digest must match corresponding `ManageData` value;
- signer signature must be cryptographically valid for tx hash and selected network passphrase.
- `txSourceAccount` is recorded for diagnostics; mismatch with `signer` is treated as warning (off-chain compatible).

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

### Self-test

```bash
npm run selftest
```

Covers:
- StrKey roundtrip;
- local SEP-53 sign/verify (both hashes);
- local SEP-53 sign/verify (single hash);
- local SEP-53 verify for renamed byte-identical files;
- SEP-7 signedXDR verification;
- wrong network passphrase detection.
- SEP-7 strict hash/ManageData coverage checks.

------------

## License

This project is distributed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for the full text.
