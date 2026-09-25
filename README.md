# Stellar WebSigner
## Digital signature tool

Static client-only web app for Stellar (Ed25519) content signatures and XDR proofs (`.sig`) using pure HTML/CSS/JS.

For AI-assisted operation, use the repository-local [Stellar WebSigner skill](docs/skills/stellar-websigner/SKILL.md). It contains exact workflows, validation limits, recovery instructions, and a linked code/runtime evidence record.

[Features](#features) | [Architecture](#architecture) | [Development](#development) | [License](#license)

------------

## Features

1. Key management: generate/import Ed25519 (Stellar) keys and export public information only.
2. Sign locally: select file/text, sign a protected manifest through SEP-53, download `.sig`.
3. Sign with external wallet: generate unsigned XDR proof, sign externally, paste signed XDR, download `.sig`.
4. Verify: select original input + `.sig` + the expected signer, get `VALID`, `UNCONFIRMED`, `MISMATCH`, or `INVALID` with separated cryptographic, input, and signer-context diagnostics.

------------

## Architecture

### Algorithms and standards alignment

We aim to implement
* Ed25519 according to [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) and [FIPS 186-5](https://doi.org/10.6028/NIST.FIPS.186-5), executed by the browser Web Crypto provider
* SHA-256 according to [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4), executed by the browser Web Crypto provider
* SHA3-512 according to [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202), bundled implementation (browser Web Crypto does not offer SHA-3)
* Message signing with Stellar according to [SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md), especially its Signing Procedure
* Detached XDR proof verification according to Stellar transaction hashing/signature rules

SEP-53 signs `SHA-256("Stellar Signed Message:\n" || messageBytes)` with Ed25519. This is not Ed25519ph. `messageBytes` is the RFC 8785 serialization of the protected manifest; the manifest contains the detached content digests.

Algorithm alignment is not validation. No component is a FIPS 140-3 validated module, and the validation status of a browser's cryptographic provider cannot be established from JavaScript. Do not describe deployments as FIPS-compliant.

Verification performs provider-independent Ed25519 checks before Web Crypto: canonical point encodings, prime-order subgroup membership for the public key and `R`, rejection of the identity point, and canonical `S < L`. Full subgroup membership is a deliberate acceptance policy stricter than RFC 8032 and common Stellar verification stacks: it can produce a false-negative interoperability result for an unusual mixed-order point, but cannot produce a false-valid result. Honest signatures and keys are always in the prime-order subgroup. Policy errors for public keys, `R`, and `S` identify the strictness explicitly.

This pre-validation is load-bearing, not cosmetic: current Chromium and Firefox Web Crypto providers accept the identity-key universal forgery (identity `A`, identity `R`, `S = 0`) that the W3C specification asks them to reject ([Issue 423](https://github.com/w3c/webcrypto/issues/423)). Every verification path in the application goes through the strict checks.

Startup known-answer tests gate the application. They cover SHA-256 through the provider, one-shot and chunked-streaming SHA3-512, RFC 8032 TEST 1 signing and verification, and provider-negative Ed25519 cases (a different message and a modified canonical `S`, both of which pass the strict pre-validation and must be rejected by the provider itself). A provider that fails any of them disables all application controls.

SHA-256 always comes from Web Crypto. Web Crypto has no incremental digest, so a selected file (at most 64 MiB) is assembled in memory for the single SHA-256 call and wiped afterwards, while SHA3-512 is absorbed chunk by chunk so hashing stays cooperative and cancellable. One-shot SHA3-512 first probes the proposed WebCrypto `SHA3-512` identifier and falls back to the bundled FIPS 202 implementation only when the provider reports `NotSupportedError`; other provider failures are fatal. The proposed native identifier is from the unofficial [Modern Algorithms in the Web Cryptography API](https://wicg.github.io/webcrypto-modern-algos/) draft and is not assumed to be available.

### Security model

- No backend.
- No runtime network calls.
- No CDN.
- No telemetry.
- No persistent secret storage. Signing uses a non-extractable `CryptoKey`, and temporary byte buffers are cleared in `finally` blocks.
- Plaintext secret download and secret clipboard export are disabled.
- Secret form controls and key state are cleared on session end, unload/pagehide, and BFCache restoration.
- No form state reaches disk through the browser: every form control sets `autocomplete="off"`, which excludes it from session-restore and history form-state persistence. The generated seed is never placed in a form control; it is rendered as text only while revealed. A persistent-profile browser test checks Chromium and Firefox session files for the seed and typed content.

Cleanup is best effort, not guaranteed zeroization: JavaScript strings, discarded `CryptoKey` material, the OS clipboard, swap/crash dumps, and browser memory are outside the application's complete control.

Public-key derivation does not perform secret-scalar arithmetic in application JavaScript. Generated keypairs reuse the provider-generated public key and verify that it matches the signing key. When importing a seed, enter the matching `G...` address first: the pair is then proven with a sign/verify check and the private key never leaves the provider. Without it, the proposed `subtle.getPublicKey()` operation is preferred; no current browser implements it, so derivation falls back to a temporary extractable provider key and private JWK export. The exported `d` value is checked against the seed and references are cleared immediately, but its immutable string storage cannot be guaranteed zeroized. A provider failure other than explicit lack of support is not silently downgraded.

This app protects against accidental network disclosure, malformed signature documents, unsafe XDR proof envelopes, and common deployment mistakes when the required headers are installed. It does not protect a secret seed from a compromised browser, malicious extension, malicious same-origin release, compromised deployment pipeline, or operating-system compromise. Online JavaScript origin integrity is private-key integrity. Prefer the external-wallet flow; use local-seed signing only from an independently verified offline artifact on a dedicated device/origin.

Key generation uses `subtle.generateKey('Ed25519')` and therefore relies on the browser and operating system random-bit generator. Browser JavaScript cannot inspect raw noise samples or establish SP 800-90B/90C, SP 800-133, FIPS 186-5, or FIPS 140 validation status. The startup check is a capability/KAT check, not entropy certification.

### Non-goals

- Not a timestamping authority.
- Not a revocation system.
- Not a general PKI or identity verification service.
- Not anti-exfiltration against a compromised tab.
- Not a replacement for hardware wallets or multisig operational controls.

### Signature format choice

Version 3.0.0 accepts only JSON schema `stellar-signature/v3`. Earlier containers are rejected; unsigned-metadata legacy verification has been removed.

- `protected` binds application, format version, purpose, signer, proof profile, exact input role/name (Unicode NFC)/size, advisory browser media metadata, and exactly SHA-256 plus SHA3-512;
- protected bytes use RFC 8785 canonical JSON and reject non-I-JSON strings/numbers;
- JSON files require valid UTF-8 without a BOM; parsing rejects duplicate members, noncharacters, excessive size/depth, unknown fields, missing fields, and incorrect field types;
- binary fields require strings containing canonical padded RFC 4648 Base64; arrays and other coercible values are rejected.

Text mode signs UTF-8 of the textarea DOM value, with no Unicode normalization; CRLF and CR are normalized to LF by the application (not every engine does this in the textarea value); unpaired UTF-16 surrogates are rejected. Verifiers must supply the same DOM text value. Text is limited to 1 MiB after UTF-8 encoding and is hashed in cooperative, cancellable chunks.

Verification authenticates the canonical protected manifest before using its metadata to compare the selected input or the expected signer. `signatureValid`, `inputMatches`, and `contextMatches` are reported independently:

- `VALID`: the proof, the selected input, and the expected signer all match;
- `SIGNER_UNCONFIRMED`: the proof and input match, but no expected signer was supplied. The signer named in a `.sig` is self-asserted; anyone can re-sign substituted content with their own key. This state only shows that the holder of that key signed, and is never presented as `VALID`. Obtain the expected `G...` address through a trusted channel;
- `MISMATCH`: a valid signature for different content, basename, size, or signer;
- `INVALID`: a failed proof. Input/context results are then reported as not checked, and the document's signer is labeled as claimed, not authenticated.

A verdict describes the inputs it was computed from: changing any input, the signature file, the expected signer, or the key session clears the displayed result.

`File.type` is user-agent metadata rather than content-derived identity. It remains signed for provenance, but a difference at verification is advisory and produces a warning. Basename (compared after Unicode NFC normalization, so composed and decomposed forms of the same name match), byte size, SHA-256, and SHA3-512 remain hard input-match requirements.

For local signing, the protected manifest itself is the SEP-53 message. For external signing, SHA-256 of that manifest is stored in the namespaced `org.stellar-websigner.manifest.sha256` `ManageData` entry. These are detached immutable-content proofs; they have no freshness, expiry, relying-party challenge, or anti-replay semantics and must not be treated as fresh authorization.

Both profiles sign in shared Stellar domains: any SEP-53 `signMessage` over a canonical manifest, and any wallet signature over a matching `ManageData` transaction, is a valid proof. A wallet shows the manifest digest only as an opaque value, so confirm that it equals the value displayed in the app before signing, and never sign such a request that you did not generate yourself.

### External wallet XDR proof boundaries

Implemented as unsigned XDR generation + pasted `signedXDR`.

Supported assumptions:
- `ENVELOPE_TYPE_TX` only.
- exactly one operation, a `ManageData` named `org.stellar-websigner.manifest.sha256`. This avoids unsafe XDR behavior (payments, account merge, setOptions, etc.);
- XDR strings must be printable ASCII (0x20-0x7E), matching stellar-core's `ManageData` name validation; a BOM or other bytes are rejected rather than normalized;
- operation-level source account is rejected;
- preconditions/memo extensions outside `NONE` are rejected;
- the `ManageData` value must equal the protected-manifest SHA-256 digest; the app displays this value (name, base64, hex) for confirmation in the wallet;
- the wallet-returned transaction bytes must exactly equal the generated unsigned draft (only the envelope signature may be added);
- exactly one canonical 64-byte Ed25519 decorated signature is allowed and its hint must match the signer;
- XDR bounds and zero padding required by the Stellar schema and RFC 4506 are enforced;
- signer signature must be cryptographically valid for the transaction hash and protected network passphrase;
- transaction source must exactly match the protected signer.

------------

## Development

### Install

```bash
npm ci
```

`npm ci` installs exactly the lockfile; use it for any build you intend to compare or release.

### Run locally

```bash
npm run dev
```

Open: `http://localhost:5173`

Use `npm run preview` to build, verify, and serve the minified production artifact on loopback without file watching. The browser security gate uses this mode for both local-secret policies.

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

The workflow runs the complete release gate and builds `dist/` with `BUILD_TARGET=pages` and `LOCAL_SECRET_POLICY=disabled`. The Pages target omits unsupported header markers before generating the manifest; the exact final upload directory is verified again before upload. A Pages build refuses an enabled local-secret policy.

For production, use a dedicated HTTPS origin containing no unrelated applications and a host or edge proxy that sets the headers below. Submit the origin to the HSTS preload list: the in-app secure-context check cannot resist TLS stripping, because an active attacker serves their own page. Do not accept a production seed until deployed headers and iframe denial have been tested. A meta CSP cannot enforce `frame-ancestors`. The application also refuses to initialize when framed, including on header-limited preview hosts; this is defense in depth and not a substitute for response headers.

Required security headers:

```http
Content-Security-Policy: default-src 'self'; connect-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'; trusted-types 'none'; frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Cache-Control: no-cache
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(self), clipboard-write=(self)
```

`frame-ancestors` must be delivered as an HTTP header; browsers ignore that directive in a meta CSP. The in-document meta CSP intentionally keeps `connect-src 'none'` and adds Trusted Types for script sinks.

Deployment verification checklist:

```bash
curl -I https://example.invalid/
```

Confirm the response includes the headers above, that the page cannot be embedded in an iframe, and that `self.crossOriginIsolated` is `true` in the loaded page.

Builds display the package version and commit identifier, use content-addressed JavaScript filenames, and emit `artifact-manifest.sha256`. The commit comes from CI or the local Git checkout; source archives should set `BUILD_COMMIT` to the full commit ID. `npm run verify:artifact` rejects missing, extra, non-regular, path-unsafe, or digest-mismatched build files. The manifest detects artifact drift but is not an authenticity proof when served from the same origin. Production releases should additionally use signed tags and an out-of-band signed attestation/checksum. Configure HTTPS redirection at the host; HSTS takes effect only after a secure response.

### Self-test

```bash
npm run selftest
```

Covers:
- startup KATs, including rejection of a provider whose verify accepts every signature;
- SHA-256/SHA3-512 vectors and the SHA3-512 streaming corpus;
- StrKey roundtrip and shape validation;
- local SEP-53 sign/verify, official SEP-53 vectors, and negative cases;
- expected-signer semantics (`VALID` only with a matching expected signer);
- XDR proof verification, wrong network passphrase detection, exact unsigned-XDR binding, and stale-file-context rejection;
- RFC 8785/duplicate-key/JSON depth/strict UTF-8/Base64/XDR canonicality and printable-ASCII data-name rejection;
- malformed/extra XDR signature rejection;
- strict Ed25519 identity/small-order/mixed-order/canonicality policy with explicit diagnostics;
- seed import with a supplied `G...` never exporting the private key;
- every form control opting out of browser form-state persistence.

`npm run test:core` additionally compares both bundled hashes with independent Node/OpenSSL implementations across 266 input sizes (including empty input, padding boundaries, and the 4 MiB SHA-256 transition). It checks the published SEP-53/XDR vectors using independent signing and transaction encoding, adversarial Ed25519 points/scalars, strict container parsing, byte ownership, and complete build packaging. The build tools are pinned in both `package.json` and the lockfile; use `npm ci` for reproducible installation.

### Production browser security gate

Install the pinned browser engines once, then run the complete release gate:

```bash
npx playwright install chromium firefox webkit
npm run check:production
```

The Playwright suite runs the deployed bundle in Chromium, Firefox, and WebKit. It verifies response security headers and iframe denial, the external-wallet-only build policy, startup Ed25519 provider behavior, key-operation serialization, cancellable text hashing, local signing, verdict semantics and invalidation, the external-wallet handoff, navigation/BFCache cleanup, and, with persistent browser profiles, that neither a revealed seed nor typed content is written to Chromium or Firefox session-restore files.

Local-secret support is capability-gated rather than inferred from the browser name. A provider must pass the RFC 8032 startup signing and verification KATs, including the provider-negative cases. A provider that fails is not permitted to continue in a reduced cryptographic mode: all application controls are disabled and a visible fatal error is displayed. The browser gate permits this explicit fail-closed outcome for an engine whose provider is non-conformant; Chromium and Firefox are required to complete the full local-secret flow.

For a release candidate, run `npm run check:release`, verify that regenerated vectors have no unexplained changes, and verify the exact final package after any transfer. Follow the deployment requirements above and [SECURITY.md](SECURITY.md). Maintainer tag and artifact signatures are handled as a separate provenance step.

------------

## License

This project is distributed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for the full text.
