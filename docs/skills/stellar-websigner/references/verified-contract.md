# Verified implementation contract and evidence

Read this for schema integration, provenance, deployment checks, or interpreting a result beyond the operator workflow. Baseline: `stellar-websigner` **3.0.0**, 2026-09-25. Paths below are repository-relative links.

Evidence labels: **S** = inspected implementation; **R** = executed against this checkout; **I** = operational inference/recommendation; **U** = untested external behavior. Test success describes the exercised cases, not a complete cryptographic/security audit.

## Construction and formats (S; principal paths also R)

Let `C` be the exact input bytes and `P` the protected manifest. Both creation flows compute SHA-256(C) and SHA3-512(C). Let `M = UTF8(JCS(P))`.

| Profile | Exact construction and container |
|---|---|
| Local | `H = SHA256(UTF8("Stellar Signed Message:\n") || M)`; `signature = Ed25519.sign(seed, H)`. Top-level keys exactly `schema`, `signer`, `protected`, `signatureB64`. This is SEP-53 over the manifest, not over C, a hex digest string, or the whole container. Not Ed25519ph. |
| External | Exactly one `ManageData` named `org.stellar-websigner.manifest.sha256` whose value is the **32 raw bytes** `SHA256(M)`. `networkID = SHA256(UTF8(passphrase))`; `txHash = SHA256(networkID || int32be(2) || transactionXDR)`; Ed25519 signs `txHash`. Top-level keys exactly `schema`, `signer`, `protected`, `signedXdr`. No top-level `signatureB64`; the UI extracts it for display only. |
| Serialization | `schema = "stellar-signature/v3"` (the only accepted schema); top-level signer must exactly equal protected signer. Download is compact canonical JSON with no appended newline. UI JSON is sorted, two-space indented, with trailing newline; either representation verifies. JSON property order is irrelevant to verification; hash-array order is mandatory. Files must be UTF-8 without BOM. |

Both profiles use SHA-256 as an outer binding even though the manifest contains both content digests. Do not describe this as a post-quantum signature or an independent SHA3-512 outer security guarantee. Identical key, input metadata/content and profile yield deterministic documents; no creation time or random nonce is included (S).

### Protected manifest schema

All rows below are required unless marked XDR-only. Missing or extra keys fail.

| Member | Required value / shape |
|---|---|
| `application` | `"stellar-websigner"` |
| `formatVersion` | Number `1` (distinct from schema v3 and app version 3.0.0) |
| `purpose` | `"detached-content-authentication"` |
| `proofType` | `"sep53-message-signature"` or `"xdr-envelope-proof"` |
| `payloadType` | `"protected-manifest"` |
| `signatureScheme` | `"sep53-sha256-ed25519"` for local; `"tx-envelope-ed25519"` for XDR |
| `signer` | Same canonical G string as container signer |
| `input` (file) | Exactly `{type:"file", name, namePolicy:"exact-basename", size, mediaType}`; new documents store `name` in Unicode NFC, and comparison normalizes both sides to NFC |
| `input` (text) | Exactly `{type:"text", size, mediaType:"text/plain;charset=utf-8", textEncoding:"utf-8-dom-value-no-normalization"}` |
| `hashes` | Exactly `[{alg:"SHA-256",hex:64_lowercase_hex_chars},{alg:"SHA3-512",hex:128_lowercase_hex_chars}]`, in this order |
| `network` (XDR-only) | Exactly `{passphrase, hint}`. Trimmed nonempty passphrase at most 255 JS characters; hint `"pubnet"`, `"testnet"`, or `"custom"` must correspond to its exact value. Local manifests must omit `network`. |

`size` is a nonnegative safe integer in bytes. File media type is trimmed/lowercased browser `File.type`, default `application/octet-stream`; canonical metadata must be 1–255 printable ASCII characters. It is signed for provenance but compared only as an advisory warning. Text media type is fixed. Last-modified time is read into context but excluded from the manifest.

Core XDR helpers/verifier support Testnet/custom passphrases; **the browser creation flow always supplies Public Network**. Finalization demands exact original transaction bytes (including fee 8000). Standalone `.sig` verification has no original draft: it enforces the proof profile, sequence 0, and fee 1–100000, rather than requiring fee exactly 8000. Do not conflate these two acceptance rules.

XDR parsing accepts only envelope tag 2, ED25519 account type 0, no operation source, PRECOND_NONE, MEMO_NONE, tx.ext.v=0, canonical zero padding, printable-ASCII (0x20–0x7E) string bytes (as stellar-core validates ManageData names), and fully consumed bytes. Verification then requires exactly one operation, the namespaced manifest `ManageData` with the correct digest and source, and exactly one 64-byte decorated signature with the public key's last four bytes as hint. Fee-bump, muxed accounts, payments, account merge, setOptions, multiple signatures and additional operations fail. There is no submit endpoint.

### Verification result semantics (S, R)

`signatureValid`, `inputMatches` and `contextMatches` are reported separately. `summary` precedence: `INVALID` (proof failed) > `MISMATCH` (input or expected signer differs) > `SIGNER_UNVERIFIED` (no expected signer supplied; `contextMatches` is `null`, shown as `NOT CHECKED`) > `VALID_WITH_WARNINGS` > `VALID`. `valid` is true only when all three are true. Manifest metadata is compared only after the proof authenticates it; for `INVALID`, the document signer and hashes are labeled as claimed/unauthenticated. Strict-policy rejections name the reason (public key, `R`, or non-canonical `S`).

Sources: [signing.js](../../../../src/core/signing.js), [sep53.js](../../../../src/core/sep53.js), [protected-manifest.js](../../../../src/core/protected-manifest.js), [message.js](../../../../src/core/message.js), [signature-container.js](../../../../src/core/signature-container.js), [xdr-proof.js](../../../../src/core/xdr-proof.js), [xdr.js](../../../../src/core/xdr.js), [verify.js](../../../../src/core/verify.js), [bytes.js](../../../../src/core/bytes.js), [canonical-json.js](../../../../src/core/canonical-json.js).

The prefix/hash/signature construction was cross-checked against the official [SEP-53 specification](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md) (v1.0.0, Final); its raw-message vectors match the bundled test vectors byte for byte but do not directly equal this app's manifest signatures. Canonicalization follows [RFC 8785 JCS](https://www.rfc-editor.org/info/rfc8785/). These references establish format intent; source/runtime establish this app's behavior.

## Browser APIs, dependencies, and data lifetime (S)

| Area | Actual implementation |
|---|---|
| Bootstrap | ES modules, top-level await, BigInt, DOM events; frame check, then startup KATs: provider SHA-256; one-shot and chunked-streaming SHA3-512; RFC 8032 TEST 1 signing and verification; provider-negative Ed25519 (different message, modified canonical `S`) that must be rejected by the provider itself. Any startup exception disables all controls, including verification. |
| Ed25519 | `crypto.subtle.generateKey/importKey/exportKey/sign/verify`. The app validates public points and signature `R` using BigInt, rejects identity/non-prime-order points and `S >= L` before every provider call. This is load-bearing: raw Chromium 153 / Firefox 155 Web Crypto accept the identity-key universal forgery. Secret-dependent signing/derivation stays in the provider. Strict policy can reject signatures other verifiers accept. |
| Key material | Signing-session key imported non-extractable via PKCS#8. Generated provider pair is temporarily extractable to export the seed/public key. Seed import with a supplied G proves the pair by sign/verify without any export. Without G: proposed `subtle.getPublicKey` if available (absent in all tested browsers), else temporary extractable private JWK (`d`, `x`) with seed consistency check. Other derivation failures propagate. Public-key import tries raw then SPKI. |
| Hashing / file IO | `File/Blob.slice().arrayBuffer()` in 512 KiB chunks assembled into one buffer (≤ 64 MiB, wiped after hashing); text uses `TextEncoder`, 64 KiB chunks. SHA-256 always via Web Crypto (no incremental API, so one call over the assembled input); SHA3-512 via the bundled FIPS 202 implementation, absorbed per chunk (cooperative, cancellable). Short/long chunk reads and final size changes fail. No portable whole-file filesystem lock is available. |
| Native hashes | One-shot SHA3-512 probes proposed `SHA3-512`, falling back only for `NotSupportedError` (all tested browsers fall back). |
| Scheduling | `AbortController`, operation epochs/nonces, `setTimeout` yielding/debounce (Sign text: 180 ms), `requestAnimationFrame`. Hashing runs on the UI thread; cancellation is cooperative. Rehashing before signing/finalization/verification avoids trusting the initial preview digest. |
| Input/output | Typed arrays, DataView, `btoa/atob`; `.sig` bytes decoded with a fatal UTF-8 decoder, BOM rejected. Downloads use Blob/object URL/anchor click, revoke after 200 ms. Clipboard `readText/writeText` depends on permission/context; write has legacy `execCommand` fallback. Keys use native `window.confirm`. |
| State | Module-local in-memory objects; no application use of localStorage/sessionStorage/IndexedDB/cookies, service workers, or backend API. Every form control has `autocomplete="off"`, so browsers do not persist form state to session-restore/history files; the generated seed is a text node shown only while revealed, never a form value. No runtime dependencies, CDN, fetch/XHR/WebSocket/beacon. Static assets still load from the origin, and the user-clicked Source code link navigates externally. |
| Cleanup | Session `destroy()` releases the CryptoKey reference; it is an app wrapper, not proof of native key erasure. Imported seed buffers/forms are cleared; generated seed bytes/string remain until replacement/end. Any key change or wipe re-masks the seed entry field. beforeunload/pagehide run wipe handlers; persisted pageshow wipes and reloads. End Session clears keys, sign output and the verification result, but not original input fields or logs. |
| Build/test | Package devDependencies `esbuild ^0.28.2`, `@playwright/test ^1.63.0` (installed 0.28.2 and 1.63.0; `npm audit`: 0 vulnerabilities). Node requirement >=22. Bundle targets ES2022; `BUILD_MODE=copy` needs no bundler. No Stellar SDK or external crypto library in the shipped app. |

Sources: [main.js](../../../../src/main.js), [runtime-check.js](../../../../src/core/runtime-check.js), [ed25519.js](../../../../src/core/ed25519.js), [ed25519-validation.js](../../../../src/core/ed25519-validation.js), [strkey.js](../../../../src/core/strkey.js), [hash.js](../../../../src/core/hash.js), [input-context.js](../../../../src/core/input-context.js), [keys UI](../../../../src/ui/keys.js), [sign UI](../../../../src/ui/sign.js), [verify UI](../../../../src/ui/verify.js), [common UI](../../../../src/ui/common.js), [session-wipe.js](../../../../src/app/session-wipe.js), [package.json](../../../../package.json).

## Deployment and security boundaries

**S:** Local-secret gating checks secure context, non-`github.io` hostname, and build meta policy `enabled`. It does **not** inspect response headers, authenticate the build, or establish dedicated-origin isolation. The Pages workflow uses `LOCAL_SECRET_POLICY=disabled` (including custom domains); the runtime additionally refuses frames. Keep that restriction.

For production local-secret operation, use an independently authenticated offline artifact and the dedicated-origin requirements of [SECURITY.md](../../../../SECURITY.md). Verify actual responses against [security-headers.mjs](../../../../scripts/security-headers.mjs):

```http
Content-Security-Policy: default-src 'self'; connect-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'; trusted-types 'none'; frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(self), clipboard-write=(self)
```

Also confirm `self.crossOriginIsolated === true` in the loaded page and that the origin is on (or submitted to) the HSTS preload list: the secure-context check cannot resist TLS stripping. Meta CSP cannot enforce `frame-ancestors`; an emitted `_headers` file is not evidence the host serves these headers. Build UI commit defaults to `development` unless `BUILD_COMMIT`/`GITHUB_SHA` is supplied. Bundle names are content-addressed; copy-mode filenames are not. `npm run verify:artifact` detects changed/missing/extra files, but a manifest from the same compromised origin cannot authenticate that origin. The Pages workflow removes `_headers` and its manifest entry, then re-verifies the artifact before upload.

**I:** Preserve an immutable original while hashing/signing and verify the downloaded proof afterward. Repeated rehashing detects ordinary changes but cannot certify a live mutable file's future contents. Hashes can disclose low-entropy content guesses; metadata and filenames are public in `.sig`. Cleanup cannot guarantee erasure of JS strings, OS memory/swap, clipboard contents, or downloaded files. Algorithm alignment (FIPS 180-4/186-5/202) is not FIPS validation; no module validation, RNG entropy certification, revocation, freshness, legal identity, ledger account existence or threshold control is established. A wallet shows the manifest digest only as an opaque value; confirmation against the app's displayed value is the only link between wallet request and content.

## Executed evidence (R)

Environment: macOS arm64, Node `v26.7.0`; Playwright 1.63.0 with Chromium 153.0.8010.12 (revision 1243, full build and headless shell), Firefox 155.0 (1543), WebKit 26.6 (2359). Only public fixture keys, freshly generated throwaway keys, and test content were used; no wallet account, production key, network submission, deployment or publication occurred.

| Check | Observed result |
|---|---|
| `npm run check:production` | Exit 0. **71/71** self-tests; vectors regenerated without drift (the generator refuses vectors that do not verify `VALID`); production build; manifest verified exactly **6 files**; browser suite **17 passed, 4 skipped** (WebKit fails the Ed25519 startup KAT and is disabled closed, so its crypto-dependent workflows skip). |
| `npm audit` | 0 vulnerabilities (development dependencies only). |

Browser tests ([workflows](../../../../tests/browser/agent-workflows.spec.js), [production security](../../../../tests/browser/production-security.spec.js), [session persistence](../../../../tests/browser/session-persistence.spec.js)):

- Local signing: empty text disables Sign; CRLF/CR textarea input becomes LF; both content hashes match Node crypto; the browser signature verifies independently via Node Ed25519 over an independently serialized manifest; download bytes equal canonical JSON named `plain-text.sig`; zero network requests during these actions; End Session clears signing state/output but leaves the original textarea.
- Seed import: a mismatched G is rejected without installing a session; the matching G installs it (no private-key export path).
- File verification: exact match with expected signer `VALID`; editing the file or expected signer hides the result; renamed original `MISMATCH`; changed MIME `WARNING`; blank expected signer `UNVERIFIED SIGNER` with `NOT CHECKED`; tampered protected name `INVALID` with claimed-signer labeling; BOM-prefixed `.sig` `INVALID`.
- External handoff: G-only session generates sequence 0 / fee 8000 / one namespaced digest operation; `#sign-xdr-manifest-digest` equals the ManageData value; Testnet signature rejected; Public signature creates an XDR `.sig` that verifies; a correctly signed fee change is rejected and leaves no downloadable output.
- Lifecycle and gating: headers and iframe denial; disabled-build behavior; key-operation serialization; deterministic hashing cancellation; navigation/BFCache cleanup; seed re-masking on session replacement.
- Session persistence: with persistent profiles (full Chromium, Firefox), a revealed generated seed and typed text/signed-XDR content do not appear in any profile file; removing `autocomplete="off"` from one field makes the test fail in both engines.

Run from repository root after `npm ci` and `npx playwright install chromium firefox webkit`. Local servers bind 127.0.0.1:4173 and :4174.

**U:** No named third-party wallet/hardware wallet, real mainnet account, deployed site's headers/provenance, production offline device, shipping Safari, Windows/Linux browsers, password-manager extensions, download-collision behavior, or real clipboard permission/fallback was exercised. Runtime verification supports the operator guide, not a claim that all wallet/browser/provider combinations or all adversarial cases are safe.
