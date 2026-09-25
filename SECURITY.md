# Security policy

## Supported formats and assurance

Version 3.0.0 signs and verifies only `stellar-signature/v3`. Earlier signature containers are unsupported and rejected because they do not authenticate all surrounding metadata.

Verification reports three independent decisions:

- `signatureValid`: the signature document, protected protocol profile, and cryptographic proof are valid;
- `inputMatches`: the selected input type, basename (Unicode NFC), byte size, SHA-256, and SHA3-512 match the authenticated manifest;
- `contextMatches`: the authenticated signer matches the verifier's expected signer; it is null (shown as `NOT SUPPLIED`) when no expected signer is supplied.

Only a result where all three are true is `VALID`. If the expected signer is absent, `contextMatches` remains null and a matching content signature is `SIGNER_UNCONFIRMED` (shown as `UNCONFIRMED`), never `VALID`: the signer named in a `.sig` is self-asserted and proves only that the holder of that key signed. A cryptographically valid signature for a different input or signer is `MISMATCH`, not `INVALID`. Input and context comparisons are not performed until the manifest has been authenticated, and the signer of a failed proof is labeled as claimed, not authenticated. Any change to the verification inputs clears the displayed result.

The browser-reported file media type is retained as authenticated advisory metadata. A media-type difference produces a warning but does not override matching content digests, basename, and size because `File.type` can vary by user agent and operating system.

Algorithm alignment with FIPS 180-4, FIPS 186-5, and FIPS 202 is not FIPS validation. The application is not a validated cryptographic module, and the validation status of a browser provider cannot be established from JavaScript.

## Deliberately strict Ed25519 acceptance

Stellar WebSigner requires canonical encodings, canonical `S < L`, non-identity public-key and `R` points, and full prime-order subgroup membership for both points. The subgroup requirement is deliberately stricter than the acceptance behavior required by RFC 8032 and used by common Stellar verification stacks. It can reject an unusual signature or public key that another implementation accepts; it cannot turn an otherwise invalid signature into a valid one. Errors identify this as the Stellar WebSigner strict policy.

These checks run before every provider call and are required, not optional: current Chromium and Firefox Web Crypto providers accept the identity-key universal forgery. Startup known-answer tests also require the provider to reject invalid signatures that pass the strict pre-validation; a provider that fails disables the application.

## Production local-secret requirements

Local seed generation or import is allowed only on a secure, dedicated HTTPS origin that delivers every response header documented in `README.md`, including HSTS (preload recommended). The application also refuses to run inside a frame. GitHub Pages and builds with `LOCAL_SECRET_POLICY=disabled` are external-wallet/verification previews only.

Secrets and typed content are kept out of browser-persisted form state: every form control opts out with `autocomplete="off"`, and a generated seed is displayed only as text while revealed. Importing a seed together with its matching `G...` address avoids any private-key export.

The local-secret threat model does not include a compromised browser, extension, operating system, same-origin release, or deployment pipeline. JavaScript cleanup is best effort and cannot prove memory zeroization. Prefer external-wallet signing and independently verified offline artifacts.

## Release security gate

Run `npm run check:release` with all pinned Playwright browsers installed. This covers self-tests and startup KATs, independent core regressions, vectors, the production build, artifact-manifest verification, browser security behavior (including session-restore persistence with real browser profiles), and dependency audit. Verify the exact upload package again after packaging or transfer, and check the deployed headers and iframe denial before enabling local secrets.

`artifact-manifest.sha256` detects accidental or unauthorized drift only when its expected value is obtained through an independent trusted channel. It is not an authenticity proof when downloaded from the same potentially compromised origin. Maintainer-signed tags and out-of-band signed release attestations remain a separate release provenance step.

## Reporting a vulnerability

Use the repository host's private security-reporting channel when available. Do not include real secret seeds, private keys, or sensitive signed content in a report. Public issues are appropriate only for non-sensitive hardening suggestions and documentation defects.
