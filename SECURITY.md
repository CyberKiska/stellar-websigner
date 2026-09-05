# Security policy

## Supported formats and assurance

Version 3.0.0 signs and verifies only `stellar-signature/v3`. Earlier signature containers are unsupported and rejected because they do not authenticate all surrounding metadata.

Verification reports three independent decisions:

- `signatureValid`: the signature document, protected protocol profile, and cryptographic proof are valid;
- `inputMatches`: the selected input type, exact basename policy, byte size, SHA-256, and SHA3-512 match the authenticated manifest;
- `contextMatches`: the authenticated signer matches the verifier's optional expected signer.

Only a result where all three are true is `VALID`. If the expected signer is absent, `contextMatches` remains null and a matching content signature is `SIGNER_UNCONFIRMED`; the UI displays `UNCONFIRMED`, never a successful expected-signer match. A cryptographically valid signature for a different input or signer is `MISMATCH`, not `INVALID`. Input and context comparisons are not performed until the v3 manifest has been authenticated.

The browser-reported file media type is retained as authenticated advisory metadata. A media-type difference produces a warning but does not override matching content digests, basename, and size because `File.type` can vary by user agent and operating system.

## Deliberately strict Ed25519 acceptance

Stellar WebSigner requires canonical encodings, canonical `S < L`, non-identity public-key and `R` points, and full prime-order subgroup membership for both points. The subgroup requirement is deliberately stricter than the acceptance behavior required by RFC 8032 and used by common Stellar verification stacks. It can reject an unusual signature or public key that another implementation accepts; it cannot turn an otherwise invalid signature into a valid one. Errors identify this as the Stellar WebSigner strict policy.

## Production local-secret requirements

Local seed generation or import is allowed only on a secure, dedicated origin that delivers every response header documented in `README.md`. The application also refuses to run inside a frame. GitHub Pages and builds with `LOCAL_SECRET_POLICY=disabled` are external-wallet/verification previews only.

The local-secret threat model does not include a compromised browser, extension, operating system, same-origin release, or deployment pipeline. JavaScript cleanup is best effort and cannot prove memory zeroization. Prefer external-wallet signing and independently verified offline artifacts.

## Release security gate

Run `npm run check:release` with all pinned Playwright browsers installed. This covers self-tests and startup KATs, independent core regressions, vectors, the production build, artifact-manifest verification, browser security behavior, and dependency audit. Verify the exact upload package again after packaging or transfer, and check the deployed headers and iframe denial before enabling local secrets.

`artifact-manifest.sha256` detects accidental or unauthorized drift only when its expected value is obtained through an independent trusted channel. It is not an authenticity proof when downloaded from the same potentially compromised origin. Maintainer-signed tags and out-of-band signed release attestations remain a separate release provenance step.

## Reporting a vulnerability

Use the repository host's private security-reporting channel when available. Do not include real secret seeds, private keys, or sensitive signed content in a report. Public issues are appropriate only for non-sensitive hardening suggestions and documentation defects.
