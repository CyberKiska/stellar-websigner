# Release checklist

This checklist prepares a production release candidate. Maintainer tag and artifact signatures are intentionally a separate provenance step and are not performed automatically.

## Reproducible inputs

- Confirm the release commit and version are intentional and the working tree contains no unexplained changes.
- Use Node.js 22 or newer and install exactly the lockfile with `npm ci`.
- Review dependency changes and run `npm audit --audit-level=high`.
- Confirm generated `test-vectors.json` has no unexplained drift.

## Security and quality gate

- Install the pinned engines with `npx playwright install chromium firefox webkit`.
- Run `npm run check:release` and require every self-test and browser project to pass or reach its documented fail-closed provider outcome.
- Build with the intended `LOCAL_SECRET_POLICY` and exact commit identifier.
- Run `npm run verify:artifact` against the final `dist/` directory after any packaging or transfer.
- Inspect `artifact-manifest.sha256`; archive it independently from the deployed origin.

## Deployment gate

- Use a dedicated HTTPS origin for any local-secret-enabled build.
- Verify the required CSP, framing, cross-origin, referrer, and permissions headers from the deployed response.
- Verify the deployed page cannot be embedded in an iframe. The in-app guard is defense in depth, not a substitute for response headers.
- Verify a local-secret-disabled build disables seed generation/import while preserving public-key, external-wallet, and verification workflows.
- Verify the displayed version and commit match the intended release candidate.
- Verify no runtime network request or third-party asset is introduced.

## Protocol acceptance

- Verify a v3 SEP-53 proof and a v3 XDR proof against known-good fixtures.
- Verify tampered signature bytes produce `INVALID` without evaluating selected input metadata.
- Verify a valid signature with different bytes, basename, or expected signer produces `MISMATCH`.
- Verify identical file bytes/name/size with a different browser-reported media type remains `VALID` with an advisory warning.
- Confirm the v2 deprecation notice and removal date remain visible in verification diagnostics and documentation.

## Maintainer provenance after release preparation

- Create and publish the maintainer-signed annotated tag.
- Publish an out-of-band signed checksum or attestation for the final artifact and its manifest.
- Verify those signatures from a separate trusted environment before announcing local-secret production availability.
