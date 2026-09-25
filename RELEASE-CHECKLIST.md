# Release checklist

This checklist prepares a production release candidate. Maintainer tag and artifact signatures are intentionally a separate provenance step and are not performed automatically.

## Reproducible inputs

- Confirm the release commit and version are intentional and the working tree contains no unexplained changes.
- Use Node.js 22 or newer and install exactly the lockfile with `npm ci`; confirm `npm ls esbuild` matches the locked version before building.
- Review dependency changes and run `npm audit --audit-level=high`.
- Confirm generated `test-vectors.json` has no unexplained drift.

## Security and quality gate

- Install the pinned engines with `npx playwright install chromium firefox webkit`.
- Run `npm run check:release` and require every self-test and browser project to pass or reach its documented fail-closed provider outcome. The session-persistence test requires the full Chromium build (`npx playwright install chromium` installs it).
- Build with the intended `LOCAL_SECRET_POLICY` and exact commit identifier.
- Run `npm run verify:artifact` against the final `dist/` directory after any packaging or transfer.
- Inspect `artifact-manifest.sha256`; archive it independently from the deployed origin.

## Deployment gate

- Use a dedicated HTTPS origin for any local-secret-enabled build.
- Verify the required CSP, HSTS, framing, nosniff, cross-origin (COOP/COEP/CORP), referrer, and permissions headers from the deployed response, that `self.crossOriginIsolated` is `true`, and that the origin is on (or submitted to) the HSTS preload list.
- Verify the deployed page cannot be embedded in an iframe. The in-app guard is defense in depth, not a substitute for response headers.
- Verify a local-secret-disabled build disables seed generation/import while preserving public-key, external-wallet, and verification workflows.
- Verify the displayed version and commit match the intended release candidate.
- Verify no runtime network request or third-party asset is introduced.

## Protocol acceptance

- Verify a v3 SEP-53 proof and a v3 XDR proof against known-good fixtures with the expected signer supplied (`VALID`), and without it (`SIGNER_UNVERIFIED`, never `VALID`).
- Verify tampered signature bytes produce `INVALID` without evaluating selected input metadata.
- Verify a valid signature with different bytes, basename, or expected signer produces `MISMATCH`.
- Verify identical file bytes/name/size with a different browser-reported media type remains `VALID` with an advisory warning.
- Verify that changing the input, signature file, or expected signer after a result clears the displayed verdict.
- Generate a key, reveal the seed, and confirm with a throwaway profile that the seed does not appear in the browser's session files.

## Maintainer provenance after release preparation

- Create and publish the maintainer-signed annotated tag.
- Publish an out-of-band signed checksum or attestation for the final artifact and its manifest.
- Verify those signatures from a separate trusted environment before announcing local-secret production availability.
