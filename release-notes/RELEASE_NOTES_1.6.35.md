# Fluxheim 1.6.35 Release Notes

Fluxheim 1.6.35 is the first stabilization checkpoint after the Pingora-free
runtime proof release.

This release is intentionally scoped to security cleanup, soak-test evidence,
performance/regression checks, dependency hygiene, and documentation clarity
before the 1.6.36 structural cleanup removes the temporary native proxy shim.

## Highlights

- Keep the normal runtime on the Fluxheim-owned listener, TLS, HTTP/1, HTTP/2,
  WebSocket, cache, load-balancer, admin, metrics, stream, and background
  service paths introduced by the 1.6.34 Pingora-free proof release.
- Start the first-party secret-memory migration pass from direct `zeroize`
  calls toward Fluxheim's `sanitization` crate where the replacement is
  practical and testable.
- Move the legacy root auth subrequest forwarded-header secret container from
  direct `zeroize` wrappers to `sanitization::SecretString`.
- Move native auth-request forwarded and allowed response-header secret
  containers to `sanitization::SecretString`.
- Fix the release version-bump helper so package versions such as `1.6.35` are
  not interpreted as regex backreferences during automated metadata updates.
- Keep dependency, metadata, container, RPM, and smoke-test gates as blocking
  evidence for the stabilization line.

## Compatibility Notes

- No new protocol or extensibility surface is planned for this checkpoint.
- Third-party transitive `zeroize` use inside dependencies such as rustls,
  AWS-LC, and other cryptographic crates remains untouched.
- The 1.6.36 follow-up remains reserved for structural cleanup: deleting the
  temporary native proxy shim, moving remaining DTOs/helpers into owning crates,
  and removing inert Pingora-era root code.

## Verification

- `scripts/validate-release-metadata.sh`
- `scripts/validate-pingora-dependency-policy.sh`
- `scripts/validate-native-runtime-cutover.sh`
- `scripts/stable_release_gate.sh check`
