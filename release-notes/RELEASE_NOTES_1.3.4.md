# Fluxheim 1.3.4 Release Notes

## Summary

Fluxheim 1.3.4 is the OpenSSL FIPS-capable TLS release for the 1.3 line. It
adds strict terminology, OpenSSL-provider diagnostics, OpenSSL default-property
enforcement for FIPS-required TLS startup, fail-closed configuration
validation, and release evidence plumbing.

This release does not claim that Fluxheim is FIPS certified or that enabling a
Cargo feature makes a deployment compliant. FIPS validation belongs to the
selected cryptographic module and its tested operating environment. Fluxheim's
role is to enforce configuration boundaries, verify provider status where the
backend exposes it, and produce useful evidence for operators.

- Release type: OpenSSL FIPS-capable TLS validation and release tooling
- Compatibility: no broad config break intended
- Primary area: OpenSSL FIPS provider diagnostics, OpenSSL default FIPS
  properties, `tls.fips.required`, release evidence, and FIPS documentation

## Highlights

- Added `docs/fips.md`, a standalone FIPS-capable deployment guide covering
  NIST/CMVP references, compliance boundaries, OpenSSL and rustls/AWS-LC paths,
  internal cryptography blockers, and post-`1.3.4` roadmap work.
- Added `[tls.fips] required = true` as a fail-closed guard for FIPS-required
  configuration. Default builds reject it because they cannot prove a
  validated provider path.
- Added `tls-openssl-fips`, an opt-in OpenSSL 3 provider proof path that
  checks that the OpenSSL FIPS provider can be loaded and that an approved
  cipher can be fetched with the `fips=yes` property query.
- FIPS-required OpenSSL startup now enables and verifies OpenSSL default FIPS
  properties through `EVP_default_properties_enable_fips` and
  `EVP_default_properties_is_fips_enabled` before Pingora TLS services are
  built.
- The OpenSSL FIPS-capable runtime check verifies that approved AES-GCM can be
  fetched through the default property path and that a non-FIPS cipher is
  rejected there.
- Patched the vendored `pingora-openssl` compatibility crate to stop forcing
  `openssl/vendored`, so FIPS-capable OpenSSL builds can link against the
  operator-selected system OpenSSL provider.
- Added `profile-fips-openssl` as a narrow proxy/security/OpenSSL-FIPS feature
  alias for local and release validation.
- Added `fluxheim crypto` and `fluxheim-config-tester --crypto` diagnostics
  showing compiled TLS backends, OpenSSL FIPS provider availability, OpenSSL
  version, and visible `OPENSSL_CONF` / `OPENSSL_MODULES` environment.
- Added `examples/fips-openssl.toml` and
  `fluxheim-config-tester --profile fips-openssl` so operators and CI can
  validate the expected OpenSSL FIPS configuration shape.
- Added `scripts/validate-fips-openssl.sh` for local and release checks. It
  builds the FIPS-capable profile, captures provider diagnostics, validates the
  FIPS fixture, and optionally fails if no provider is available with
  `FLUXHEIM_REQUIRE_FIPS_PROVIDER=1`.
- The OpenSSL FIPS-capable validation script now also proves fail-closed
  behavior for backend mismatch and non-FIPS TLS policy fixtures.
- Wired OpenSSL FIPS-capable validation into CI, `scripts/checks.sh`, the
  optional stable release gate, the deep release gate, and release evidence
  capture.
- Added an OWASP Top 10 2025 baseline document and validation script mapping
  Fluxheim-owned controls to A01-A10, with a quick CI mode and deeper local
  representative-test mode. The baseline is wired into CI, local checks, stable
  release gates, and release evidence capture.
- Updated build, feature, config-reference, release-runbook, readiness, and
  roadmap documentation to use "FIPS-capable" language and avoid compliance
  overclaims.

## Operator Notes

For local OpenSSL FIPS-provider validation:

```bash
scripts/validate-fips-openssl.sh check
```

For strict validation on a builder that is expected to have a working provider:

```bash
FLUXHEIM_REQUIRE_FIPS_PROVIDER=1 scripts/validate-fips-openssl.sh check
```

Fluxheim does not hardcode provider module directories. Provider discovery uses
OpenSSL's normal configuration and environment model, including `OPENSSL_CONF`,
`OPENSSL_MODULES`, distro crypto policies, and compiled-in defaults.

The 1.3.4 OpenSSL path loads the `fips` provider, fetches an approved cipher
with `fips=yes`, enables OpenSSL default FIPS properties for the process-default
library context, verifies that those default properties are active, and checks
that the default fetch path rejects a non-FIPS cipher. Operators still need to
install and configure a validated OpenSSL provider according to the selected
module Security Policy; Fluxheim is not itself a validated cryptographic
module.

## Build

Build the OpenSSL FIPS-capable profile explicitly:

```bash
cargo build --release --locked --no-default-features \
  --features profile-fips-openssl \
  --bin fluxheim --bin fluxheim-config-tester
```

Build the normal PHP-FPM release profile as before:

```bash
cargo build --release --locked --no-default-features \
  --features profile-web-server,php-fpm,acme-client \
  --bin fluxheim --bin fluxheim-acme
```

## Checksums And Signatures

To be filled during release.
