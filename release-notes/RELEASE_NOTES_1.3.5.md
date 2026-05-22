# Fluxheim 1.3.5 Release Notes

## Status

Fluxheim 1.3.5 adds the rustls/AWS-LC FIPS-capable candidate path for source
builds and release evidence.

## Highlights

- Added a rustls/AWS-LC FIPS-capable candidate backend through
  `tls-rustls-fips`.
- Added `profile-fips-rustls` and `profile-iso19790-rustls` as narrow
  validation aliases for rustls/AWS-LC FIPS and ISO/IEC 19790 terminology.
- Added `tls-rustls-iso19790` as the raw ISO/IEC 19790 terminology alias for
  `tls-rustls-fips`.
- Refactored rustls TLS setup so normal rustls builds keep the ring provider
  while rustls FIPS candidate builds install/pass
  `rustls::crypto::default_fips_provider()`.
- Added rustls FIPS provider diagnostics to `fluxheim crypto` and
  `fluxheim-config-tester --crypto`.
- Added `examples/fips-rustls.toml`, `examples/iso19790-rustls.toml`, and
  `scripts/validate-fips-rustls.sh`.
- Added per-backend release evidence skips, `--skip-fips-openssl` and
  `--skip-fips-rustls`, for builders that collect OpenSSL and rustls/AWS-LC
  evidence in different environments.

## Compliance Boundary

This release does not claim that Fluxheim is FIPS certified or ISO/IEC 19790
validated. The rustls path is a source-build candidate that can make Fluxheim's
TLS listener use rustls' AWS-LC FIPS provider path and fail closed when
`[tls.fips] required = true` or `[tls.iso19790] required = true` is configured.

Operators still need the exact AWS-LC module certificate, Security Policy,
platform match, build procedure, deployment records, and non-TLS crypto
evidence before making regulated claims.

The rustls/AWS-LC FIPS candidate build requires the `aws-lc-fips-sys` toolchain,
including CMake, Go, and a C compiler.

## Example

```bash
cargo build --release --no-default-features --features profile-fips-rustls
scripts/validate-fips-rustls.sh check
```

Use `profile-iso19790-rustls` when the operator-facing evidence should use
ISO/IEC 19790 terminology. It maps to the same rustls/AWS-LC FIPS candidate
logic.

For release-mode evidence, use an AWS-LC-supported FIPS builder. Newer rolling
distribution compilers can fail inside `aws-lc-fips-sys`; the validation helper
now fails early for known newer GCC/Clang families unless
`FLUXHEIM_ALLOW_EXPERIMENTAL_AWS_LC_FIPS_TOOLCHAIN=1` is set for investigation
builds.
