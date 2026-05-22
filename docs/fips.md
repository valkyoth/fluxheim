# FIPS / ISO-Capable Deployments

This document defines Fluxheim's FIPS 140-3 and ISO/IEC 19790 direction. It is
intentionally strict about language: Fluxheim can provide FIPS/ISO-capable
builds and fail-closed configuration enforcement, but Fluxheim itself is not a
validated cryptographic module.

For a real FIPS-required deployment, the operator must use a cryptographic
module validated by the NIST/CCCS Cryptographic Module Validation Program
(CMVP), operate that module in its approved mode, and follow the module's
published Security Policy.

## Status

Current stable line: `1.3.4`.

The `1.3.4` release line adds OpenSSL FIPS-capable TLS validation and
ISO/IEC 19790 terminology aliases for compliance evidence plumbing. The
`1.3.5` development line adds a rustls/AWS-LC FIPS candidate path. Neither is a
broad "FIPS compliant" or "ISO/IEC 19790 compliant" claim. The implemented
targets are backend proof paths, while BoringSSL, s2n, and non-TLS internal
crypto work remain explicitly staged.

## Official References

Fluxheim's FIPS work should be tracked against these primary sources:

- [FIPS PUB 140-3, Security Requirements for Cryptographic Modules](https://csrc.nist.gov/pubs/fips/140-3/final)
- [FIPS 140-3 Adopts ISO/IEC Standards](https://www.nist.gov/publications/fips-140-3-adopts-isoiec-standards)
- [FIPS 140-3 CMVP documents and Implementation Guidance](https://csrc.nist.gov/Projects/fips-140-3-transition-effort/fips-140-3-docs)
- [NIST SP 800-52 Rev. 2, Guidelines for TLS Implementations](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
- The selected module's CMVP entry and Security Policy, such as
  [AWS-LC Cryptographic Module certificate 5146](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5146)
- [OpenSSL FIPS provider documentation](https://docs.openssl.org/master/man7/OSSL_PROVIDER-FIPS/)
- [OpenSSL fipsinstall documentation](https://docs.openssl.org/master/man1/openssl-fipsinstall/)
- [rustls FIPS guidance](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html)
- [rustls CryptoProvider documentation](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)

These documents have different roles. FIPS 140-3 references ISO/IEC
19790:2012 requirements and ISO/IEC 24759 test methods for cryptographic
modules. The CMVP documentation and Implementation Guidance explain how
validation is interpreted and managed. NIST SP 800-52 Rev. 2 defines the TLS
policy shape for web servers and clients. The selected module Security Policy
is the binding operator manual for installing and invoking the validated module.

ISO/IEC 19790:2025 and ISO/IEC 24759:2025 are the current ISO editions for the
international cryptographic-module requirements and test-method structure. They
are useful for Fluxheim's ISO-facing roadmap and evidence terminology, but they
do not by themselves update an existing FIPS 140-3 CMVP certificate or replace
the NIST CMVP transition documents for a FIPS deployment. Until NIST or a
certification body states otherwise for a selected module, FIPS evidence should
continue to reference the certificate, Implementation Guidance, and Security
Policy that apply to that exact module.

For product-level evaluation planning, keep this document separate from the
[Common Criteria readiness roadmap](common-criteria-roadmap.md). ISO/IEC 15408
can help structure Fluxheim's product security evidence, but it does not replace
cryptographic-module validation.

## Compliance Boundary

FIPS validation attaches to a cryptographic module and its tested operating
environment, not to a web server merely because it links a library.

Fluxheim can be responsible for:

- Selecting a TLS backend compiled for a FIPS-capable module path.
- Restricting TLS protocol versions, cipher suites, groups, signatures, and
  certificate/key policy to NIST-approved settings.
- Triggering or verifying the selected backend's approved/FIPS mode where the
  backend exposes that check.
- Rejecting configs that request non-approved cryptography while
  FIPS-required mode is enabled.
- Showing evidence in diagnostics: selected TLS backend, selected provider,
  FIPS-required setting, runtime provider status, and relevant module/version
  data where available.
- Keeping Fluxheim-owned security-sensitive cryptography off non-validated
  fallback crates in FIPS-required builds.
- Exposing application-level status indicators such as the configured
  `tls.compliance_mode`, backend, provider checks, and fail-closed validation
  result.

Operators remain responsible for:

- Choosing a CMVP-validated module with an active certificate appropriate for
  their environment.
- Installing exactly the module build covered by the selected Security Policy.
- Running required installation steps such as OpenSSL `fipsinstall`, when that
  module requires it.
- Preserving the module integrity data, configuration files, and environment
  variables expected by the Security Policy.
- Ensuring the OS, container image, package source, CPU/platform, and runtime
  environment match the module validation boundary.
- Maintaining operational evidence for auditors.
- Mapping Fluxheim's application evidence to the selected cryptographic
  module's Security Policy, including the module boundary, approved services,
  non-approved services, roles, self-tests, operational environment, and SSP
  handling described by that Security Policy.

Fluxheim's status and diagnostic output are application indicators. They are not
a replacement for the validated module's own service indicators, self-test
status, or laboratory evidence.

Fluxheim release notes must therefore use wording such as:

- "FIPS-capable OpenSSL build path"
- "FIPS-required mode rejects non-approved TLS configuration"
- "Validated-module evidence is exposed in diagnostics"

Fluxheim release notes must not say:

- "Fluxheim is FIPS certified"
- "Fluxheim is FIPS compliant by enabling a Cargo feature"
- "Rustls/OpenSSL is FIPS compliant" without naming the exact validated
  module and required operating procedure

## TLS Policy Requirements

FIPS-required TLS profiles should follow NIST SP 800-52 Rev. 2 unless a newer
applicable NIST document supersedes it.

Baseline server policy:

- Support TLS 1.2 with FIPS-based cipher suites.
- Support TLS 1.3.
- Reject SSL 2.0, SSL 3.0, and TLS versions below the chosen FIPS profile.
- Prefer TLS 1.3 where clients support it.
- Allow TLS 1.2 only with NIST-approved algorithms.

Fluxheim-specific FIPS policy should therefore:

- Force `tls.min_protocol = "tls1.2"` or stricter.
- Reject TLS 1.0 and TLS 1.1 in FIPS-required mode.
- Reject `curve_preferences` that include non-NIST groups such as `X25519`.
- Reject post-quantum/hybrid groups such as `X25519MLKEM768` until the chosen
  validated module and NIST guidance clearly cover them for the deployment.
- Reject TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` in FIPS-required mode unless
  the selected module Security Policy and NIST guidance explicitly support it
  for that use.
- Prefer AES-GCM/SHA-2 TLS 1.3 suites and NIST elliptic curves such as P-256,
  P-384, and P-521 where the backend supports them.
- Reject configured TLS cipher-suite names that Fluxheim cannot map to a
  backend-approved implementation.

Example future FIPS-required TLS profile:

```toml
[tls]
enabled = true
backend = "openssl"
profile = "fips"
min_protocol = "tls1.2"
alpn = "http1-and-http2"
curve_preferences = ["CurveP256", "CurveP384"]

[tls.fips]
required = true

# European/international terminology alias for the same enforcement path:
# [tls.iso19790]
# required = true
```

`tls.fips.required` is present as a fail-closed OpenSSL guard.
`tls.iso19790.required` is an ISO/IEC 19790 terminology alias for the same
validated-provider enforcement path. They validate the obvious non-approved TLS
choices and reject startup unless the build has a backend-specific proof path.
The first proof path is `tls-openssl-fips` or the `tls-openssl-iso19790`
alias with `backend = "openssl"`, which checks that the OpenSSL FIPS provider
can be loaded and that a `fips=yes` property query can fetch an approved
cipher, enables OpenSSL default FIPS properties for the process, and verifies
that the default fetch path rejects a non-FIPS cipher. The exact schema may
grow when more backend proof fields are implemented. The important rule is fail
closed: a FIPS/ISO-required config must not silently fall back to a
non-validated provider or non-approved cipher.

## Backend Paths

### OpenSSL FIPS Provider

This is the practical first implementation path. Fluxheim `1.3.4` completes
the OpenSSL FIPS-capable TLS proof path with an opt-in feature, runtime
provider probe, and default-property enforcement; it still does not make a
blanket FIPS-compliance claim for the deployment.

Feature shape:

```toml
tls-openssl-fips = [
  "tls-openssl",
  "dep:fluxheim-openssl-fips-support",
  "dep:openssl",
]
```

`profile-fips-openssl` and `profile-iso19790-openssl` are intentionally small
proof profiles. They are useful for local provider validation and release
evidence, but they are not the only valid way to build a FIPS/ISO-capable
Fluxheim binary.

For custom deployments, combine `tls-openssl-fips` with the raw modules you
need. Do not combine it with a broad profile alias that already enables
`tls-rustls`, because Cargo features are additive and Fluxheim supports only one
Pingora TLS backend per binary.

Examples:

```bash
# FIPS/ISO-capable static web server
cargo build --release --locked --no-default-features \
  --features proxy,web,security,tls-openssl-fips \
  --bin fluxheim

# FIPS/ISO-capable cache edge
cargo build --release --locked --no-default-features \
  --features proxy,cache,security,tls-openssl-fips \
  --bin fluxheim

# FIPS/ISO-capable PHP-FPM web server
cargo build --release --locked --no-default-features \
  --features php-fpm,security,tls-openssl-fips \
  --bin fluxheim
```

These examples make Fluxheim's TLS listener use the OpenSSL FIPS proof path.
They do not prove that every cryptographic operation in the full deployment is
inside a validated module. In particular, PHP applications, managed ACME
account operations, local cache encryption, outbound OTLP TLS, and any
application-level token/signature logic need their own evidence, validated
backend routing, or must be disabled before claiming a strict FIPS-required
deployment boundary.

The recommended strict-boundary pattern is to use local/static certificate
files generated and renewed by an approved external process. Managed ACME can
still be compiled into a FIPS-capable TLS binary by adding `acme-client` and
building `fluxheim-acme`, but that adds a separate cryptographic workflow that
requires its own evidence. Fluxheim must not imply that ACME account keys, ACME
JWS signing, CA communication, or certificate issuance policy are covered by the
OpenSSL TLS provider proof merely because the listener is in FIPS-required
mode.

Current Fluxheim enforcement:

- Adds a direct `openssl` crate dependency only for OpenSSL FIPS diagnostics
  and provider/property checks.
- Uses Fluxheim's local `pingora-openssl` patch to avoid forced
  `openssl/vendored`, so builds can link against the operator-selected OpenSSL
  installation.
- Requires OpenSSL 3.x behavior for the FIPS property query path.
- Loads the `fips` provider and keeps it loaded for the process lifetime.
- Attempts to load the `base` provider for normal encoder/decoder support.
- Fetches `AES-256-GCM` with `fips=yes` to prove the property query can resolve
  an approved cipher.
- Enables OpenSSL default FIPS properties for the process-default library
  context through a small local support crate.
- Verifies `EVP_default_properties_is_fips_enabled`, proves `AES-256-GCM` can
  be fetched through the default property path, and proves `CHACHA20-POLY1305`
  is rejected through that path.
- Exposes diagnostic output showing OpenSSL version, provider availability, and
  default FIPS property status.
- Rejects FIPS-required startup if the backend is not OpenSSL or if the
  provider/property check fails.

Operator responsibilities:

- Install an OpenSSL build and FIPS provider covered by a CMVP certificate.
- Follow that exact module Security Policy.
- Generate and verify the module config with `openssl fipsinstall` when the
  selected module requires it.
- Provide the OpenSSL config/module paths using the mechanism required by the
  module and operating system, commonly `OPENSSL_CONF`, `OPENSSL_MODULES`, or
  distribution-specific FIPS mode tooling.

Important caveat:

Linking to OpenSSL is not enough. A Fluxheim binary built with
`tls-openssl-fips` refuses to run in FIPS-required mode if the validated
provider and OpenSSL default FIPS property path cannot be proven active.

Fluxheim `1.3.4` diagnostics load the `fips` provider and resolve
`AES-256-GCM` through an explicit `fips=yes` property query without enabling
OpenSSL global FIPS default properties. FIPS-required runtime startup then
enables OpenSSL default FIPS properties for the process-default library
context, verifies `EVP_default_properties_is_fips_enabled`, checks that
`AES-256-GCM` can be fetched through the default property path, and checks that
`CHACHA20-POLY1305` is rejected through that same default path. The raw OpenSSL
default-property calls are contained in a small local support crate so the main
Fluxheim crate can keep `#![forbid(unsafe_code)]`.

Provider handles are intentionally kept loaded for the process lifetime.
Moving between FIPS-required and non-FIPS TLS operation is a process-restart
boundary, not a hot-reload boundary.

Operators still need to install and configure OpenSSL according to the chosen
module Security Policy, including provider installation and integrity setup
such as `openssl fipsinstall` where that policy requires it. Fluxheim verifies
the process behavior it can observe; it does not replace CMVP certificate,
platform, or operational evidence.

Local provider sanity check:

```bash
scripts/validate-fips-openssl.sh check
```

Fluxheim does not hardcode a provider directory. It lets OpenSSL use the
platform's normal provider search rules, including `OPENSSL_CONF`,
`OPENSSL_MODULES`, distro crypto policies, and compiled-in defaults. The
`fluxheim crypto` output prints the OpenSSL environment variables visible to
the process so operators can capture how provider discovery was configured.
On distributions that package OpenSSL providers separately, install only the
provider package needed for local testing. Full-system FIPS mode packages,
boot loader changes, and initramfs changes are deployment decisions, not
required for normal Fluxheim development.

The repository includes `examples/fips-openssl.toml` and
`examples/iso19790-openssl.toml` as minimal validation fixtures. Validate them
with a `profile-fips-openssl` or `profile-iso19790-openssl` build:

```bash
scripts/validate-fips-openssl.sh check
```

### rustls With AWS-LC FIPS

The `1.3.5` development line includes a rustls/AWS-LC FIPS candidate. It is a
compile-time alternative to the default rustls/ring backend:

```toml
tls-rustls-fips = ["tls-rustls-backend", "rustls/fips"]
tls-rustls-iso19790 = ["tls-rustls-fips"]
profile-fips-rustls = ["proxy", "security", "tls-rustls-fips"]
profile-iso19790-rustls = ["profile-fips-rustls", "tls-rustls-iso19790"]
```

Build and validation examples:

```bash
cargo build --no-default-features --features profile-fips-rustls
cargo build --no-default-features --features profile-iso19790-rustls
scripts/validate-fips-rustls.sh check
```

`tls-rustls-fips` enables rustls' `fips` feature, which routes rustls through
AWS-LC FIPS support and pulls in `aws-lc-fips-sys`. Building it requires the
toolchain documented by that crate, including CMake, Go, and a C compiler.
Fluxheim installs or passes `rustls::crypto::default_fips_provider()` instead
of the ring provider, maps configured suites/groups through the AWS-LC rustls
provider, and rejects startup when a FIPS/ISO-required rustls listener does not
report `ServerConfig::fips()`.

Release-mode rustls/AWS-LC FIPS evidence should be generated on an
AWS-LC-supported FIPS builder, not an arbitrary rolling distribution compiler.
Upstream `aws-lc-fips-sys` has known build failures with newer compiler
families such as GCC >= 14 and newer Clang releases. Fluxheim's validation
script therefore fails early in `release` mode for those toolchains unless
`FLUXHEIM_ALLOW_EXPERIMENTAL_AWS_LC_FIPS_TOOLCHAIN=1` is set. That override is
for investigation only; compliance evidence still has to match the selected
module Security Policy.

A practical smoke path that avoids rolling-host compiler drift is to run the
release helper in `docker.io/library/rust:1-bookworm` after installing CMake,
Go, Clang/libclang, pkg-config, Perl, and CA certificates. This has been
verified to build both `profile-fips-rustls` and `profile-iso19790-rustls` in
release mode and to report `rustls_fips_provider: available
(provider_fips=true)`.

The repository includes `examples/fips-rustls.toml` and
`examples/iso19790-rustls.toml` for config-tester validation. Those fixtures
intentionally use local/static certificate assumptions and do not prove ACME,
application, cache, or telemetry cryptography.

Important caveat:

The rustls `fips` feature can make rustls use the AWS-LC FIPS path, but
regulated operators still have to match the AWS-LC module certificate, Security
Policy, platform, and build procedure. Fluxheim's check proves that its rustls
TLS listener is built from a provider and config that report FIPS mode; it does
not prove the whole deployment or every non-TLS crypto path.

### BoringSSL And s2n

These remain research tracks.

`tls-boringssl-fips` is not planned until Fluxheim can prove it is linked to a
validated BoringCrypto module stream and can expose the module/version/runtime
status. Normal BoringSSL must not be described as FIPS validated.

`tls-s2n-fips` is not planned until the s2n/Pingora integration can prove s2n
was built with a FIPS-capable AWS-LC path, can expose runtime FIPS status, and
can restrict configured s2n security policies to approved cryptography.

## Internal Crypto Inventory

TLS is the visible part, but FIPS-required mode also has to account for
security-sensitive cryptography outside TLS.

Current Fluxheim areas to inventory before a FIPS-required release:

- TLS key exchange, signatures, symmetric encryption, and secure random.
- ACME account/order/challenge signing and ACME TLS-ALPN certificate handling.
- ACME EAB HMAC handling.
- Admin bearer-token comparison and any token/MAC generation.
- Request IDs and temporary object names where unpredictability is
  security-sensitive.
- Local disk-cache encryption.
- OpenBao Transit cache encryption, including whether the external OpenBao
  deployment uses a validated module.
- OTLP HTTPS client TLS and any future outbound HTTPS clients.
- Future CSRF/session/JWT/plugin signing features.
- Test/dev certificate generation.

FIPS-required mode should classify each area as one of:

- Routed through selected validated module.
- Externally delegated to a validated service with operator evidence.
- Non-security-sensitive and documented as such.
- Disabled/rejected in FIPS-required builds.

For ISO/IEC 19790-facing evidence, the same inventory should also identify:

- The Fluxheim feature and configuration option that enables or disables the
  service.
- Whether the service is security-relevant or non-security-relevant to the
  approved operation.
- Which SSPs, if any, are generated, imported, stored, output, or zeroized by
  Fluxheim itself.
- Whether the approved-mode indicator comes from Fluxheim, the validated crypto
  module, or an external service.
- The exact error state and operator action when a provider check, self-test,
  or configuration guard fails.

Known current blockers:

- `instant-acme` and `rcgen` currently use ring-backed paths in Fluxheim's ACME
  feature set. A FIPS-required profile may need to disable managed ACME at
  first or replace the affected signing/certificate-generation paths.
- Local cache encryption currently uses ring AES-GCM. A FIPS-required profile
  should initially reject local cache encryption unless it is rerouted through
  the selected validated backend. OpenBao Transit may be acceptable only when
  the operator can provide validated-module evidence for OpenBao's crypto
  boundary.
- OTLP export currently uses a rustls-backed HTTP client. FIPS-required
  outbound TLS needs provider alignment or a local-only collector exception
  with clear documentation.

## Release Roadmap After 1.3.4

### 1.3.4 - OpenSSL FIPS-Capable TLS

Goal: complete the OpenSSL FIPS-capable TLS path without claiming that
Fluxheim itself is a validated cryptographic module.

Deliverables:

- This standalone FIPS documentation.
- FIPS terminology guardrails in README, roadmap, and release notes.
- A tracked crypto inventory covering TLS, ACME, admin, cache encryption,
  random IDs, and outbound telemetry.
- A FIPS TLS policy validator design: protocols, cipher suites, curves,
  signature algorithms, and backend support.
- A diagnostics design for `fluxheim --version --crypto` or an equivalent
  config-tester/runtime command.
- Initial `fluxheim crypto` and `fluxheim-config-tester --crypto` output that
  reports compiled TLS backends and OpenSSL FIPS provider availability.
- `tls-openssl-fips` feature plus `tls-openssl-iso19790` terminology alias for
  OpenSSL 3 provider diagnostics, fail-closed `tls.fips.required` /
  `tls.iso19790.required` startup validation, default FIPS property enablement,
  and observable default-property verification.
- `profile-fips-openssl` and `profile-iso19790-openssl` as narrow
  proxy/security/OpenSSL feature aliases for release and local validation.
- Evidence-focused config-tester fixtures for provider failure, non-FIPS TLS
  settings, and backend mismatch.
- Release evidence template listing OpenSSL version, provider config, module
  certificate, and Security Policy.
- Documentation for systemd, RPM, and container operation using an
  operator-installed validated OpenSSL provider.

Exit criteria:

- Documentation does not overclaim.
- OpenSSL FIPS-required startup fails if provider loading, explicit `fips=yes`
  fetch, default FIPS property enablement, or default-property verification
  fails.
- Operators can see which non-OpenSSL pieces remain blockers before they
  attempt a regulated deployment.
- The next implementation PR has a separate rustls/AWS-LC path.

Likely limitations:

- Managed ACME may be disabled in FIPS-required mode until ACME signing is
  routed through validated crypto or separately justified.
- Local cache encryption may be disabled in FIPS-required mode until migrated
  away from ring.

### 1.3.5 - rustls/AWS-LC FIPS Candidate

Goal: provider-aware rustls implementation using AWS-LC FIPS through rustls.

Deliverables:

- Refactor rustls code away from ring-specific helpers.
- `tls-rustls-fips` feature using rustls' FIPS/AWS-LC provider path.
- Runtime FIPS status checks on rustls provider and server configs.
- `profile-fips-rustls` and `profile-iso19790-rustls` aliases.
- `examples/fips-rustls.toml`, `examples/iso19790-rustls.toml`, and
  `scripts/validate-fips-rustls.sh`.
- Build documentation for AWS-LC FIPS dependencies, including Go.
- CI build coverage where feasible, or a documented manual evidence workflow
  if CI cannot reasonably host the validated environment.
- Release-mode evidence guard for unsupported/newer compiler families, with an
  explicit override only for investigation builds.

Likely limitations:

- Exact module Security Policy and platform matching must be operator-provided
  unless Fluxheim publishes a dedicated validated-container recipe.

### 1.3.6 - Internal Crypto Closure

Goal: remove or gate non-validated crypto paths from FIPS-required builds.

Deliverables:

- ACME FIPS decision: reroute, disable, or document external issuance workflow.
- Cache encryption FIPS decision: OpenSSL/AWS-LC backend, OpenBao-only
  evidence path, or disabled.
- Outbound telemetry TLS FIPS decision.
- Request ID/temp-name/randomness classification and backend routing where
  needed.
- Test coverage proving `fips.required = true` fails closed for incompatible
  feature combinations.

### 1.3.7 Or Later - Compliance Evidence Package

Goal: make regulated operators' audit work practical.

Deliverables:

- Release evidence bundle template.
- SBOM notes identifying the selected crypto module path.
- Runtime diagnostics capture template.
- Example systemd and container deployment checklists.
- Clear "not validated by Fluxheim" language unless a future sponsor funds a
  full CMVP validation for a Fluxheim-controlled module boundary.
- ISO/IEC 19790 / 24759 evidence crosswalk for operators, covering module
  boundary, module type, operational environment, roles, approved and
  non-approved services, status indicators, SSP management, self-tests,
  lifecycle evidence, and mitigation-of-other-attacks claims.

## Operator Checklist

Before claiming a Fluxheim deployment uses FIPS-validated cryptography:

1. Select a validated cryptographic module from the CMVP database.
2. Download the exact Security Policy for that certificate.
3. Install the module exactly as the Security Policy requires.
4. Configure Fluxheim with a FIPS-capable backend that can prove approved mode.
5. Enable Fluxheim's FIPS-required guard.
6. Run `fluxheim-config-tester` and the runtime crypto diagnostic command.
7. Use a Unix target. Fluxheim's storage trust checks rely on Unix ownership,
   mode bits, `O_NOFOLLOW`-style path handling, and Unix-domain control
   sockets; non-Unix ACL and descriptor-rights checks are not implemented.
8. Verify TLS protocol/cipher/group behavior with an external scanner.
9. Confirm ACME, cache encryption, telemetry, and other crypto features are
   either FIPS-routed, externally evidenced, or disabled.
10. Archive the Fluxheim version, build command, Cargo.lock, SBOM, module
   certificate, Security Policy, provider config, and runtime diagnostic output.

## Evidence Capture Template

For each FIPS-capable deployment or release candidate, capture:

```text
Fluxheim version:
Fluxheim git commit:
Fluxheim build command:
Cargo.lock checksum:
SBOM checksums:

TLS backend:
FIPS-required config path:
fluxheim crypto output:
fluxheim-config-tester --crypto output:

OpenSSL version:
openssl list -providers -provider fips -provider base output:
OPENSSL_CONF:
OPENSSL_MODULES:
Provider config checksum:

CMVP certificate number:
Module Security Policy title/version:
Operating system and OpenSSL package versions:
TLS scanner output:
Non-TLS crypto decision log:

ISO/IEC evidence vocabulary used:
Cryptographic module boundary:
Module type:
Operational environment:
Approved services used:
Non-approved services disabled or separated:
Roles and authentication model:
Status/service indicators:
SSP inventory and zeroization notes:
Self-test evidence and failure behavior:
Lifecycle/release evidence location:
Mitigation-of-other-attacks claims:
```

The `fluxheim crypto` provider check proves only that the process can load a
provider and fetch an approved cipher through `fips=yes`. It does not replace
the CMVP certificate, the module Security Policy, or the operating-system
evidence required by the deployment boundary.

## Documentation Rules

Use:

- "FIPS-capable"
- "ISO/IEC 19790-capable"
- "FIPS-required mode"
- "ISO/IEC 19790-required mode"
- "validated cryptographic module"
- "approved mode"
- "operator evidence required"
- "application-level indicator" when referring to Fluxheim's own diagnostics

Avoid:

- "FIPS compliant" without a named deployment boundary.
- "ISO/IEC 19790 compliant" without a named deployment boundary.
- "FIPS certified Fluxheim."
- "Compile this feature and you are compliant."
- Any statement that treats a Cargo feature as a substitute for CMVP validation
  and the module Security Policy.
- Any statement that treats Fluxheim's status endpoint as the validated
  module's laboratory service indicator.
