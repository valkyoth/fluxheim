# FIPS-Capable Deployments

This document defines Fluxheim's FIPS direction. It is intentionally strict
about language: Fluxheim can provide FIPS-capable builds and fail-closed
configuration enforcement, but Fluxheim itself is not a validated
cryptographic module.

For a real FIPS-required deployment, the operator must use a cryptographic
module validated by the NIST/CCCS Cryptographic Module Validation Program
(CMVP), operate that module in its approved mode, and follow the module's
published Security Policy.

## Status

Current stable line: `1.3.3`.

Planned `1.3.4` direction: FIPS-capable TLS foundation and compliance
evidence plumbing. The target is not a broad "FIPS compliant" claim. The
target is to add enough backend-specific validation, diagnostics, and
documentation that the later FIPS-required profiles can fail closed instead of
silently accepting non-approved cryptography.

## Official References

Fluxheim's FIPS work should be tracked against these primary sources:

- [FIPS PUB 140-3, Security Requirements for Cryptographic Modules](https://csrc.nist.gov/pubs/fips/140-3/final)
- [FIPS 140-3 CMVP documents and Implementation Guidance](https://csrc.nist.gov/Projects/fips-140-3-transition-effort/fips-140-3-docs)
- [NIST SP 800-52 Rev. 2, Guidelines for TLS Implementations](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
- The selected module's CMVP entry and Security Policy, such as
  [AWS-LC Cryptographic Module certificate 5146](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5146)
- [OpenSSL FIPS provider documentation](https://docs.openssl.org/master/man7/OSSL_PROVIDER-FIPS/)
- [OpenSSL fipsinstall documentation](https://docs.openssl.org/master/man1/openssl-fipsinstall/)
- [rustls FIPS guidance](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html)
- [rustls CryptoProvider documentation](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)

These documents have different roles. FIPS 140-3 defines module security
requirements. The CMVP documentation and Implementation Guidance explain how
validation is interpreted and managed. NIST SP 800-52 Rev. 2 defines the TLS
policy shape for web servers and clients. The selected module Security Policy
is the binding operator manual for installing and invoking the validated
module.

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
```

`tls.fips.required` is present as a fail-closed planning guard. It validates
the obvious non-FIPS TLS choices and rejects startup unless the build has a
backend-specific proof path. The initial proof path is
`tls-openssl-fips` with `backend = "openssl"`, which checks that the OpenSSL
FIPS provider can be loaded and that a `fips=yes` property query can fetch an
approved cipher. The exact schema may grow when more backend proof fields are
implemented. The important rule is fail closed: a FIPS-required config must
not silently fall back to a non-FIPS provider or non-approved cipher.

## Backend Paths

### OpenSSL FIPS Provider

This is the practical first implementation path. Fluxheim `1.3.4` starts this
path with an opt-in feature and runtime provider probe; it still does not make
a blanket FIPS-compliance claim for the deployment.

Feature shape:

```toml
tls-openssl-fips = ["tls-openssl", "dep:openssl"]
```

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
- Exposes diagnostic output showing OpenSSL version and provider availability.
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
`tls-openssl-fips` must still refuse to run in FIPS-required mode if the
validated provider cannot be proven active.

Local provider sanity check:

```bash
openssl list -providers -provider fips -provider base
cargo run --no-default-features --features proxy,security,tls-openssl-fips --bin fluxheim -- crypto
```

On distributions that package OpenSSL providers separately, install only the
provider package needed for local testing. For example, openSUSE/SUSE systems
provide `libopenssl-3-fips-provider`. Full-system FIPS mode packages, boot
loader changes, and initramfs changes are deployment decisions, not required
for normal Fluxheim development.

Minimal FIPS-required runtime validation example:

```toml
[server]
listen = ["127.0.0.1:0"]

[tls]
enabled = true
backend = "openssl"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

[tls.fips]
required = true
```

Validate it with a `tls-openssl-fips` build:

```bash
cargo run --no-default-features --features proxy,security,tls-openssl-fips \
  --bin fluxheim-config-tester -- --config fips-example.toml --crypto
```

### rustls With AWS-LC FIPS

This is desirable, but it requires more Fluxheim refactoring than OpenSSL.

Current blocker:

- Fluxheim's rustls path currently uses ring-specific helpers in TLS setup.
  Real rustls FIPS support needs provider-aware helpers before a clean
  `tls-rustls-fips` feature can be implemented.

Planned feature shape:

```toml
tls-rustls-fips = ["tls", "pingora/rustls", "dep:rustls", "rustls/fips"]
```

Expected implementation work:

- Replace ring-specific rustls provider calls with provider-aware helper
  functions.
- Install or pass the rustls AWS-LC FIPS provider rather than the ring
  provider.
- Construct server and client configs from provider-supported suites filtered
  through the Fluxheim FIPS TLS policy.
- Verify `ServerConfig::fips()` and `ClientConfig::fips()` where rustls
  exposes those checks.
- Document build requirements for `aws-lc-fips-sys`, including CMake, Go, and
  a C compiler.
- Prove the AWS-LC module certificate and Security Policy boundary in release
  evidence.

Important caveat:

The rustls `fips` feature can make rustls use the AWS-LC FIPS path, but
Fluxheim still has to ensure all selected suites/groups and all non-TLS crypto
paths are compatible with FIPS-required mode.

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

### 1.3.4 - FIPS Foundation

Goal: prepare Fluxheim for real FIPS-required profiles without claiming
compliance.

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
- Initial `tls-openssl-fips` feature for OpenSSL 3 provider diagnostics and
  fail-closed `tls.fips.required` startup validation.

Exit criteria:

- Documentation does not overclaim.
- Operators can see which pieces remain blockers before they attempt a
  regulated deployment.
- The next implementation PR has a clear release-evidence path for OpenSSL and
  a separate rustls/AWS-LC path.

### 1.3.5 - OpenSSL FIPS Candidate Hardening

Goal: harden the first OpenSSL FIPS-capable runtime path using OpenSSL 3.x with
a validated FIPS provider.

Deliverables:

- Evidence-focused config-tester fixtures for provider failure, non-FIPS TLS
  settings, and backend mismatch.
- Optional operator-supplied OpenSSL config/module path diagnostics where the
  platform exposes them cleanly.
- Release evidence template listing OpenSSL version, provider config, module
  certificate, and Security Policy.
- Documentation for systemd, RPM, and container operation using an
  operator-installed validated OpenSSL provider.

Likely limitations:

- Managed ACME may be disabled in FIPS-required mode until ACME signing is
  routed through validated crypto or separately justified.
- Local cache encryption may be disabled in FIPS-required mode until migrated
  away from ring.

### 1.3.6 - rustls/AWS-LC FIPS Candidate

Goal: provider-aware rustls implementation using AWS-LC FIPS through rustls.

Deliverables:

- Refactor rustls code away from ring-specific helpers.
- `tls-rustls-fips` feature using rustls' FIPS/AWS-LC provider path.
- Runtime FIPS status checks on rustls server/client configs.
- Build documentation for AWS-LC FIPS dependencies.
- CI build coverage where feasible, or a documented manual evidence workflow
  if CI cannot reasonably host the validated environment.

Likely limitations:

- Exact module Security Policy and platform matching must be operator-provided
  unless Fluxheim publishes a dedicated validated-container recipe.

### 1.3.7 - Internal Crypto Closure

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

### 1.3.8 Or Later - Compliance Evidence Package

Goal: make regulated operators' audit work practical.

Deliverables:

- Release evidence bundle template.
- SBOM notes identifying the selected crypto module path.
- Runtime diagnostics capture template.
- Example systemd and container deployment checklists.
- Clear "not validated by Fluxheim" language unless a future sponsor funds a
  full CMVP validation for a Fluxheim-controlled module boundary.

## Operator Checklist

Before claiming a Fluxheim deployment uses FIPS-validated cryptography:

1. Select a validated cryptographic module from the CMVP database.
2. Download the exact Security Policy for that certificate.
3. Install the module exactly as the Security Policy requires.
4. Configure Fluxheim with a FIPS-capable backend that can prove approved mode.
5. Enable Fluxheim's future FIPS-required guard.
6. Run `fluxheim-config-tester` and the runtime crypto diagnostic command.
7. Verify TLS protocol/cipher/group behavior with an external scanner.
8. Confirm ACME, cache encryption, telemetry, and other crypto features are
   either FIPS-routed, externally evidenced, or disabled.
9. Archive the Fluxheim version, build command, Cargo.lock, SBOM, module
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
```

The `fluxheim crypto` provider check proves only that the process can load a
provider and fetch an approved cipher through `fips=yes`. It does not replace
the CMVP certificate, the module Security Policy, or the operating-system
evidence required by the deployment boundary.

## Documentation Rules

Use:

- "FIPS-capable"
- "FIPS-required mode"
- "validated cryptographic module"
- "approved mode"
- "operator evidence required"

Avoid:

- "FIPS compliant" without a named deployment boundary.
- "FIPS certified Fluxheim."
- "Compile this feature and you are compliant."
- Any statement that treats a Cargo feature as a substitute for CMVP validation
  and the module Security Policy.
