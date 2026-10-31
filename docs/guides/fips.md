# FIPS / ISO-Capable Deployments

Fluxheim supports FIPS-capable cryptographic providers and required-mode policy
checks. **Fluxheim is not a validated cryptographic module.** A successful build,
diagnostic or TLS handshake does not certify a server or deployment.

For ordinary HTTPS, start with [TLS](tls.md). Required mode deliberately rejects
some otherwise supported features.

## Understand The Boundary

| Check | What it establishes | What it does not establish |
| --- | --- | --- |
| Capable build | Intended OpenSSL or rustls/AWS-LC integration is compiled | Module availability or an approved deployment |
| Required-mode validation/startup | Supported configuration and runtime-provider checks pass | Qualification of every application, external service or OS operation |
| Deployment evidence | Exact module, platform, approved mode and procedures are recorded | Automatic certification from a completed checklist |

Select the module's certificate and Security Policy first, then build and operate
within their requirements. Check its current certificate status and supported
platform. A module name or algorithm list is insufficient. See the
[CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
and [FIPS PUB 140-3](https://csrc.nist.gov/pubs/fips/140-3/final).

ISO/IEC 19790 names below are terminology aliases for the same Fluxheim enforcement
path, not a second certified implementation. Product-level
[Common Criteria planning](../roadmap/common-criteria-roadmap.md) is separate.

## Choose One Backend

| Cargo profile | Implementation | Prerequisite |
| --- | --- | --- |
| `profile-fips-openssl` | OpenSSL 3 FIPS provider | Operator-selected system OpenSSL, provider module/configuration and Security Policy |
| `profile-fips-rustls` | rustls with AWS-LC FIPS | Supported AWS-LC module build toolchain and operating environment |
| `profile-iso19790-openssl` | Same OpenSSL path | Same prerequisites |
| `profile-iso19790-rustls` | Same AWS-LC path | Same prerequisites |

These are custom Cargo profiles, not additional standard archives or ordinary
PHP/Wolfi image variants. The FIPS profiles include proxying and security, not
every optional module. Ordinary rustls/ring or OpenSSL builds are not substitutes.
BoringSSL and s2n are not supported alternatives.

Build **one** backend using the repository's pinned Rust toolchain:

```bash
cargo build --locked --release --no-default-features \
  --features profile-fips-openssl \
  --bin fluxheim --bin fluxheim-config-tester
```

For AWS-LC substitute `profile-fips-rustls`. Its native build needs CMake, Go and
a supported C/C++ toolchain. Follow the module's requirements; successful
compilation on an arbitrary compiler is not qualification.

Additional functionality needs a reviewed custom selection. For example:

```bash
cargo build --locked --release --no-default-features \
  --features proxy,web,security,tls-openssl-fips \
  --bin fluxheim --bin fluxheim-config-tester
```

Do not combine an ordinary rustls-selecting profile with OpenSSL, or use
`--all-features`. Read the [feature reference](../reference/features.md) and
[installation guide](installation.md). The shell preflight has a recorded
nested-alias limitation; its success does not replace the locked
Cargo build.

## All Required-Mode Options

These four global booleans default to `false`. They are not per-vhost options.

| Field | Effect |
| --- | --- |
| `tls.fips.required` | Require the capable backend, allowed TLS policy and internal-crypto restrictions |
| `tls.iso19790.required` | Require the same enforcement under ISO terminology |
| `tls.fips.require_disk_cache_encryption` | When either required flag is true, reject configured disk caches without encryption |
| `tls.iso19790.require_disk_cache_encryption` | Same disk-cache requirement; either encryption flag activates it |

Either required flag enables enforcement; both may be set. An encryption flag
alone does **not** enable required mode, caching or encryption, or select a key.
Disabling disk cache avoids that cache requirement, not the other checks.

```toml
[tls.fips]
required = true
require_disk_cache_encryption = true
```

For ISO terminology replace that table with:

```toml
[tls.iso19790]
required = true
require_disk_cache_encryption = true
```

`tls.compliance_mode()` is an internal derived value, **not a TOML setting**.
There is no `profile = "fips"`: TLS profiles are `modern`, `intermediate` and
`compat`. Required-mode policy is also validated when `tls.enabled = false`.

### Choose An Explicit TLS Policy

Normal profile defaults include X25519 and ChaCha20. Required mode rejects them;
it does not silently substitute different defaults. Set both lists explicitly:

```toml
[tls]
enabled = true
backend = "openssl"
profile = "modern"
min_protocol = "tls1.3"
alpn = "http1"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

[tls.fips]
required = true
```

Use `backend = "rustls"` with the AWS-LC build. The capable backend must match
the configuration. The permitted groups are `CurveP256` and `CurveP384`;
X25519 and X25519MLKEM768 are rejected. P-521 is not selectable.

For TLS 1.2 clients use `intermediate`, `min_protocol = "tls1.2"` and the
needed AES-GCM suites. Replace the cipher list inside `[tls]` with:

```toml
cipher_suites = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
]
```

Select suites appropriate to your certificates and module policy. TLS 1.2 suites
are rejected when the minimum is TLS 1.3. `compat` does not enable TLS 1.0/1.1
or exempt an algorithm from required-mode checks.

Required mutual TLS also needs a CRL bundle:

```toml
[tls.client_auth]
mode = "required"
ca_path = "certs/client-ca.pem"
crl_path = "certs/client-crls.pem"
```

See [TLS](tls.md) for certificate, client-authentication and reload behavior.
Path validation does not prove external policy compliance of your CA, key
algorithm, revocation freshness or certificate lifecycle.

## Complete HTTPS Proxy Example

[examples/fips/proxy.toml](../../examples/fips/proxy.toml) listens only on
`127.0.0.1:8443`, serves `fips.test` and verifies a TLS origin on
`127.0.0.1:9444`. Supply these operator-provided files next to it:

```text
proxy.toml
certs/
  server.pem       # chain for fips.test
  server-key.pem   # corresponding private key
  origin-ca.pem    # CA for the origin identity localhost
```

Use owner-controlled directories and private key permissions (for example,
`0700` directories/`0600` key on Unix), or trusted Windows ACLs. Never deploy
repository test keys. Start the origin separately; this recipe does not issue
certificates or install an application.

Validate and start as the actual service identity:

```bash
./target/release/fluxheim-config-tester \
  --config /srv/fluxheim-fips/proxy.toml --profile fips-openssl --crypto
./target/release/fluxheim --config /srv/fluxheim-fips/proxy.toml --validate-config
./target/release/fluxheim --config /srv/fluxheim-fips/proxy.toml
```

For AWS-LC change the example backend to `rustls` and tester profile to
`fips-rustls`, with the corresponding binaries. Test using the issuing CA:

```bash
curl --resolve fips.test:8443:127.0.0.1 \
  --cacert /path/to/server-ca.pem https://fips.test:8443/
```

Do not use `--insecure`. Change listening addresses and firewall rules
deliberately for public service. The example enables no plaintext listener,
managed ACME, disk cache, admin listener or exporter.

Downstream `[tls]` policy is not an upstream cipher/version interface.
Keep origin chain and hostname verification enabled and qualify the actual
upstream path; see [upstream TLS](upstream-tls.md).

The shorter [OpenSSL](../../examples/fips-openssl.toml),
[AWS-LC](../../examples/fips-rustls.toml),
[ISO OpenSSL](../../examples/iso19790-openssl.toml) and
[ISO AWS-LC](../../examples/iso19790-rustls.toml) examples are diagnostic fixtures,
not complete sites. Their `--no-runtime-paths` command intentionally omits
deployment-path checks and is not production acceptance.

## Runtime Provider Checks

**OpenSSL:** the diagnostic probe loads the FIPS provider and fetches AES-GCM
with `fips=yes`. It reports availability and current default-property state;
availability alone is not activation. Required runtime validation enables default
FIPS properties, checks them, verifies approved/default AES-GCM fetching and
checks that ordinary ChaCha20 fetching is unavailable through those defaults.
Provider/enforcement failure stops startup. Fluxheim neither installs the provider
nor falls back to ordinary crypto to make required-mode startup succeed.

**rustls/AWS-LC:** the capable build selects `default_fips_provider()`. The root
runtime rejects an already-installed non-FIPS process provider, checks the
provider's indicator and checks the resulting downstream server config.
These indicators are not certificate or platform attestation.

These integrations are process-level, not per-request/vhost switches. This
contract describes the validated Fluxheim executable startup, not arbitrary
embedders calling lower-level APIs without that startup.

```bash
./target/release/fluxheim --config /srv/fluxheim-fips/proxy.toml crypto
```

Record the output alongside startup validation and live traffic. A probe from a
different binary, container or service environment is not proof for your process.
The standalone `crypto` command can print an unavailable provider and still exit
successfully: it is a report, not an acceptance gate. Use full runtime validation
without `--no-runtime-paths` and actual startup for fail-closed provider checks.

The local `scripts/validate-fips-rustls.sh release` helper may select an installed
GCC 13/12/11 pair unless `CC` is supplied. Its
`FLUXHEIM_ALLOW_EXPERIMENTAL_AWS_LC_FIPS_TOOLCHAIN=1` override is for investigation,
not approved deployment evidence. Likewise, an OpenSSL helper run with
`FLUXHEIM_REQUIRE_FIPS_PROVIDER=0` proves only stub/configuration checks, not a
working required-mode provider. Neither override changes server enforcement.

## Other Features In Required Mode

| Functionality | Implemented boundary / operator action |
| --- | --- |
| Managed ACME | Rejected: account/JWS/EAB, HTTPS and challenge crypto are not all provider-routed. Use static certificates and an independently evidenced renewal process |
| HTTP-01 challenge proxy | Not itself certificate signing; the external issuance boundary still needs evidence |
| Admin bearer authentication | Root integration uses provider-routed HMAC-SHA-256; provider failure has no ordinary-crypto fallback. Transport and secret-file rules still apply |
| Snapshot integrity | Root admin/CLI integrations supply the selected SHA-256/HMAC provider; standalone library defaults are not deployment evidence |
| Load-balancer MAC operations | Root runtime installs its provider callback; qualify actual enabled persistence/management operations, not just TLS |
| Unencrypted disk cache | Allowed with a warning unless either disk-encryption requirement flag is active |
| Local cache encryption | Rejected because it uses ring AES-GCM |
| OpenBao Transit | Accepted only over numeric loopback HTTP; evidence the external module and service separately |
| OTLP metrics/traces | Enabled exporters allow numeric loopback HTTP only; remote, HTTPS and localhost endpoints are rejected |
| Auth-request / mirroring | Enabled hooks allow numeric loopback HTTP only, including vhost/route scopes |
| PHP, applications and plugins | Their cryptography is not qualified by Fluxheim's TLS checks |
| Request/trace IDs | Diagnostic metadata, not authentication credentials or keys |
| OS randomness / temporary names | Part of the environment review; names do not replace filesystem permissions |

This is not exhaustive attestation of every optional path. Inventory each enabled
feature, security purpose, sensitive parameter, provider, failure mode and
external service in the [evidence template](../evidence/compliance-evidence-template.md).
Test/development certificate generation is not production module evidence.

### Disk Cache

For a custom build containing `cache`, add this to a valid required-mode proxy
configuration. Provision the credential/private directory using
[cache encryption](cache-encryption.md):

```toml
[cache]
enabled = true

[cache.disk]
enabled = true
path = "cache"

[cache.disk.encryption]
enabled = true
provider = "openbao-transit"

[cache.disk.encryption.openbao]
address = "http://127.0.0.1:8200"
mount = "transit"
key_name = "fluxheim-cache"
token_credential = "openbao-token"
```

This delegates encryption; it does not qualify an arbitrary OpenBao instance.
IPv6 `http://[::1]:8200` is also supported. `localhost`, remote and HTTPS
addresses are rejected in required mode. An encrypted filesystem does not satisfy
Fluxheim's explicit encryption-flag check: disable disk cache or configure the
supported encryption provider when that flag is active.

### Local Collector

For a custom build containing the relevant metrics/OTLP features:

```toml
[metrics]
enabled = true

[metrics.otlp]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/metrics"

[tracing]
enabled = true

[tracing.otlp]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"
```

Omit sections for capabilities not compiled into your binary. The collector must
share the process network namespace: container loopback is not another
container's address. Protect it from unrelated local processes and evidence its
onward export independently. A loopback exception is not encrypted transport.

OTLP bearer authentication always requires HTTPS, which required mode rejects.
**There is no supported required-mode OTLP bearer-token combination.** Do not
disable certificate validation or embed credentials in an endpoint as a workaround.
Use a protected local collector or leave export off. Separate Prometheus
scrape-token rules remain unchanged.

For auth-request/mirroring use the [authorization](external-authorization.md)
and [mirroring](traffic-mirroring.md) guides with
endpoints such as `http://127.0.0.1:4180/auth` and
`http://127.0.0.1:9000/shadow`. The service and its policy remain your boundary.

## Live Proof And Evidence

```bash
scripts/smoke_fips_backend_images.sh all
```

Use `openssl` or `rustls` for one backend. These build/run local proof images,
not published runtime variants. The
[OpenSSL recipe](../../containers/fips/Containerfile.openssl) uses pinned UBI
and its packaged provider; the
[AWS-LC recipe](../../containers/fips/Containerfile.rustls) records its native
toolchain. Both record compiler/package/Cargo/binary-hash evidence, reject
forbidden TLS policy and run the built binary unprivileged. The smoke verifies
downstream TLS and a certificate/hostname-verified HTTPS origin, then checks the
proxied response.

The manual `FIPS Backend Evidence` workflow performs the builds. Lightweight CI
validation of the plan is not that test. Enable the release-gate image checks
with `FLUXHEIM_GATE_FIPS_IMAGES=1`. An existing image's smoke proves only its
recorded binary identity, not later unbuilt source edits.

These Linux proofs do not qualify native Windows/macOS providers. Windows
trusted-path/ACL enforcement is a different property from module qualification.
Run native provider, certificate, ACL, TLS, reload and failure tests before
expanding platform claims. Container success does not establish host approved mode.

Record at least:

1. Source commit, signed release reference, lockfile, features, toolchain, binary
   hash, image digest and OS/kernel.
2. Exact module/version, certificate status, Security Policy, supported platform,
   installation/configuration and approved-mode evidence.
3. Actual service-user startup/probes and negative tests for missing provider,
   wrong backend, forbidden algorithms and inaccessible secrets.
4. Real verified downstream/upstream TLS; client-auth/revocation, certificate
   reload, admin/snapshot operations and failure behavior where enabled.
5. Every external crypto boundary (renewal, OpenBao, collector, application),
   its owner, evidence and accepted limitations.
6. Key/credential creation, storage, access, rotation, backup/destruction;
   restart/recovery procedures and patch policy.

Use the [evidence template](../evidence/compliance-evidence-template.md) and
[release runbook](release-runbook.md), not a blanket certification claim.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Unknown FIPS TLS profile | Use modern/intermediate with explicit AES/P256/P384 and a separate required flag |
| Curve/cipher rejection | Omitted/empty lists select normal defaults, not required-mode defaults |
| Backend rejection | Match the capable feature and configuration; ordinary archives are not FIPS builds |
| OpenSSL provider unavailable | Check exact provider install/configuration and service environment; do not suppress required-mode failure |
| AWS-LC native build fails | Check supported compiler/CMake/Go; experimental compilation is not qualification |
| Managed ACME or HTTPS exporter rejected | Use the documented external boundary or disable that feature |
| Encrypted host disk rejected | The flag checks configured Fluxheim cache encryption, not storage attestation |
| Diagnostic passes but service fails | Validate complete site paths as the service user without --no-runtime-paths, then test actual traffic |

## References And Code Map

- [OpenSSL FIPS provider](https://docs.openssl.org/3.5/man7/OSSL_PROVIDER-FIPS/)
  and [fipsinstall](https://docs.openssl.org/3.5/man1/openssl-fipsinstall/).
- [rustls FIPS guidance](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html).
- [NIST TLS guidance](https://csrc.nist.gov/pubs/sp/800/52/r2/final): apply relevant
  requirements rather than assuming a configuration allowlist implements a whole standard.
- [TLS policy](../../crates/fluxheim-config/src/config_tls.rs),
  [internal restrictions](../../crates/fluxheim-config/src/config_root_validate.rs)
  and [cache restrictions](../../crates/fluxheim-config/src/config_cache_compliance.rs).
- [Provider checks](../../crates/fluxheim-tls/src/provider.rs) and
  [root MAC/snapshot integration](../../src/internal_crypto.rs).
