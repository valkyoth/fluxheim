# Fluxheim 1.3.6 Release Notes

Fluxheim 1.3.6 is the FIPS/ISO internal-crypto closure and compliance evidence
package release for the 1.3 line. It does not claim that Fluxheim is FIPS
certified, ISO/IEC 19790 certified, or Common Criteria certified. It tightens
what a FIPS/ISO-required config can enable so non-TLS cryptography is either
outside the boundary, externally evidenced, documented as non-secret, or
rejected, and it gives operators a repeatable evidence template for regulated
reviews.

## Highlights

- FIPS/ISO-required configs now reject managed ACME. Use externally issued
  static certificates or an external renewal workflow until ACME account
  key generation, JWS account signing, EAB, outbound ACME HTTPS transport, and
  challenge certificate generation are provider-routed or separately evidenced.
- FIPS/ISO-required configs now allow the admin API in `tls-openssl-fips` and
  `tls-rustls-fips` builds because bearer-token HMAC is routed through OpenSSL
  FIPS or AWS-LC FIPS respectively. Non-FIPS builds still reject admin in
  FIPS/ISO-required configs.
- FIPS/ISO-required configs now reject local disk-cache encryption because the
  local path currently uses ring AES-GCM.
- FIPS/ISO-required configs warn when disk cache is enabled without
  encryption. This is allowed for operator-controlled policies, but cached
  response bodies are written at rest without a Fluxheim-managed encryption
  boundary. Operators can set `require_disk_cache_encryption = true` under
  `[tls.fips]` or `[tls.iso19790]` to make this a hard config error.
- OpenBao Transit cache encryption remains allowed as an external evidence
  boundary only through local numeric loopback HTTP. Operators must provide
  OpenBao module, platform, and deployment evidence. Remote or HTTPS OpenBao
  transport remains blocked until outbound TLS evidence is added.
- OTLP metrics/traces export is allowed only to numeric local `http://`
  loopback collectors in FIPS/ISO-required configs. `localhost`, remote OTLP,
  and HTTPS OTLP remain blocked until outbound TLS can be routed through the
  selected validated backend or separately evidenced.
- Request IDs and temporary object names are documented as non-secret
  operational identifiers rather than authentication tokens, key material, or
  SSPs.
- Added `docs/compliance-evidence-template.md` with release metadata, candidate
  TOE boundary, Security Target-style draft fields, operational-environment
  assumptions, cryptographic module evidence, validation-script identifiers,
  scanner output checklist, and vulnerability-analysis records.
- `scripts/release_evidence.sh` now emits a compliance evidence package section
  that points to the template and records the required follow-up fields.
- Runtime Pingora cache storage, tiered storage, cache locks, and cache
  predictors are reused for identical cache plans across authenticated reloads,
  reducing process-lifetime allocations required by Pingora's `'static` cache
  API.
- Dynamic admin API JSON responses now serialize through `serde_json::to_vec`
  instead of hand-written `format!` response bodies, preserving existing schemas
  while reducing future JSON escaping risk.
- Admin bearer-token authorization avoids length-check short-circuiting,
  zeroizes the temporary candidate copy used for comparison, and aborts on
  impossible system-clock failures instead of falling back to epoch timestamps.
- Snapshot ID generation now aborts on system-clock failure rather than
  generating `s0-...` identifiers.
- Admin runtime/auth-throttle mutex poisoning now aborts instead of recovering
  potentially inconsistent state in debug/test builds, matching the production
  fail-closed model.
- Peer-fill concurrency counters now use checked arithmetic and refuse permits
  if a counter saturates.
- The `RUSTSEC-2024-0437` suppression now has release-metadata enforcement so
  it must be reviewed when Pingora moves off Prometheus `0.13.4` or when the
  scheduled review date is reached.

## Validation

The release adds config-validation tests that prove FIPS/ISO-required mode
accepts provider-backed admin auth, fails closed for managed ACME and local
cache encryption, and accepts OpenBao Transit cache encryption only through
local numeric loopback HTTP as an external cryptographic service boundary. The
OpenSSL and rustls FIPS validation scripts include matching provider-backed and
fail-closed fixtures for those internal-crypto gates, and the managed ACME
fixtures assert the specific ACME rejection reason instead of accepting any
non-zero config-tester exit.

Recommended local checks:

```bash
cargo test --locked --no-default-features --features profile-fips-openssl fips_required_
cargo test --locked --no-default-features --features profile-fips-rustls fips_required_
cargo test --locked fips_otlp_local_collector_exception_accepts_loopback_http_only
```

## Operator Notes

This release makes strict FIPS/ISO-required configs more conservative. Builds
can still compile ACME, admin, cache, PHP-FPM, and telemetry features for normal
operation, but enabling `[tls.fips] required = true` or
`[tls.iso19790] required = true` rejects the incompatible runtime paths listed
above.

For regulated deployments, prefer static certificate files generated by an
approved external process, enable the admin API only in a provider-backed
OpenSSL FIPS or rustls/AWS-LC FIPS build, use no cache encryption or OpenBao
Transit with evidence, and send OTLP only to a numeric local collector until
outbound TLS evidence is added.

Use `docs/compliance-evidence-template.md` with `scripts/release_evidence.sh`
for the release evidence package. The Common Criteria-aligned sections are
evidence organization only; they are not a Protection Profile, evaluated
Security Target, EAL, or certification claim.
