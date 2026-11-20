# ACME renewal holds and dependency refresh

Selected and all-target due runs share the same scheduling path. A future
`renew_after` defaults to an elective hold; only an explicit absolute hold
blocks emergency and issuer-advised renewal. At the deadline ordinary rules resume.
An explicit forced run still needs an enabled target and issuer terms. Status
reports the local schedule; it does not query the issuer for a prediction.
See the [operator guide](../guides/acme.md#renewal-holds-and-reload).

## Qualification

- Offline tests exercise instant equality, offset-equivalent times, missing
  and observed certificates, selected and all-target force, rejected terms,
  and no account or certificate state creation during an absolute hold.
- Native all-feature ACME suites ran on Linux, Apple Silicon macOS and
  Windows x64. Linux skipped its existing privileged mount-namespace test.
- The packaged Wolfi full and PHP profiles ran against local Pebble via
  Podman. With an absolutely held background gateway and a missing certificate, unforced
  legacy and companion commands (including a selected vhost) attempted zero
  renewals. An elective hold permits initial issuance but defers routine
  replacement without due issuer advice. An explicitly disabled target stays
  off even with force. The fixture counts order requests rather than relying solely on
  CLI output. It checks four CLI issuance paths and a fifth order from the
  released background scheduler, then compares the served leaf with the
  installed certificate over hostname-verified TLS. No public CA is used.
- The production and fuzz lockfiles were refreshed, including Sanitization
  2.2.0. The compatible-crate freshness check and RustSec audits passed.
  Cargo Deny 0.22.0 passed the production advisory, license, ban and source
  checks. The collector browser fixture uses Playwright 1.65.1 (Node 20+);
  its matching Chromium headless shell launched and rendered a test page.
