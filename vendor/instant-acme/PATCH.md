# Fluxheim instant-acme patch

This directory is the crates.io `instant-acme 0.8.5` source published from
upstream Git commit `c8c16a211d01bee3586c2639da00dcd96e70dcd2`. The original
crate checksum is
`9f05ad37c421b962354c358d347d4a6130151df9407978372d3ad7f0c8f71a64`.

Fluxheim adds one method, `AccountBuilder::create_with_key`, which calls the
existing private `create_inner` implementation with caller-provided PKCS#8 key
material. No ACME wire-format, signing, EAB, HTTP, or response behavior is
changed. This API lets Fluxheim durably journal the account key before the
issuer can activate it while preserving configured contacts and EAB.

Remove this patch when an upstream release exposes an equivalent API. Before
updating it, compare every vendored file with the corresponding crates.io source
and retain a focused test proving key identity, contacts, and EAB behavior.
`scripts/validate-instant-acme-patch.sh` enforces that comparison in CI and
release gates by stripping the marked method and checking the published source
hashes in `UPSTREAM-SHA256SUMS`.
