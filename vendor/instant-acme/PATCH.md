# Fluxheim instant-acme patch

This directory is the crates.io `instant-acme 0.8.5` source published from
upstream Git commit `c8c16a211d01bee3586c2639da00dcd96e70dcd2`. The original
crate checksum is
`9f05ad37c421b962354c358d347d4a6130151df9407978372d3ad7f0c8f71a64`.

Fluxheim adds caller-key account bootstrap and recovery methods around the
existing private `create_inner` implementation. Account credential PKCS#8 bytes
are owned by `sanitization::SecretVec`, and key JSON encoding/decoding uses
drop-cleared Base64 buffers. No ACME wire-format, signing, EAB, HTTP, or response
behavior is changed. These APIs let Fluxheim durably journal the account key
before the issuer can activate it while preserving configured contacts and EAB.

Remove this patch when an upstream release exposes an equivalent API. Before
updating it, compare every vendored file with the corresponding crates.io source
and retain a focused test proving key identity, contacts, and EAB behavior.
`scripts/validate-instant-acme-patch.sh` checks unchanged published files against
`UPSTREAM-SHA256SUMS`, checks the three intentionally modified files against
`FLUXHEIM-PATCHED-SHA256SUMS`, and verifies an aggregate patch-set digest in
`FLUXHEIM-PATCH-SHA256`. The validator also requires every bounded account API
marker and the protected credential-storage primitives, so neither unchanged
upstream code nor reviewed patched files can drift without an explicit policy
update.
