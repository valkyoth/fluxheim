# Commit 22: Root Cache Inspection

Base: `6669165db80ab34a71a40be9d66192c786e71869`.

## Scope

Offline proxy-cache inspection now selects the root policy when no vhosts are
configured. Its explicit `root` scope has an empty vhost field and uses the
serving cache's existing `root` identity; no synthetic vhost or new admin alias
is created. Named-vhost inspection honors exact hosts, longest wildcard suffix,
strict-host rejection and configured/default fallback. Routes retain exact,
longest-prefix, regex and fallback precedence. A route without a cache cannot
inspect the fallback vhost cache instead.

Preview uses the shared request-bypass policy and retains repeated CLI header
values. Filesystem lookup uses the selected scope's policy and resolves stored
Vary metadata with the supplied headers. Root query keys and encrypted objects
are inspectable without origin requests. Static/non-proxy actions and rewritten
routes return an explicit ineligible result instead of a guessed proxy key.

Eligible standalone storage-bin lookup now returns an unsupported error before
opening storage. It does not acquire a second allocator, whether or not a server
is running. Memory-only lookup remains empty: a separate CLI process has no
access to serving RAM. Filesystem inspection retains its existing recovery and
pruning behavior and is not a guaranteed read-only inventory. Preview remains
configuration-derived, not a simulation of authorization, response admission,
header transformations, Wasm or live cache-pass state.

Admin endpoints, authorization and scoped purge contracts are unchanged. Root
activity can contribute to process totals, but named vhosts/routes remain the
supported detail/purge scopes. The operations guide makes this distinction
explicit rather than introducing an ambiguous `root` vhost alias.

No Cargo manifest, lockfile, dependency, HTTP serving or CodeQL policy changed.

## Regression Coverage

- Root scope/key/query/host identity; no fictitious vhost; memory lookup empty.
- Exact and wildcard host precedence, strict rejection, default fallback,
  named `root` versus root policy, and disabled policies.
- Route selection, absent route cache, bypassed credentials/no-store, repeated
  headers, unsafe paths and HEAD bypass.
- Root and named-vhost HTTP MISS/HIT, filesystem lookup and explicit bin refusal.
- Memory, filesystem and bin restart; disk-only and tiered configurations;
  encrypted filesystem/bin variants; query and Accept-Language variants.
- Origin counts remain unchanged across inspection. Bin lookup refusal leaves
  the serving allocator usable and subsequent restart still returns the object.
- Live route namespaces, prefix/regex/exact selection and unknown-host refusal.
- Existing authenticated admin operations still reject anonymous and observer
  access; no scope expansion was made.

The Windows admin fixture initially used Unix directory permissions without
installing inheritable private ACLs. It now uses the established private fixture
and protects each cache parent before credentials/configuration are created.
Regression tests cover failure before writes. Production trust checks were not
relaxed.

## Qualification

Completed on 2026-11-13 using Rust 1.99.1:

| Check | Result |
| --- | --- |
| Linux locked workspace, normal parallel execution | Passed; one existing privileged ACME test ignored |
| Linux locked workspace, serialized execution | Passed |
| Linux load-balancer profile application library | 284 passed before two additional tests; final focused suite passed |
| macOS application library / cache crate | 281 / 67 passed; final focused suite passed |
| Windows application library / cache crate | 257 / 67 passed; final focused suite passed |
| Final inspection/proxy unit suite on Linux, macOS and Windows | 12 passed each |
| Live cache inspection matrix | Passed on Linux, macOS, Windows and non-root Podman |
| Protected cache operations | Memory/filesystem/bin passed on Linux, macOS and Windows |
| Strict application Clippy, all targets | Passed on Linux and macOS |
| Privacy profile without cache | Compiled; cache remains intentionally incompatible with privacy mode |
| Python cache fixture regressions | 15 passed on Linux/macOS; native Windows fixture execution passed |
| CI qualification / documentation layout | 11 / 28 passed |
| Formatting, Python compilation, documentation links and diff validation | Passed |
| RustSec / cargo-deny | 449 locked dependencies, no advisory failures; policy passed |

Two initial parallel workspace attempts failed in unchanged load-balancer tests:
retry alternative selection and a readiness-port rebind (`AddrInUse`). The
selection test passed alone; a serialized workspace run and the final normal
parallel workspace run both passed without changing either test or production
selection logic. These observations are retained rather than presented as an
uninterrupted pass. Native Windows Clippy was unavailable in the installed
read-only toolchain; no toolchain installation was performed for this change.

Packaged runtime image tested:
`sha256:88b77b969fdbecc696f757e27d1611cdd4c9ac315e473d7186b613a8e1e1e5a7`.
The fixture image added only scripts/examples and a private working directory;
it ran non-root with no network, dropped capabilities and no-new-privileges.
The dedicated Windows VM was shut down normally after testing.

Native release archives, ARM64 and byte reproducibility were not requalified
for this CLI correction; they remain final release gates. Independent pentest
and exact-commit GitHub acceptance are pending. This is not release approval or
an absence-of-vulnerabilities claim.

## CodeQL Follow-up

Alert #461 identified direct reflection of Accept-Language into Content-Language
in the loopback Python test origin. The fixture now emits only literal `en`,
`sv` or `none` values, with `none` used for missing, unsupported, duplicated or
folded input. No production server code or dependency changed.

Raw-socket regression coverage exercises eight header cases, including CRLF
and LF folding, and checks the response headers and body. The cache fixture
suite passes all 16 tests. The full Linux live cache matrix, including encrypted
variants, backend/layout migration and route isolation, also passes. Python
compilation and diff validation pass. Exact-commit CodeQL confirmation remains
pending.
