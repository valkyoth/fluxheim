# Peer Cache Variant Qualification

Local qualification: 2026-11-11. Commit 19 follows
`a6edc73aa69136998f957d83eecfafc5c8c5c246`. Implementation and local tests are
complete; independent pentest and exact-commit GitHub acceptance remain pending.
This is not final release qualification.

## Delivered

Peer fills now preserve bounded, explicitly selected request variants. The
standard Accept, Accept-Encoding and Accept-Language fields are accompanied by
safe custom `vary_request_headers`. Missing, empty and repeated values have
distinct canonical representations, including repeated-value order. Credentials,
hop-by-hop fields and connection-nominated fields are not forwarded.

Version-2 request and response HMACs bind the canonical variant context, target,
Host and nonce. Responses declare their required variant fields, and recipients
reject responses requiring fields they did not preserve. Unsupported or
incompatible peer responses cannot populate the local cache. The existing
fail-open/fail-closed policy controls subsequent fallback.

The response envelope protects the original cache Date separately because the
HTTP writer regenerates Date and framing headers after signing. Body hashing
binds response bytes; Age and the variant envelope remain authenticated. The
verified cache date is restored before local admission, and internal peer
metadata is removed before serving ordinary clients or forwarding to origins.

This changes peer wire compatibility: upgrade cooperating peers together.
There is no version-1 downgrade. See the
[peer-fill guide](../guides/cache-peer-fill.md) for configuration, bounds,
fallback behavior and the trust boundary. Operators must select only public
representation metadata as custom selectors; header-name filtering cannot
identify every possible secret carried under an arbitrary name.

No Cargo manifests or locked dependencies changed.

## Verification

| Check | Result |
| --- | --- |
| Full locked Linux workspace suite | Passed; existing privileged ACME test remains ignored |
| Combined Wasm/PHP/load-balancer/Rustls server suite | 704 passed |
| Linux OpenSSL/load-balancer server suite | 599 passed on complete rerun |
| Native macOS Apple Silicon Rustls/load-balancer server suite | 602 passed |
| Native Windows x86_64 Rustls/load-balancer server suite | 600 passed |
| Focused Linux peer tests | 29 passed |
| Live shared-secret peer smoke | All six scenarios passed on each of Linux, macOS and Windows |
| Fresh non-root Wolfi peer smoke | All six scenarios passed |
| Existing peer-fill shell smoke | Passed, including Age, language variants, fallback and metrics |
| Existing cache guide, restart and backend migration smoke | Passed on macOS and Windows |
| Strict Clippy | Combined-feature Linux and native macOS passed |
| Minimal server without default features | Passed |
| Python peer regression tests | Four passed on Linux, macOS and Windows |
| Python cache and error-phase regressions | 15 passed on Linux |
| RustSec and cargo-deny | 449 locked dependencies, zero known vulnerabilities; all deny policies passed |
| Formatting, documentation layout/links, modularity and diff checks | Passed |

The real-peer matrix starts two peers and a counted origin. It covers memory,
filesystem disk and storage bins, with either configured selectors or
origin-declared Vary. Exact response bodies and origin counts are asserted for
missing, empty, custom and repeated values. A cold first peer does not contact
the origin; the warmed second peer supplies the matching variant. A subsequent
local hit must preserve that body. A cold path falls back exactly once.

Rust tests run both authenticated and permitted unauthenticated loopback modes.
Standalone native smokes generate private shared-secret files and exercise
actual secret loading on all three operating systems. The non-root container
fixture exercises the permitted unauthenticated numeric-loopback mode, not
authenticated traffic across an untrusted container network.

Negative tests cover variant, Host, manifest, nonce and protocol tampering;
cross-request response replay; wrong secrets; missing and legacy versions;
unsupported origin Vary; duplicate fields; bounded lengths and counts; and
protected freshness metadata. The HTTPS fixture presents a trusted certificate,
then separately checks wrong-hostname and wrong-CA failures. Its fixture CA is
supplied directly to the test client; no system trust store or new public
peer-CA configuration is introduced. Failed TLS verification cannot admit a
peer response, while allowed fallback still returns the correct origin body.

Linux, macOS and Windows CI now include the standalone peer-variant smoke.

Tested Wolfi image:
`sha256:c48be44d99285d6fddecce30d2c8e45ab4490955150893bcb32f0048a9271a38`.
This identifies the local test image, not independent artifact provenance.

## Boundaries

- An initial OpenSSL suite run failed the existing storage-bin missing-index
  recovery test. Its isolated rerun and the full 599-test rerun passed. The
  cause was not established; no assertion was weakened or unrelated recovery
  code changed to obtain the pass.
- Native Linux ARM64 and release archives were not rebuilt for this checkpoint.
  Final release-wide qualification remains required.
- Native Windows lacks Clippy; Linux and macOS provide strict Clippy checks.
- HMAC authenticates members of the shared-secret group; it does not make a
  compromised trusted peer honest or encrypt traffic. Use HTTPS on untrusted
  networks. Ordinary cache eligibility and freshness rules still apply.
- No public server, shared-project VM or system certificate store was modified.
- Machine-specific logs and unresolved correction planning remain local.
- Local qualification does not replace the independent pentest and CI gates.
