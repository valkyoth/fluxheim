# Fluxheim 1.8.0 Release Notes

Fluxheim 1.8.0 packages the completed Wasm extensibility line as an explicit
distribution profile and begins a shared portable archive contract for Linux,
macOS, and Windows.

## Wasm Distribution Profile

- Add `profile-wasm` as `profile-full` plus the reviewed proxy-ABI and WASI
  capability surfaces.
- Keep `profile-full` and the unsuffixed full container image Wasm-free.
- Add dedicated `wasm` container-image and binary-archive profiles with ACME,
  metrics, and OpenTelemetry support matching the full production package.
- Require an explicit read-only plugin mount such as
  `/srv/infra/fluxheim/plugins:/etc/fluxheim/plugins:ro,Z`; no operator plugin
  is embedded in the image.
- Document that container read-only mounts do not protect their host source,
  require hash pinning for every production module, and recommend
  digest-pinned derivative images containing reviewed modules for
  high-assurance deployments.

## Portable Archives

- Generate `.tar.gz` and `.zip` from the same staged release directory.
- Add per-profile archive selection so the Wasm artifact can be built and
  tested independently.
- Preserve a common archive naming and content contract as the basis for
  unsigned macOS and Windows portable releases.
- Validate the same seven public profile names, Cargo feature sets, and binary
  layout across Linux, macOS, and Windows, including `.exe` naming on Windows.
- Generate and validate the archive matrix through one native Python planner
  consumed by the POSIX asset builder, avoiding WSL-versus-Git-Bash command
  resolution on Windows, and use portable package-version extraction in both
  native archive jobs.
- Build representative `full` and `wasm` archives on native macOS CI while
  keeping Windows at archive-plan and fail-closed config-boundary validation
  until native runtime and archive work begins in `1.8.2`.
- Compile Windows configuration and admin-socket planning without relying on
  Unix-only symbols, while keeping configuration-file loading fail-closed
  until Windows owner and ACL trust checks are implemented in `1.8.2`.
- Fix the release helper's `--profile all` state handling so one completed
  profile cannot suppress the remaining six archives.
- Keep signed/notarized macOS packages and Authenticode/MSI/MSIX delivery
  deferred until company-backed publisher credentials exist.

## Verification

- Validate that `profile-full` cannot accidentally enable Wasm.
- Validate that the image and archive matrices retain the dedicated Wasm
  profile.
- Extract the Wasm release tarball and run the real F5 iRules-style,
  nginx/OpenResty-style, HAProxy Lua/SPOE-style, and VCL-like cache-policy
  examples through the packaged binary.
- Build the dedicated Wasm Wolfi image, mount a hash-pinned policy module
  read-only at `/etc/fluxheim/plugins`, prove writes fail inside the container,
  and exercise live allow/deny decisions.
- Prove configured request-header variance partitions fixed-slice cache objects
  and reject response-only slice variance that cannot be known at lookup time.
- Prove a concurrent 32-request burst for one missing range slice produces one
  origin fetch when cache locking is enabled.
- Prove ordinary and fixed-slice cache-fill waiters cannot miss a fast writer
  notification and receive a bounded retryable `503` after one total wait
  deadline without creating another origin request.
- Bound runtime and inspection Vary keys to one SHA-256 component regardless of
  permitted request-header value length.
- Prove non-cache Wasm admission is partitioned per vhost beneath the native and
  preview process-wide ceilings, matching the existing cache-hook isolation.
- Run a native Windows regression proving unsupported filesystem ownership and
  ACL trust checks return an error rather than silently accepting a config
  path.
- Keep Unix descriptor-relative cache storage out of Windows profile builds
  until the native Windows filesystem implementation is reviewed in `1.8.2`.
- Compile and test the full workspace against `sanitization 2.0`, including
  request-body clearing, TLS and ACME secret input handling, snapshot
  integrity, administrative authentication, and persistence-cookie checks.
- Build RPM evidence from the exact release-candidate tree instead of remote
  `main`, and tag both FIPS backend evidence images with the candidate package
  version.

## Security Notes

- Record the ACME provider's opaque active signing-key representation as an
  accepted upstream residual. Fluxheim clears its transient PKCS#8 copies but
  does not claim provider-owned key-state zeroization.
- Apply the existing per-key cache-fill gate to fixed range slices, preventing
  same-slice origin stampedes.
- Register cache-fill notifications before releasing shared state, and enforce
  one total waiter deadline across ordinary and fixed-slice fills.
- Tune cache-lock waits above normal upper-tail origin latency but below
  surrounding request deadlines, with `age_timeout_secs` no shorter than the
  intended waiter budget.
- Replace variable-width encoded Vary material in cache keys with a fixed-width
  SHA-256 digest. Persisted variants using the prior key format become cold and
  age out or can be purged.
