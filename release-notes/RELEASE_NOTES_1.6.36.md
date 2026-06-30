# Fluxheim 1.6.36 Release Notes

Fluxheim 1.6.36 is the post-cutover structural cleanup release after the
Pingora-free 1.6.34 proof release and the 1.6.35 stabilization checkpoint.

This release is intentionally scoped to behavior-preserving cleanup unless
pentest or CI finds a correctness issue: remove temporary compatibility
boundaries, move remaining native runtime DTOs and helpers into their owning
crates, and delete inert Pingora-era root code that normal Fluxheim builds no
longer use.

## Highlights

- Start replacing the temporary native proxy shim with direct crate-owned APIs.
- Rename the temporary native proxy shim module to `native_proxy`, keeping the
  historical `crate::proxy` re-export stable while the owning crate APIs are
  split out.
- Stop re-exporting cache admin DTOs through the native proxy compatibility
  boundary; admin and CLI code now use the dedicated `cache_api` module
  directly.
- Replace active root/admin/CLI/runtime imports of the historical `crate::proxy`
  compatibility alias with direct `crate::native_proxy` imports.
- Move load-balancer admin request/result DTOs from the native proxy boundary
  into the `fluxheim-load-balancer` crate.
- Remove the historical `crate::proxy` re-export from normal builds; active
  code now uses `crate::native_proxy` and crate-owned APIs directly.
- Delete inert Pingora-era root source files that were permanently gated behind
  `cfg(any())`, including the old proxy, cache, header, auth-request, edge
  policy, PHP-FPM, traffic-mirror, and proxy-protocol adapters.
- Remove stale disabled Pingora compatibility runner/test code from
  `runtime.rs` so dead `cfg(any())` paths no longer reference non-existent
  native proxy methods or Pingora traits.
- Remove the stale Pingora HTTP boundary exception rows now that normal source
  no longer carries quarantined Pingora HTTP adapter code.
- Consolidate native proxy config storage so hot reload refreshes the same
  config snapshot used by cache purge, cache preview, cache stats, activity
  reset, and load-balancer stats paths.
- Add native HTTP/1 chunked-body regression coverage for the historical
  overflow-sized chunk header crash class; the native parser rejects the
  `ffffffffffffffff` chunk size before routing reaches the proxy handler.
- Pin observability smoke images to stable Prometheus and Jaeger tags instead
  of `latest` so CI pulls deterministic container versions.
- Keep normal Fluxheim builds on the Pingora-free runtime introduced in
  `1.6.34` and stabilized in `1.6.35`.
- Keep release, dependency, native-runtime, RPM, container, and smoke gates as
  blocking evidence while the cleanup removes compatibility code.

## Compatibility Notes

- This release should not change runtime configuration semantics.
- Cleanup should be mechanical and behavior-preserving unless a specific
  security or correctness issue is found during review.

## Verification

- `scripts/validate-release-metadata.sh`
- `scripts/validate-pingora-dependency-policy.sh`
- `scripts/validate-native-runtime-cutover.sh`
- `scripts/stable_release_gate.sh check`
