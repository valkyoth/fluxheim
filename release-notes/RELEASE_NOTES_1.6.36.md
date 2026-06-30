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
