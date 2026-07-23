# Fluxheim 1.8.0 Release Notes

Fluxheim 1.8.0 packages the completed Wasm extensibility line as an explicit
distribution profile and begins a shared portable archive contract for Linux,
macOS, and Windows.

This release is under development.

## Wasm Distribution Profile

- Add `profile-wasm` as `profile-full` plus the reviewed proxy-ABI and WASI
  capability surfaces.
- Keep `profile-full` and the unsuffixed full container image Wasm-free.
- Add dedicated `wasm` container-image and binary-archive profiles with ACME,
  metrics, and OpenTelemetry support matching the full production package.
- Require an explicit read-only plugin mount such as
  `/srv/infra/fluxheim/plugins:/etc/fluxheim/plugins:ro,Z`; no operator plugin
  is embedded in the image.

## Portable Archives

- Generate `.tar.gz` and `.zip` from the same staged release directory.
- Add per-profile archive selection so the Wasm artifact can be built and
  tested independently.
- Preserve a common archive naming and content contract as the basis for
  unsigned macOS and Windows portable releases.
- Keep signed/notarized macOS packages and Authenticode/MSI/MSIX delivery
  deferred until company-backed publisher credentials exist.

## Verification

- Validate that `profile-full` cannot accidentally enable Wasm.
- Validate that the image and archive matrices retain the dedicated Wasm
  profile.
- Extract the Wasm release tarball and run the real F5 iRules-style,
  nginx/OpenResty-style, HAProxy Lua/SPOE-style, and VCL-like cache-policy
  examples through the packaged binary.
