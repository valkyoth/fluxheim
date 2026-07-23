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
- Validate the same seven public profile names, Cargo feature sets, and binary
  layout across Linux, macOS, and Windows, including `.exe` naming on Windows.
- Build representative `full` and `wasm` archives on native macOS and Windows
  CI runners before expanding live platform parity in `1.8.1` and `1.8.2`.
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
