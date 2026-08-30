# Fluxheim 1.8.2 Release Notes

Fluxheim 1.8.2 is the Windows portable-parity development line. It targets
native MSVC builds on both x86_64 and ARM64 Windows hosts while preserving the
same seven public profiles used by Linux and Apple Silicon macOS.

## In Progress

- Build unsigned `.zip` previews for `full`, `wasm`, `cache`, `proxy`,
  `load-balancer`, `php`, and `config-tester` on both Windows architectures.
- Replace Unix-only filesystem, local-control, locking, shutdown, and
  certificate-storage assumptions with reviewed Windows-native behavior.
- Add native live static, proxy, TLS, cache, admin, load-balancer,
  observability, and packaged-Wasm tests before publishing Windows artifacts.
- Keep the Windows `php` profile on the shared FastCGI request path with
  external TCP pools. Managed PHP-FPM supervision remains Unix-only and is
  rejected during Windows configuration validation and runtime construction;
  a native Windows TCP FastCGI responder regression proves the supported path.
- Produce exact-tag, architecture, checksum, test, and reproducibility evidence
  from dedicated Windows builders. Planning-only output is not releasable.
- Run the complete workspace test suite on the normal Windows x86_64 gate and
  deny Windows-target compiler warnings before using cloud builders for final
  x86_64 and ARM64 release evidence. The Unix/OpenSSL FIPS support shim is
  excluded as an independent workspace package while remaining covered by the
  dedicated Linux OpenSSL-FIPS profiles.

These archives remain unsigned previews. Authenticode and installer work stays
deferred until company-backed publisher credentials are available.
