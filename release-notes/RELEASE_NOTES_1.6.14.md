# Fluxheim 1.6.14 Release Notes

Fluxheim 1.6.14 continues the Pingora-exit line by adding native rustls and
OpenSSL upstream TLS support to the staged HTTP/1.1 proxy path. The production
default still keeps Pingora as the compatibility fallback for unsupported
policy combinations, but simple HTTPS upstream candidates can now be
represented and tested through Fluxheim-owned connector code.

## Added

- Added `fluxheim-server` native HTTP/1 upstream TLS connectors for rustls and
  OpenSSL profiles, including explicit SNI, route-local CA bundle loading,
  optional upstream client certificate/key loading, certificate verification
  controls, and bounded no-follow PEM file reads.
- Added explicit rustls crypto-provider installation in the native upstream TLS
  connector so standalone `fluxheim-server` tests and future crate consumers do
  not panic when both rustls provider crates are present in the dependency
  graph.
- Added a real native HTTP/1 proxy test that generates a test CA and
  localhost SAN leaf certificate, starts a TLS upstream, verifies through the
  configured CA bundle, and forwards a request through the native proxy.
- Added real native upstream TLS hostname-policy tests proving the default
  path rejects SAN mismatches, `upstream_alternative_cn` verifies against the
  configured alternate name, and `upstream_verify_hostname = false` disables
  only hostname verification while keeping CA verification active.
- Added a real native upstream mTLS test that starts an origin requiring a
  client certificate and verifies the configured upstream client cert/key path
  works through rustls and OpenSSL builds. The same fixture now also verifies
  that an mTLS-only origin fails closed when the native proxy is not configured
  with upstream client certificate material.
- Added ordered static upstream failover for the staged native HTTP/1 proxy
  path. Safe methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) can try the next
  configured static upstream after an upstream error; unsafe methods are not
  replayed.

## Changed

- Changed the native HTTP/1 upstream connection pool to store Fluxheim-owned
  boxed IO streams instead of raw `TcpStream`s. This keeps one retry/reuse path
  for plain TCP and TLS upstream connections.
- Wired the root rustls and OpenSSL feature aliases into `fluxheim-server` so
  the native upstream TLS path is built in the same TLS profiles operators
  already use.
- Allowed plain static `proxy.upstreams` lists to become native HTTP/1
  candidates when no advanced load-balancer policy is configured. Weighted,
  priority, locality, alias, tag, backup, drain, disabled, dynamic-discovery,
  and DNS-discovery policy still fail closed to the compatibility path.
- Restricted stale pooled-connection retries in the native HTTP/1 upstream
  client to safe methods only, matching the static failover replay policy.

## Security

- Native HTTPS upstream conversion now fails closed when any configured static
  upstream is IP-addressed with certificate verification enabled and no explicit
  `upstream_sni`, matching the validated config contract and avoiding silent
  hostname-verification downgrades.
- The native HTTP/1 proxy builder now mirrors the config loader's upstream TLS
  material checks so crate-level callers cannot silently ignore a CA bundle,
  one-sided client certificate/key material, or inconsistent
  `upstream_verify_cert` / `upstream_verify_hostname` settings.
- OpenSSL-only native HTTP/1 server-plan tests now assert the same TLS policy
  failure reason as rustls builds instead of treating OpenSSL as an unsupported
  TLS backend.
- The native OpenSSL upstream TLS connector now enforces TLS 1.2 or newer and
  uses explicit AEAD-only TLS 1.2 / TLS 1.3 cipher suite allowlists instead of
  relying on system OpenSSL defaults.
- Native upstream TLS certificate/key loading now canonicalizes the existing
  parent directory before inspecting and opening the final file, keeping the
  final `O_NOFOLLOW` symlink protection while making the filesystem trust
  boundary explicit for CodeQL.
- TLS key, certificate, and CA files loaded by the native path are bounded to
  1 MiB, must be regular files, and are opened with `O_NOFOLLOW` on audited Unix
  platforms. The native file reader now has direct tests for oversized-file
  rejection and final-symlink rejection.

## Compatibility

- Existing Pingora compatibility behavior remains available for unsupported
  policy combinations, HTTP/2 upstreams, dynamic discovery, advanced
  load-balancer policy, upstream PROXY protocol, and websocket upgrades.
