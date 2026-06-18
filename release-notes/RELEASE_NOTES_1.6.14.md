# Fluxheim 1.6.14 Release Notes

Fluxheim 1.6.14 continues the Pingora-exit line by adding native rustls
upstream TLS support to the staged HTTP/1.1 proxy path. The production default
still keeps Pingora as the compatibility fallback for unsupported policy
combinations, but simple HTTPS upstream candidates can now be represented and
tested through Fluxheim-owned connector code.

## Added

- Added a `fluxheim-server` native HTTP/1 upstream TLS connector for rustls
  profiles, including explicit SNI, route-local CA bundle loading, optional
  upstream client certificate/key loading, certificate verification controls,
  and bounded no-follow PEM file reads.
- Added explicit rustls crypto-provider installation in the native upstream TLS
  connector so standalone `fluxheim-server` tests and future crate consumers do
  not panic when both rustls provider crates are present in the dependency
  graph.
- Added a real native HTTP/1 proxy test that generates a test CA and
  localhost SAN leaf certificate, starts a TLS upstream, verifies through the
  configured CA bundle, and forwards a request through the native proxy.
- Added ordered static upstream failover for the staged native HTTP/1 proxy
  path. Safe methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) can try the next
  configured static upstream after an upstream error; unsafe methods are not
  replayed.

## Changed

- Changed the native HTTP/1 upstream connection pool to store Fluxheim-owned
  boxed IO streams instead of raw `TcpStream`s. This keeps one retry/reuse path
  for plain TCP and TLS upstream connections.
- Wired the root rustls feature aliases into `fluxheim-server` so the native
  upstream TLS path is built in the same rustls profiles operators already use.
- Kept OpenSSL-native upstream TLS behind the existing compatibility fallback
  until it has equivalent implementation and tests.
- Allowed plain static `proxy.upstreams` lists to become native HTTP/1
  candidates when no advanced load-balancer policy is configured. Weighted,
  priority, locality, alias, tag, backup, drain, disabled, dynamic-discovery,
  and DNS-discovery policy still fail closed to the compatibility path.

## Security

- Native HTTPS upstream conversion now fails closed when any configured static
  upstream is IP-addressed with certificate verification enabled and no explicit
  `upstream_sni`, matching the validated config contract and avoiding silent
  hostname-verification downgrades.
- TLS key, certificate, and CA files loaded by the native path are bounded to
  1 MiB, must be regular files, and are opened with `O_NOFOLLOW` on audited Unix
  platforms.

## Compatibility

- Existing Pingora compatibility behavior remains available for unsupported
  policy combinations, OpenSSL-native upstream TLS, HTTP/2 upstreams, dynamic
  discovery, advanced load-balancer policy, upstream PROXY protocol, and
  websocket upgrades.
