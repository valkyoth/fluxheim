# Fluxheim 1.5.4 Release Notes

Fluxheim 1.5.4 is the TLS backend simplification release. It narrows the
supported TLS matrix to the backend families that Fluxheim fully wires through
listener policy, SNI, upstream TLS, client authentication, and compliance
evidence paths.

## Changed

- Remove the incomplete `tls-boringssl` and `tls-s2n` Cargo feature backends
  from the supported build matrix.
- Reject `backend = "boringssl"` and `backend = "s2n"` as TLS config values.
- Keep `tls-rustls` as the default and recommended backend.
- Keep `tls-openssl` as the supported OpenSSL integration path.
- Keep `tls-rustls-fips` / `tls-rustls-iso19790` and `tls-openssl-fips` /
  `tls-openssl-iso19790` as the compliance-oriented build aliases.
- Simplify TLS backend validation scripts so release checks cover rustls and
  OpenSSL only.
- Update documentation, feature tables, release checklist, FIPS notes, and
  compliance evidence templates to describe the rustls/OpenSSL-only matrix.

## Boundaries

1.5.4 does not add new TLS backends, HTTP/3/QUIC, native load-balancer
internals, stream proxy decoupling, or restart-persistent load-balancer state.
Those remain separate roadmap lines.
