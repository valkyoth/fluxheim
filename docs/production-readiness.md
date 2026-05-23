# Production Readiness

Fluxheim has a stable `1.3` shared ingress and TLS feature split on top of the
`1.2` cache/operations line, the `1.1` certificate-operations line, and the
`1.0` gateway foundation. This page states what each released line supports and
what operators should verify before using a build beyond local testing.

## 0.5 Basic-Sites Preview

The `0.5.x` line is intentionally limited:

- static file hosting from configured vhost roots;
- simple whole-vhost reverse proxying to one configured upstream target;
- vhost routing by exact and wildcard host names;
- cache code compiled by default, with runtime caching disabled until a storage
  tier is configured;
- static certificate loading for user-managed certificates;
- rustls as the default TLS backend;
- secure default response header policy with configurable request and response
  header operations;
- explicit request header, URI, and body limits;
- optional cleartext-to-HTTPS redirect;
- rootless Podman deployment paths and container examples;
- local release gates for formatting, linting, tests, license policy,
  dependency advisories, core feature profiles, SBOM generation, reproducible
  build evidence, and localhost smoke checks.

## Stable 1.0 Gateway Foundation

The `1.0` line is the first gateway-ready release for representative real
multi-site configs. In addition to the `0.5.x` behavior, it supports:

- static TLS with one default certificate;
- SNI certificate selection across multiple configured certificates in the
  default rustls build;
- route-level exact, prefix, and fallback matching;
- route actions for proxy, static serving, and redirects;
- cleartext ACME challenge exception routes plus HTTPS redirect for everything
  else;
- apex/`www` redirect vhosts that preserve the request URI safely;
- websocket-safe proxy smoke coverage for routes such as `/chat/`;
- per-route body limits, prefix stripping, and upstream connect/read/send
  timeouts;
- typed forwarding headers plus a small validated dynamic request-header
  template set for common proxy migrations;
- custom upstream error pages;
- static aliases and secure directory listing;
- container DNS behavior suitable for local Podman deployments, including
  graceful direct-proxy DNS failures;
- property-based invariant tests for parser, normalization, and security policy
  code that accepts attacker-controlled values;
- crate-level direct unsafe prohibition with safe wrappers for OS calls and
  safe test wakers;
- release-profile abort-on-panic plus clippy enforcement that production code
  does not use `unwrap()`, `expect()`, or `panic!()`;
- zeroizing admin token buffers and vetted constant-time comparison for
  authentication token verification;
- native systemd support for manually compiled binaries, including a hardened
  service unit, documented install paths, runtime directory handling, config
  validation before start, graceful shutdown/reload behavior, no-new-privileges,
  no ambient capabilities, strict filesystem protection, limited address
  families, and a conservative syscall filter.
- release evidence that includes SPDX/CycloneDX SBOMs, signed tags, checksums,
  immutable container digests, and a local reproducible-build check.

## Not Stable In 1.0

These features may exist in code, documentation, or feature flags, but they are
not part of the `1.0` stable support promise:

- ACME runtime issuance or automatic renewal;
- load balancing and health-check policy;
- admin snapshot and rollback API;
- remote logging pipelines;
- metrics exporters;
- OpenTelemetry tracing;
- WAF, auth-request, image filters, media modules, or WASM extension points;
- in-process seccomp or Landlock sandboxing;
- PHP, CGI, or any dynamic script execution;
- Cloudflare automation;
- legacy HTTP compatibility listeners;
- WireGuard/Sentinel Mesh or clustered state.

Treat these as design or incubator work until a later versioning-plan milestone
promotes them. Some of these items have since been promoted in `1.1`, `1.2`, or
`1.3`; use the sections below for the current support promise.

## Stable 1.1 Certificate Operations

The `1.1` line makes TLS and certificate operations practical for normal
production deployments. In addition to the `1.0` behavior, it supports:

- explicit safe TLS policy profiles;
- minimum TLS version config bounded to safe values;
- ALPN policy, curve preferences, cipher-suite allow-lists, and per-backend TLS
  validation;
- structured HSTS policy;
- ACME runtime issuance for Let's Encrypt, Actalis, and Google Trust Services;
- HTTP-01 and rustls TLS-ALPN-01 challenge handling for configured vhosts;
- Actalis and Google Trust Services External Account Binding support;
- safe ACME storage and key/certificate permission validation;
- renewal scheduling with a configurable renew-before window;
- renewal failure behavior that keeps the previous valid certificate serving.

DNS-01, wildcard automation, Cloudflare Origin CA automation, external secret
store deploy hooks, and full zero-downtime reload through the later snapshot
model are not part of the first `1.1` promise unless they are explicitly
promoted with tests and release evidence.

## Stable 1.2 Operations And Cache

The `1.2` line is the cache-server and operations-hardening milestone. It
promotes:

- vhost and route-scoped proxy cache policies with memory, disk, and tiered
  storage;
- cache key preview tooling, cache status visibility, and protected purge
  endpoints;
- indexed hard and soft purges by primary key, path, user tag, and cache tag;
- request collapsing with bounded cache-lock waits to reduce backend stampedes;
- stale-if-error and stale-while-revalidate behavior with explicit cache
  activity metrics;
- stable on-disk cache object metadata for combined keys, primary keys, tags,
  and path indexes;
- Prometheus metrics plus OpenTelemetry metric and trace export basics;
- strict host-routing mode that rejects missing, invalid, and unknown host
  headers instead of failing open to the default vhost;
- built-in admin bearer-token brute-force throttling with per-source and global
  failure windows, progressive lockouts, security logs, and metrics;
- authenticated admin health checks by default, with explicit loopback-only
  unauthenticated mode and optional empty `204` responses for local probes;
- fail-closed remote admin transport guardrails: non-loopback admin listeners
  require an explicit `trusted_tls_terminator` declaration until first-class
  admin TLS/mTLS lands;
- release-gate coverage for proxy cache, local observability smoke suites, and
  the published full/default, cache, and proxy container feature profiles.

Release evidence for the `1.2` line includes the stable gate, cache behavior
smokes, observability smokes, and focused follow-up checks. Bounded
single-range caching, the storage-bin disk backend, optional encrypted cache at
rest, distributed cache peer fill, and fixed-slice range composition are covered
by focused `1.2.x` releases. Varnish-style ban expressions and WASM cache hooks
remain future work unless explicitly promoted with tests and release evidence.

## Stable 1.3 Split Profiles

The `1.3.0` line starts the shared ingress/TLS feature-graph split. It does not
make the future PHP, advanced proxy, load-balancer, or WASM milestones stable;
instead it gives operators and packagers cleaner binaries and container images
for the modules that are already supported.

The `1.3.0` support promise includes:

- shared `ingress` and `tls` feature boundaries so TLS, ACME, proxy, cache, web,
  and future load-balancer modules can compose without every focused build
  compiling every application module;
- focused profile aliases: `profile-full`, `profile-web-server`,
  `profile-cache-edge`, `profile-proxy-edge`, and
  `profile-load-balancer-edge`;
- official full/default, cache-edge, and proxy-edge container image variants;
- TLS and ACME support in focused cache and proxy builds without requiring local
  static web-serving config in those images;
- runtime config guardrails that reject enabled static web config when the
  binary was compiled without `web`, and reject enabled cache config when the
  binary was compiled without `cache`;
- full native and RPM packages that keep the broad production feature set for
  operators who prefer one complete binary.

The load-balancer edge profile is compile- and config-validated in `1.3.0` so
the feature graph is ready for `1.5`, but it is not a production
load-balancing support promise yet.

The `1.3.1` support promise adds an opt-in `php-fpm` module for PHP
applications. PHP remains outside default and focused cache/proxy builds. A
PHP-FPM build is production-eligible only when php-fpm is isolated separately,
the PHP root is trusted, request body limits are configured, and operators have
validated their framework/application behavior with their php-fpm pool.
WordPress install, login, admin, plugin, and theme flows have release-candidate
coverage for both direct PHP-FPM serving and reverse-proxy gateway deployments.
The same release also normalizes split browser `Cookie` headers before proxying
or generating PHP-FPM `HTTP_COOKIE`, matching the behavior WordPress expects
behind HTTP/2 and container gateways.

The same line also supports pending Fluxheim-managed ACME certificates during
first issuance on reloadable SNI TLS backends. This lets operators add a new
ACME vhost without taking existing HTTPS sites down: HTTP-01 can validate on
port `80`, and the background renewal worker reloads the SNI certificate set
after the certificate files are installed. Static certificate paths remain
fail-closed.

The `1.3.4` support promise adds an OpenSSL FIPS/ISO-capable TLS build path for
operators who need to validate a deployment against an externally validated
OpenSSL 3 provider. This path is opt-in through `profile-fips-openssl` /
`tls-openssl-fips` or the ISO/IEC 19790 aliases
`profile-iso19790-openssl` / `tls-openssl-iso19790`, and requires `[tls]
backend = "openssl"` plus `[tls.fips] required = true` or `[tls.iso19790]
required = true`. Fluxheim validates the TLS policy, loads the FIPS provider,
enables OpenSSL default FIPS properties for the process-default library
context, verifies those default properties, and exposes release evidence
through `fluxheim crypto`, `fluxheim-config-tester --crypto`, and
`scripts/validate-fips-openssl.sh`. It does not make Fluxheim itself a
validated cryptographic module; operators still need the selected module's CMVP
certificate, Security Policy, provider configuration, platform evidence, and
operational records.

The `1.3.5` release line adds a rustls/AWS-LC FIPS candidate through
`profile-fips-rustls`, `tls-rustls-fips`, and the ISO/IEC 19790 terminology
alias `profile-iso19790-rustls`. It requires `[tls] backend = "rustls"` plus a
FIPS/ISO-required guard, uses rustls' AWS-LC FIPS provider path, and requires
the `aws-lc-fips-sys` build toolchain including CMake, Go, and a C compiler.
Treat it as backend evidence only, with the same non-TLS crypto caveats.

The `1.3.7` support promise completes the production PHP-FPM line. External
php-fpm remains the default, while `mode = "managed"` lets Fluxheim generate a
private php-fpm pool, supervise the php-fpm master, respawn it after post-start
crashes with bounded backoff, and run WordPress-compatible PHP through the same
FastCGI request path. The recommended Wolfi PHP image includes `php-8.5-fpm`
for this managed mode; other image variants keep the external php-fpm
deployment shape unless customized.

## Operator Checks

Before using a Fluxheim build for a real site, run the stable gate from the repo
root:

```bash
scripts/stable_release_gate.sh check
```

For `1.3` candidates, this gate also runs the proxy cache and local
observability smoke suites, and verifies the published full, cache-edge,
proxy-edge, and PHP-FPM container feature profiles against their packaged
container configs.
The load-balancer edge profile is compile/config validated only until the `1.5`
load-balancer milestone promotes runtime load-balancing behavior.

For a release candidate, also run the deeper optional checks that fit the
deployment:

```bash
FLUXHEIM_GATE_TLS_BACKENDS=1 \
FLUXHEIM_GATE_FIPS_OPENSSL=1 \
FLUXHEIM_GATE_FIPS_RUSTLS=1 \
FLUXHEIM_GATE_TLS_SCAN=1 \
FLUXHEIM_GATE_LOAD=1 \
FLUXHEIM_GATE_FRAMING=1 \
FLUXHEIM_GATE_FUZZ_CHECK=1 \
scripts/stable_release_gate.sh check
```

Use `check` mode for local development on rolling distributions. For release
mode rustls/AWS-LC FIPS evidence, prefer the supported builder workflow in
[FIPS-Capable Deployments](fips.md); otherwise set
`FLUXHEIM_GATE_FIPS_RUSTLS=0` locally and attach the rustls evidence from that
builder.

Run the Podman smoke when container paths or image definitions change:

```bash
FLUXHEIM_GATE_PODMAN=1 scripts/stable_release_gate.sh check
```

Keep the generated release evidence with the release notes:

```bash
scripts/capture_release_gate_report.sh
```

## Configuration Review

Before starting the server:

- validate every config with `fluxheim --validate-config --config <path>` before
  service start;
- use `fluxheim-config-tester --config <path> --profile <profile> --no-runtime-paths`
  when diagnosing a mounted config without access to `/run/fluxheim`;
- prefer split `conf.d` files with one `[[vhosts]]` per file;
- use `upstreams = ["host:port"]` for proxy targets;
- do not mix compatibility aliases such as `upstream` with preferred fields
  such as `upstreams`;
- keep TLS private keys, ACME storage, log files, cache roots, runtime paths,
  admin token files, and snapshot stores outside group- or world-writable directories;
- audit POSIX extended ACLs on those same sensitive paths. Fluxheim rejects
  unsafe Unix mode bits and symlinks, but it does not yet parse extended ACL
  entries that can grant write access without setting `020` or `002`;
- run Fluxheim with a restrictive umask such as `0077` or `0027`; Fluxheim sets
  private modes for its snapshot store, but a restrictive service umask remains
  useful defense in depth for operator-created paths and future state files;
- disable swap and core dumps, or use equivalent host controls, for deployments
  that treat admin bearer tokens, EAB credentials, TLS private keys, or cache
  encryption credentials as high-assurance secrets;
- keep admin and metrics listeners loopback-only unless a trusted local
  sidecar or network policy protects them;
- set `[admin.transport] mode = "trusted_tls_terminator"` only when a trusted
  local TLS/mTLS terminator protects every remote hop to the admin plane;
- keep admin authentication throttling enabled unless a stricter external
  control-plane rate limiter is already enforcing equivalent limits;
- keep admin health authenticated unless a local-only supervisor needs an
  unauthenticated loopback probe;
- explicitly decide whether access logging may include raw host and path
  values.

## Deployment Notes

The recommended container mode is rootless with host ports mapped to the
container's high internal listener ports. If a deployment deliberately runs the
container as root for direct low-port binding, keep mounted config, content,
certificate, cache, and runtime directories separate and permission them for the
chosen runtime user.

The recommended native package mode binds public ports directly. The packaged
default config listens on `80`, and the systemd unit grants only
`CAP_NET_BIND_SERVICE` so the service can also bind `443` when TLS is enabled
without running Fluxheim as root.

Fluxheim's memory-safety baseline does not replace operational security checks.
Continue running dependency audits, license checks, malformed request framing
tests, TLS scans, and load smoke tests for every stable release branch.
