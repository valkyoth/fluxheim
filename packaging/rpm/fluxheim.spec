%global fluxheim_features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
%global rust_min_version 1.96
%bcond_without tests

%{!?_tmpfilesdir:%global _tmpfilesdir %{_prefix}/lib/tmpfiles.d}
%{!?_sysusersdir:%global _sysusersdir %{_prefix}/lib/sysusers.d}
%{!?_unitdir:%global _unitdir %{_prefix}/lib/systemd/system}

Name:           fluxheim
Version:        1.6.35
Release:        1%{?dist}
Summary:        Rust edge gateway for websites, caching, and load balancing
License:        EUPL-1.2
URL:            https://github.com/valkyoth/fluxheim
Source0:        https://github.com/valkyoth/fluxheim/archive/refs/tags/v%{version}/%{name}-%{version}.tar.gz
# Create with:
#   cargo vendor vendor > /tmp/fluxheim-cargo-config.toml
#   tar -czf fluxheim-%{version}-vendor.tar.gz vendor
Source1:        %{name}-%{version}-vendor.tar.gz
Source2:        fluxheim.tmpfiles
Source3:        fluxheim.service
Source4:        fluxheim.env
Source5:        fluxheim.sysusers
Source6:        actalis-eab.conf
Source7:        fluxheim-acme.service
Source8:        fluxheim-acme.timer
Source9:        actalis-eab-acme.conf

ExclusiveArch:  x86_64 aarch64

BuildRequires:  cargo
BuildRequires:  rust >= %{rust_min_version}
BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  perl
BuildRequires:  tar
%if 0%{?suse_version}
BuildRequires:  pkgconfig
Requires(pre):   shadow
%else
BuildRequires:  pkgconf-pkg-config
Requires(pre):   shadow-utils
%endif

Requires:       ca-certificates

%description
Fluxheim is a modular Rust edge gateway for websites, applications, caching,
and load balancing. The 1.6 line is the staged Pingora-exit line while keeping
the packaged native build on the full production feature set: proxy, static web
serving, cache, load balancing, managed ACME, Prometheus metrics,
OpenTelemetry export support, GeoIP policy, stream proxying, and PHP-FPM
support.

This spec builds from vendored Cargo dependencies and uses Cargo offline mode.
It intentionally does not download crates during the RPM build.

%prep
%autosetup -n %{name}-%{version}
tar -xzf %{SOURCE1}
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"

[net]
offline = true
EOF

%build
scripts/validate-features.sh "%{fluxheim_features}"
export CARGO_HOME=%{_builddir}/%{name}-cargo-home
export RUSTFLAGS="%{?build_rustflags}"
cargo build --release --locked --offline --no-default-features --features "%{fluxheim_features}" --bin fluxheim --bin fluxheim-acme

%install
install -Dm0755 target/release/fluxheim %{buildroot}%{_bindir}/fluxheim
install -Dm0755 target/release/fluxheim-acme %{buildroot}%{_bindir}/fluxheim-acme
install -Dm0644 packaging/default/fluxheim.toml %{buildroot}%{_sysconfdir}/fluxheim/fluxheim.toml
install -Dm0644 packaging/default/index.html %{buildroot}/srv/fluxheim/index.html
install -Dm0644 %{SOURCE2} %{buildroot}%{_tmpfilesdir}/fluxheim.conf
install -Dm0644 %{SOURCE3} %{buildroot}%{_unitdir}/fluxheim.service
install -Dm0644 %{SOURCE4} %{buildroot}%{_sysconfdir}/sysconfig/fluxheim
install -Dm0644 %{SOURCE5} %{buildroot}%{_sysusersdir}/fluxheim.conf
install -Dm0644 %{SOURCE6} %{buildroot}%{_docdir}/fluxheim/systemd/actalis-eab.conf
install -Dm0644 %{SOURCE7} %{buildroot}%{_unitdir}/fluxheim-acme.service
install -Dm0644 %{SOURCE8} %{buildroot}%{_unitdir}/fluxheim-acme.timer
install -Dm0644 %{SOURCE9} %{buildroot}%{_docdir}/fluxheim/systemd/actalis-eab-acme.conf

install -d -m0755 %{buildroot}%{_sysconfdir}/fluxheim/conf.d
install -d -m0755 %{buildroot}%{_sysconfdir}/fluxheim/tls
install -d -m0700 %{buildroot}%{_sysconfdir}/fluxheim/secrets
install -d -m0750 %{buildroot}%{_localstatedir}/lib/fluxheim
install -d -m0750 %{buildroot}%{_localstatedir}/cache/fluxheim
install -d -m0750 %{buildroot}%{_localstatedir}/log/fluxheim

%check
%if %{with tests}
export CARGO_HOME=%{_builddir}/%{name}-cargo-home
export RUSTFLAGS="%{?build_rustflags}"
cargo test --locked --offline --no-default-features --features "%{fluxheim_features}"
%endif

%pre
getent group fluxheim >/dev/null || groupadd -r fluxheim
getent passwd fluxheim >/dev/null || \
    useradd -r -g fluxheim -d %{_localstatedir}/lib/fluxheim \
        -s /sbin/nologin -c "Fluxheim service user" fluxheim
exit 0

%post
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers fluxheim.conf || :
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create fluxheim.conf || :
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi

%files
%license LICENSE
%doc README.md CHANGELOG.md ROADMAP.md release-notes docs examples
%{_docdir}/fluxheim/systemd/actalis-eab.conf
%{_docdir}/fluxheim/systemd/actalis-eab-acme.conf
%{_bindir}/fluxheim
%{_bindir}/fluxheim-acme
%{_tmpfilesdir}/fluxheim.conf
%{_sysusersdir}/fluxheim.conf
%{_unitdir}/fluxheim.service
%{_unitdir}/fluxheim-acme.service
%{_unitdir}/fluxheim-acme.timer
%dir %{_sysconfdir}/fluxheim
%dir %{_sysconfdir}/fluxheim/conf.d
%dir %{_sysconfdir}/fluxheim/tls
%dir %attr(0700,root,root) %{_sysconfdir}/fluxheim/secrets
%config(noreplace) %{_sysconfdir}/fluxheim/fluxheim.toml
%config(noreplace) %{_sysconfdir}/sysconfig/fluxheim
%dir %attr(0750,fluxheim,fluxheim) %{_localstatedir}/lib/fluxheim
%dir %attr(0750,fluxheim,fluxheim) %{_localstatedir}/cache/fluxheim
%dir %attr(0750,fluxheim,fluxheim) %{_localstatedir}/log/fluxheim
%dir %attr(0755,fluxheim,fluxheim) /srv/fluxheim
%config(noreplace) %attr(0644,fluxheim,fluxheim) /srv/fluxheim/index.html

%changelog
* Mon Jun 29 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.35-1
- Start the Pingora-free runtime stabilization release after the 1.6.34 proof
  release.
- Fix the version-bump helper so semantic versions beginning with digits do not
  get interpreted as regex backreferences during workspace version updates.
- Begin the first-party secret-memory migration audit from direct zeroize APIs
  toward Fluxheim's sanitization crate where practical.
- Move legacy auth subrequest forwarded-header secret storage onto
  sanitization::SecretString.
- Move native auth-request forwarded and allowed response-header secret storage
  onto sanitization::SecretString.
- Move native metrics bearer-token storage and comparison candidates onto
  sanitization secret containers.
- Move managed load-balancer cookie HMAC key-ring clearing onto
  sanitization::SecureSanitize.
- Move HTTP discovery bearer-token storage and Authorization header assembly
  onto sanitization::SecretString.
- Move native OpenBao disk-cache encryption token storage onto
  sanitization::SecretString.
- Align the legacy cache OpenBao token holder with the native cache token
  migration.
- Move admin bearer-token digest clearing onto an explicit
  sanitization::SecureSanitize drop implementation.
- Update release guidance to prefer sanitization::ct for constant-time secret
  comparisons and remove an unused zeroize derive feature from the
  load-balancer crate.
- Move native upstream TLS client private-key PEM buffers for rustls and
  OpenSSL backends onto sanitization::SecretVec.
- Move stream-proxy upstream TLS client private-key PEM buffers for rustls and
  OpenSSL backends onto sanitization::SecretVec.
- Keep RPM, container, dependency-policy, native-runtime, and smoke-test gates
  as blocking evidence during stabilization.

* Mon Jun 29 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.34-1
- Remove the final Pingora compatibility runtime from normal Fluxheim builds
  after the native proxy-cache parity release.
- Tighten release gates so default, full, cache-edge, proxy-edge,
  load-balancer-edge, PHP, privacy, source, RPM, and container builds prove
  they no longer compile Pingora crates.
- Make the historical pingora-compat feature marker inert so explicit legacy
  build invocations cannot re-enable removed Pingora source paths.
- Wire native admin cache purge, cache object lookup, stale disk-cache purge,
  and live load-balancer stats/mutation handlers to Fluxheim-owned runtime
  handles.
- Align native cache-key/cache-lookup route-scope previews, HEAD bypass
  reporting, and disk purge activity metrics with the cache runtime.
- Harden native admin cache-preview/cache-purge host normalization, route-regex
  preview matching, stale disk-purge lock scope, and cache API exports.
- Refactor native route-proxy builders to use typed construction contexts for
  release-profile clippy compliance.
- Keep compatibility notes focused on native HTTP/1, HTTP/2, TLS, WebSocket,
  cache, load-balancer, admin, metrics, and background-service coverage.

* Sun Jun 28 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.33-1
- Add native proxy-cache memory, filesystem disk, storage-bin, local-key
  encrypted disk, OpenBao Transit encrypted disk, tiered memory+disk, peer-fill,
  stale, range, slice, lock, predictor, min-use, and load-balanced cache parity.
- Harden native cache admin purge parity so exact, bulk, prefix, tag, wildcard,
  route-scope, and stale purges invalidate live native memory state as well as
  disk state.
- Extend proxy-cache smoke coverage for native memory/disk purge, tiering,
  encryption, OpenBao, peer-fill, range, slice, stale, metrics, and restart
  behavior.

* Wed Jun 24 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.31-1
- Move cache/PHP native integration primitives into Fluxheim-owned crates and
  tighten native cutover evidence for cache and PHP blockers.
- Add native route/vhost static memory-cache coverage, host-router manifest
  evidence, and native metrics handler bearer-token support.
- Harden native rate-limit sharding, static-web encoded path handling, and
  weighted upstream failover regression coverage.

* Tue Jun 23 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.30-1
- Move plaintext native upstream HTTP/2, TLS ALPN H2 origins, and explicit
  opt-in h2c Upgrade compatibility into the native HTTP/1 proxy path.
- Add native upstream H2 pooling, keepalive pings, bounded stream-slot waits,
  failover tests, and live H2 origin coverage.
- Harden h2c fallback retry boundaries and switch h2c HTTP2-Settings encoding
  to base64-ng 1.2.2's fixed-input infallible encoder.

* Tue Jun 23 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.29-1
- Move inherited compression, header-policy behavior, forwarded-header
  ownership, access policy, concurrency, rate limiting, gRPC validation,
  ACME HTTP-01 local challenge serving, auth-request, and safe-method traffic
  mirroring onto the native HTTP/1 proxy path.
- Add native downstream request/response timeout policy and native upstream
  TCP socket option parity for receive buffers, DSCP, keepalive, and supported
  TCP user-timeout.
- Harden trusted forwarded-chain parsing, native rate-limit eviction, native
  ACME token loading, mirror recursion markers, and auth-request response
  handling during the Pingora-exit migration.

* Sun Jun 21 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.28-1
- Add native route-level response compression for gzip, Brotli, and zstd.
- Honor Accept-Encoding q-values when selecting native route compression
  algorithms.
- Add native proxy custom error-page serving for upstream failures.
- Harden custom error-page responses to close the downstream connection.
- Fall back to built-in proxy error responses when configured error-page files
  are too large.
- Harden redirect {query} path expansion against double-encoded traversal.
- Update native runtime cutover evidence isolation and release metadata for
  1.6.28.

* Sun Jun 21 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.27-1
- Add native HTTP/1 route static-web serving backed by fluxheim-web.
- Support native route static ETags, conditionals, ranges, HEAD, cache-control
  metadata, and directory listings.
- Apply route-level native request-header mutation overlays before forwarding
  matched proxy routes upstream.
- Round-robin successful native HTTP/1 proxy requests across multiple static
  upstreams while preserving safe-method failover.
- Apply static proxy.upstream_weights through native weighted round-robin.
- Apply route-level native response rewrites for Location, Refresh, and
  Set-Cookie.
- Harden native static path containment with rooted no-symlink body opens and
  method enforcement for non-GET/HEAD requests.
- Harden native redirect Location validation for encoded and double-encoded
  dot segments and slashes produced by template expansion.
- Keep forwarded-client-IP shortcut ownership on the compatibility path until
  native parity tests cover it.
- Keep health-aware, persistence, priority-group, backup/drain, dynamic
  discovery, and hash-based load-balancer policies on the compatibility path
  while static-upstream round-robin and static weights move native.
- Keep cache, PHP-FPM, auth-request, traffic mirror, compression, and advanced
  load-balancer integrations on the compatibility path until native parity
  tests land.
- Update release metadata for 1.6.27.

* Sun Jun 21 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.26-1
- Continue native route/policy parity with native HTTP/1 route redirect
  actions.
- Support safe native redirect expansion for {uri}, {path}, and {query}.
- Enforce native route request-body limits before forwarding matched requests.
- Apply route-level native response header overlays for supported native route
  proxy responses.
- Harden native redirect Location validation and native proxy candidate
  accounting for redirect-shadowed route proxies.
- Keep richer route policies and proxy integrations on the documented
  compatibility path until their native parity tests are added.

* Sun Jun 21 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.25-1
- Add native HTTP/1 proxy candidate rows to runtime cutover evidence.
- Add the first native HTTP/1 route-proxy execution primitive for exact,
  prefix, and fallback routes with prefix strip/rewrite support.
- Harden native route-proxy path validation, regex-route cutover reporting,
  candidate-row validation, and route path config validation.
- Re-scope final Pingora dependency deletion to 1.6.28 after remaining native
  policy and rich proxy parity slices.
- Update release metadata for 1.6.25.

* Sat Jun 20 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.24-1
- Promote native HTTP/2 downstream parity to cutover-ready after completing
  the safety-hook proof.
- Join aborted native stream and UDP listener tasks during shutdown.
- Assert zero representative native-runtime blockers in release evidence.
- Keep remaining Pingora runtime dependency removal targeted at 1.6.25 for a
  focused final deletion release.
- Update release metadata for 1.6.24.

* Sat Jun 20 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.23-1
- Cut stream and UDP proxy startup over to Fluxheim-owned native task
  boundaries with the Pingora runtime retained only as a registration adapter.
- Mark config-derived stream and UDP service plans native-ready in cutover
  evidence.
- Update release metadata for 1.6.23.

* Sat Jun 20 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.22-1
- Start the native admin and metrics serving slice of the Pingora-exit line.
- Keep production admin and metrics compatibility conservative while native
  handler parity tests are introduced.
- Harden native background task handle lifecycle and native cutover evidence
  path handling.
- Update release metadata for 1.6.22.

* Sat Jun 20 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.21-1
- Start the native background-service orchestration slice of the Pingora-exit
  line.
- Keep production listener behavior on the compatibility runtime while
  Fluxheim-owned task supervision is split out.
- Update release metadata for 1.6.21.

* Sat Jun 20 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.20-1
- Re-scope the final Pingora runtime-removal work into measured native cutover
  slices instead of forcing an unsafe production switch.
- Keep the remaining Pingora compatibility dependency exceptions active until
  the 1.6.25 final proof target.
- Wrap OpenSSL downstream private-key PEM buffers in the Fluxheim
  `sanitization` crate before OpenSSL key import.
- Update release metadata for the 1.6.20 native runtime cutover contract.

* Fri Jun 19 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.19-1
- Isolate the remaining Pingora compatibility runtime behind an explicit
  `pingora-compat` feature boundary.
- Stop native TLS-only web builds from enabling Pingora TLS backend features
  when the compatibility runtime is not selected.
- Extend the Pingora dependency policy with a native web+TLS cargo-tree proof.

* Fri Jun 19 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.18-1
- Continue the Pingora-exit release line toward normal-profile proxy/cache/pool
  dependency removal.
- Keep the load-balancer crate Pingora-free while preparing the next native
  runtime cutover slice.

* Fri Jun 19 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.17-1
- Remove the direct Pingora dependency from the `fluxheim-load-balancer` crate.
- Replace Pingora HTTP health sessions with Fluxheim-owned HTTP/1.1 and h2/gRPC
  health probes.

* Fri Jun 19 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.16-1
- Tighten native HTTP/1.1 proxy cutover eligibility for unsupported route
  transforms, vhost routing policy, and proxy policy layers.
- Keep production traffic on the Pingora compatibility adapter until the
  native path implements those semantics explicitly.

* Thu Jun 18 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.15-1
- Continue the Pingora-exit line with native HTTP/2 upstream client parity
  primitives in `fluxheim-server`.
- Add h2 tests for gRPC-style trailers, response bounds, and request
  flow-control write timeouts while keeping production HTTP/2 cutover gated.

* Thu Jun 18 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.14-1
- Continue the Pingora-exit line with native rustls upstream TLS support for
  the staged HTTP/1.1 proxy path.
- Add native HTTPS upstream proxy tests with generated CA/SAN certificates and
  keep unsupported OpenSSL-native upstream TLS on the compatibility path.

* Thu Jun 18 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.13-1
- Continue the Pingora-exit line with native HTTP/1.1 upstream connection
  pooling for safe content-length/no-body responses.
- Honor upstream idle timeout for the native HTTP/1.1 pool and keep unsupported
  proxy features on the Pingora compatibility path.

* Thu Jun 18 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.12-1
- Continue the Pingora-exit line with native HTTP/2 response-write lifetime
  hardening, explicit h2 response capacity handling, and trailer parity tests.
- Refresh non-Pingora dependency patches while keeping Pingora pinned at 0.8.0.

* Wed Jun 17 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.11-1
- Continue the Pingora-exit line with a native HTTP/2 preview gate and focused
  h2 stack probe in fluxheim-server.
- Add HTTP/2 safety-hook inventory, request-boundary tests, URI-limit parity,
  request-body flow-control release, and slow-body timeout coverage.
- Add real downstream HTTP/1.0 socket tests for hostless requests, default
  close behavior, and explicit keep-alive.

* Wed Jun 17 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.10-1
- Continue the Pingora-exit line with a staged native HTTP/1 upstream client
  and plain static-upstream proxy foundation.
- Add native proxy candidate inventory and real socket proxy smoke coverage.
- Harden native upstream response body limits and add Fluxheim-owned Via /
  X-Forwarded-For header parity with privacy-mode suppression.

* Wed Jun 17 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.9-1
- Continue the Pingora-exit line with a staged native HTTP/1 connection,
  listener, and static-file serving boundary.
- Map server request limits into native HTTP/1 policy and add real socket tests
  for keep-alive, bodies, static files, HEAD framing, and directory listings.
- Harden native HTTP/1 slow-client handling, connection caps, runtime-owned
  Date/Content-Length/Connection framing, static 500 bodies, and buffer guards.

* Wed Jun 17 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.8-1
- Continue the Pingora-exit line with Fluxheim-owned HTTP/1 parser foundations.
- Add bounded native HTTP/1 request-head, response-head, request-target,
  connection, body-framing, and chunked-body parser helpers in fluxheim-protocol.
- Harden the native HTTP/1 parser against authority userinfo, obs-text,
  duplicate Content-Length fields, and unbounded chunked body defaults.

* Tue Jun 16 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.7-1
- Continue the Pingora-exit line with Fluxheim-owned server plan boundaries.
- Move listener inventory, service intent, background-task intent, process
  settings, downstream HTTP/2 policy, PROXY protocol listener policy, and
  admin control socket planning into fluxheim-server.
- Harden private Unix listener setup with a temporary private umask and
  fd-based permission handling.

* Tue Jun 16 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.6-1
- Continue the Pingora-exit line with the dedicated fluxheim-tls crate.
- Move downstream TLS listener planning, SNI certificate selection, ALPN and
  cipher policy helpers, and rustls/OpenSSL provider checks into fluxheim-tls.
- Harden PROXY protocol v2 parsing and trusted-source CIDR validation.
- Fix TLS feature gates for default, OpenSSL-only, and OpenSSL-FIPS builds.

* Tue Jun 16 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.5-1
- Continue the Pingora-exit line with the first dedicated header-policy crate
  boundary.
- Move pure header rewrite, forwarded-client-IP, hop-by-hop, and repeated
  header joining helpers into fluxheim-headers.
- Move downstream PROXY protocol parsers into fluxheim-protocol and harden
  trusted-source CIDR validation.
- Broaden Pingora boundary policy checks and gate client-IP parsing helpers in
  privacy-mode builds.

* Mon Jun 15 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.4-1
- Continue the Pingora-exit line with Fluxheim-owned background runtime
  primitives in fluxheim-runtime.
- Move OTLP metrics export and certificate reload control socket handling into
  the Fluxheim background task lifecycle.
- Move self-healing snapshot runtime state into fluxheim-snapshot.
- Harden reload socket concurrency, shared timeout bounds, and HTTP discovery
  embedded-IPv4 filtering.

* Mon Jun 15 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.3-1
- Continue the Pingora-exit line with the fluxheim-stream crate.
- Move stream upstream selection, source policy, DNS guards, byte accounting,
  copy-loop limits, and PROXY protocol parsing/writing into fluxheim-stream.
- Keep the root stream adapter as the temporary Pingora service-registration
  and TLS connector boundary until later runtime cutovers.

* Sun Jun 14 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.2-1
- Continue the Pingora-exit line with cache independence work.
- Move cache key identity, serialized object envelopes, disk cache index
  entries, and disk index management into fluxheim-cache.
- Add and exercise a crate-owned FluxCacheStorage interface for memory, disk,
  storage-bin, disk-backend, and tiered cache storage while keeping the current
  Pingora HTTP runtime adapter.

* Sun Jun 14 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.1-1
- Start the first Pingora-exit implementation release after the 1.6.0
  foundation tag.
- Fix container image workflow handling so load-balancer images build for
  normal v1.6.x tag pushes.
- Remove active pingora-load-balancing usage from full and load-balancer
  image profiles with native backend sets, TCP health checks, and bounded TLS
  TCP health-check handshakes.
- Move load-balancer background service and request-view adapters to the root
  runtime boundary.

* Sun Jun 14 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.6.0-1
- Start the Pingora-exit foundation line with versioned 1.6.0 metadata.
- Add modularity policy validation and a legacy oversized-file exception
  inventory for the staged crate/file split.
- Add runtime-facts and policy-proofs planning docs for typed, redacted
  Fluxheim decision evidence.

* Sun Jun 14 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.23-1
- Add cache origin-protection configuration for route/vhost-scoped
  origin-fill budgets.
- Expose origin-protection rollout in cache status and metrics.
- Include origin-protection state in cache-key/cache-lookup release gates.
- Consolidate cache-fill concurrency limiters so slice-fill, peer-fill, and
  origin-fill budgets share one hardened implementation.

* Sun Jun 14 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.22-1
- Continue cache/load-balancer crate-boundary preparation.
- Move load-balancer persistence key extraction behind a Fluxheim-owned
  request view while keeping the Pingora request adapter at the API boundary.
- Move cache request policy, response admission, storage interface enums, and
  range/slice key component helpers into the cache crate while keeping root
  Pingora adapters.
- Harden UDP beta passive health so local downstream drops do not count as
  upstream failures and rate-limit passive-ejection warning logs.

* Sat Jun 13 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.21-1
- Add UDP beta per-source pressure controls, response-rate limiting, metrics,
  and admin status visibility.
- Keep public UDP exposure explicitly warning-only while the feature remains
  gated behind udp-proxy.

* Sat Jun 13 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.20-1
- Reject ambiguous HTTP/1 request framing with both Transfer-Encoding and
  Content-Length in the vendored request parser.
- Allow provider IPv6 trusted-proxy ranges such as Cloudflare's
  2a06:98c0::/29 after the 1.5.19 config-crate split tightened validation too
  far.

* Fri Jun 12 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.19-1
- Move the Fluxheim-owned load-balancer core into the internal
  crates/fluxheim-load-balancer workspace crate.
- Keep admin, proxy, runtime, RPM, container, feature-profile, and config
  behavior unchanged through root compatibility wiring.
- Preserve the load-balancer edge image/profile while keeping Pingora removal
  as later 1.5.x work.

* Fri Jun 12 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.18-1
- Move configuration schema, parsing, validation, loader logic, and tests into
  the internal crates/fluxheim-config workspace crate.
- Harden downstream HTTP/2 response handling with an absolute response-write
  lifetime bound for HTTP/2 responses.
- Clarify and test that duplicate request header values count toward the
  global request-header count limit before routing.

* Thu Jun 11 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.17-1
- Start the workspace and shared-crate foundation line.
- Add crates/fluxheim-common for shared FluxError/FluxResult and path-safety
  validation while preserving root compatibility adapters.
- Update regex to 1.12.4 and add release-gate checks for compatible
  non-Pingora crate freshness and release metadata alignment.
- Fix the vendored OpenSSL FIPS support build script for Rust 1.96 clippy.
- Keep RPM feature set, binaries, config syntax, and runtime behavior
  unchanged.

* Wed Jun 10 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.16-1
- Start the UDP/GSLB exploration line with a separate beta [udp] config
  namespace, udp-proxy feature gate, and scoped DNS/syslog UDP runtime.
- Add response_timeout_secs for bounded DNS-style upstream waits, drop
  oversized upstream UDP responses, and rate-limit high-volume UDP drop logs.
- Remove the unused beta max_session_secs UDP field before release so it
  cannot be accepted as a silent no-op.
- Keep UDP runtime support out of production profiles until scoped listener
  and session semantics are reviewed.

* Wed Jun 10 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.15-1
- Start the database/protocol-aware health-check line.
- Add bounded Redis PING, MySQL/MariaDB handshake, and PostgreSQL SSLRequest
  active health checks for load-balancer pools.
- Read Redis PONG responses until CRLF within the bounded response cap.
- Document MySQL/MariaDB host-cache max_connect_errors behavior for pre-auth
  handshake probes and the authenticated exec-check alternative.
- Log ACME managed-certificate install recovery failures.
- Keep Redis TLS, MySQL/PostgreSQL authenticated readiness, generic
  send-expect probes, and database proxying as future work.

* Tue Jun 09 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.14-1
- Start the local exec health-check line.
- Add opt-in bounded load-balancer exec checks with absolute allow-listed
  command paths, literal argv, no shell, cleared environment, null stdio, and
  explicit backend context variables.
- Keep agent checks, database protocol probes, arbitrary scripting/Wasm,
  UDP/GSLB, WAF, and VPN/firewall appliance behavior as future work.

* Tue Jun 09 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.13-1
- Start the Fluxheim-owned cache interface line.
- Move cache implementation internals behind FluxCacheStorage and
  FluxHandleHit/FluxHandleMiss while preserving the Pingora HTTP proxy adapter
  and existing cache behavior.
- Harden slice-cache multipart range responses with random MIME boundaries and
  CR/LF stripping for cached upstream Content-Type values.
- Keep privacy-cache as a planned explicit public-asset design only.

* Mon Jun 08 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.12-1
- Start the Fluxheim-native background task registry line.
- Move cache metrics, stale cache purging, ACME renewal, admin watchdog, and
  load-balancer refresh work through the Fluxheim background task adapter while
  preserving startup readiness and graceful shutdown behavior.

* Mon Jun 08 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.11-1
- Start the service-discovery and control-plane integration line.
- Update Prometheus metrics dependencies to remove the protobuf advisory
  suppression while keeping the patched vendored Pingora core.
- Harden downstream HTTP/2 defaults against the HTTP/2 Bomb class.
- Add bounded pull-based HTTP upstream discovery with status, metrics, reload
  classification, request hardening, and a documented example config.

* Sun Jun 07 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.10-1
- Start the runtime backend-set mutation line for authenticated add, remove,
  and update operations through atomic backend-set swaps.

* Sun Jun 07 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.9-1
- Start the restart-persistent load-balancer state line for versioned,
  size-limited, atomically written local runtime state with fail-closed rebuild
  semantics.

* Sun Jun 07 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.8-1
- Expand active health checks with bounded custom request headers, standard
  gRPC checks, exact JSON scalar body matching, and health-derived degraded
  weights.

* Sat Jun 06 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.7-1
- Start the Fluxheim-native load-balancer core line by introducing owned
  backend/backend-set construction and routing static, file, and DNS discovery
  through the Fluxheim model before adapting to the remaining Pingora selector
  boundary.

* Sat Jun 06 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.6-1
- Start the Fluxheim-native stream-proxy runtime line, focused on moving stream
  listener, connect/copy/shutdown, and upstream TLS connector helpers behind
  owned runtime and error boundaries while preserving existing TCP stream proxy
  behavior.
- Harden stream upstream TLS observability and HAProxy PROXY v1 UNKNOWN parsing.

* Fri Jun 05 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.5-1
- Start the Fluxheim-native HTTP/error type boundary line with standard HTTP
  aliases and a typed internal error surface while keeping Pingora adapters at
  runtime boundaries.

* Thu Jun 04 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.4-1
- Remove incomplete BoringSSL and s2n TLS backend support from the supported
  feature/config matrix; keep rustls as the default and OpenSSL as the
  supported alternative for non-FIPS and FIPS/ISO evidence paths.

* Thu Jun 04 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.3-1
- Start the managed affinity-cookie and HA persistence release line; planned
  stop is signed/opaque load-balancer cookie insertion, cookie rotation,
  privacy-mode constraints, and active-active cookie-mirroring design.

* Thu Jun 04 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.2-1
- Start the runtime load-balancer weight-control release line, focused on
  authenticated runtime weight overrides for configured members, audit/status
  visibility, and migration documentation without adding managed cookies,
  cross-node state sync, UDP/GSLB, WAF, VPN/firewall, or scripting surfaces.

* Wed Jun 03 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.1-1
- Stabilize enterprise load-balancer persistence metrics, stale dynamic state
  pruning, local persistence-table cleanup, release smoke coverage, and
  focused load-balancer container/release documentation; preserve explicit
  runtime disable/forced-down actions across dynamic discovery churn.

* Tue Jun 02 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.5.0-1
- Release 1.5.0 enterprise HTTP/TCP load-balancer control-plane line.
- Add focused load-balancer release profile support, runtime member controls,
  local persistence, advanced selection, health/circuit status, and 1.5
  documentation boundaries.

* Sun May 31 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.4.7-1
- Release 1.4.7 TCP stream hardening.
- Add true stream idle timeouts, stream upstream TLS/mTLS controls,
  weighted/drain/backup stream upstream policy, and expanded stream smoke
  coverage.

* Sat May 30 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.4.6-1
- Release 1.4.6 TCP stream proxy foundation.
- Add raw L4 TCP stream routes, round-robin stream upstream selection, bounded
  connect/lifetime/byte/concurrency controls, route-local PROXY protocol
  receive, upstream PROXY protocol send, stream metrics, and graceful drain.

* Fri May 29 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.4.5-1
- Release 1.4.5 bounded GeoIP/Geo-Context policy.
- Add local MMDB MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open dataset support,
  vhost/route country and ASN ACLs, structured access-log Geo fields, and
  bounded GeoIP database loading on Rust 1.96.

* Thu May 28 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.4.4-1
- Release 1.4.4 Apple Silicon macOS Level 1 developer support.
- Add Mac-safe development config, macOS developer smoke coverage, normalized
  release artifact labels for Linux ARM64 and macOS developer binaries, and
  release helper script updates.

* Wed May 27 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.4.3-1
- Release 1.4.3 maintenance architecture: split config loading, shared
  parsers, domain validation, cache/proxy/PHP/TLS/ACME/admin/server/logging
  config, and the large config test module into focused config modules while
  keeping crate::config::* paths and operator-facing behavior stable.

* Wed May 27 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.4.2-1
- Release 1.4.2 maintenance architecture: split proxy runtime domains into
  focused modules for access logs, compression, auth subrequests, traffic
  mirroring, edge policy, route policy, cache API DTOs, proxy-cache helpers,
  path safety, upstream TLS loading, outbound PROXY protocol framing, and
  PHP-FPM process/FastCGI handling.
- Harden traffic-mirror sampling with a process-local salt and keep ACME file
  mode conversion portable across Linux and macOS.

* Tue May 26 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.4.1-1
- Release 1.4.1 proxy operations: regex/method routing, regex capture rewrite
  templates, WebSocket upgrades, auth subrequests, traffic mirroring,
  DNS/file-refreshed upstream pools, structured access-log additions, and the
  read-only ops socket.

* Sat May 23 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.4.0-0.dev
- Start the 1.4 production proxy parity development line.

* Sat May 23 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.3.7-1
- Add managed php-fpm process supervision under the existing php-fpm feature.
- Keep external php-fpm as the default PHP-FPM deployment mode.
- Add managed static/dynamic/ondemand pool knobs, lifecycle limits, slowlog
  controls, and WordPress smoke coverage for both PHP-FPM modes.
- Add managed php-fpm crash respawn, sanitized worker environment, and graceful
  detached child shutdown.

* Sat May 23 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.3.6-1
- FIPS/ISO internal-crypto closure and compliance evidence release.
- Add provider-backed admin auth in FIPS builds, fail-closed managed ACME and
  local cache encryption gates, numeric-loopback-only FIPS telemetry/KMS
  exceptions, and compliance evidence templates.

* Fri May 22 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.3.5-1
- rustls/AWS-LC FIPS-capable candidate release.
- Add rustls FIPS/ISO feature profiles, provider diagnostics, release evidence
  checks, and stricter rustls FIPS runtime validation.

* Thu May 21 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.3.4-1
- OpenSSL FIPS-capable TLS release.
- Add fail-closed FIPS runtime/provider validation, FIPS diagnostics, release
  evidence checks, and sandbox-safe release gate runtime paths.

* Wed May 20 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.3.3-1
- PHP-FPM hardening and production compatibility follow-up.
- Include php-fpm keepalive pooling, safer FastCGI params, PHP cache helpers,
  PHP metrics, RFC response hardening, and updated PHP-FPM application recipes.

* Sat May 16 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.3.2-1
- Start ACME operations and config-tester follow-up.

* Sat May 16 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.3.1-1
- PHP-FPM runtime support and WordPress compatibility follow-up.
- Keep the full RPM on the broad non-PHP production profile; PHP builds remain
  explicit via feature/profile selection.

* Thu May 14 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.3.0-1
- Shared ingress/TLS feature split with focused cache and proxy build profiles.

* Thu May 14 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.2.6-1
- Focused slice-cache follow-up with bounded range composition, suffix/open-ended ranges, and multipart byte-range responses.

* Thu May 14 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.2.5-1
- Focused bounded range-cache follow-up for large proxy-cache objects.

* Wed May 13 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.2.4-1
- Focused distributed cache metadata and peer-fill follow-up.

* Wed May 13 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.2.3-1
- Focused optional disk cache encryption follow-up with local-key AES-GCM and OpenBao Transit support.

* Tue May 12 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.2.2-1
- Focused storage-bin disk cache backend with runtime selection, smoke coverage, pressure stats, and tail-bin reclamation.

* Tue May 12 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.2.1-1
- Focused local/static vhost cache follow-up.

* Tue May 12 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.2.0-1
- Cache-server operations release with observability-enabled native packaging.

* Sat May 09 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.1.0-1
- TLS policy and ACME certificate operations release with modern/intermediate profiles and native renewal support.

* Fri May 08 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.0.0-1
- Stable gateway foundation release with vhosts, TLS/SNI, redirects, static sites, routes, and systemd/RPM packaging.

* Wed May 06 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 0.5.0-1
- Initial RPM packaging spec for the basic-sites preview.
