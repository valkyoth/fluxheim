%global fluxheim_features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
%global rust_min_version 1.96
%bcond_without tests

%{!?_tmpfilesdir:%global _tmpfilesdir %{_prefix}/lib/tmpfiles.d}
%{!?_sysusersdir:%global _sysusersdir %{_prefix}/lib/sysusers.d}
%{!?_unitdir:%global _unitdir %{_prefix}/lib/systemd/system}

Name:           fluxheim
Version:        1.5.14
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
and load balancing. The 1.5 line adds the enterprise HTTP/TCP load-balancer
control-plane track while keeping the packaged native build on the full
production feature set: proxy, static web serving, cache, load balancing,
managed ACME, Prometheus metrics, OpenTelemetry export support, GeoIP policy,
stream proxying, and PHP-FPM support.

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
