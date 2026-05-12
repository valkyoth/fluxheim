%global fluxheim_features profile-observability,acme-client
%global rust_min_version 1.95
%bcond_without tests

%{!?_tmpfilesdir:%global _tmpfilesdir %{_prefix}/lib/tmpfiles.d}
%{!?_sysusersdir:%global _sysusersdir %{_prefix}/lib/sysusers.d}
%{!?_unitdir:%global _unitdir %{_prefix}/lib/systemd/system}

Name:           fluxheim
Version:        1.2.2
Release:        1%{?dist}
Summary:        Modular Pingora-based reverse proxy and static web server
License:        EUPL-1.2
URL:            https://github.com/valkyoth/fluxheim
Source0:        https://github.com/valkyoth/fluxheim/archive/refs/tags/v%{version}/%{name}-%{version}.tar.gz
# Create with:
#   cargo vendor vendor > /tmp/fluxheim-cargo-config.toml
#   tar -czf fluxheim-1.2.2-vendor.tar.gz vendor
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
Fluxheim is a modular Rust edge server built on Pingora. The 1.2 release builds
on the stable gateway and ACME foundation with cache-server operations,
Prometheus metrics, and OpenTelemetry export support compiled into the packaged
native build.

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
cargo build --release --locked --offline --no-default-features --features "%{fluxheim_features}"

%install
install -Dm0755 target/release/fluxheim %{buildroot}%{_bindir}/fluxheim
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
%doc README.md CHANGELOG.md ROADMAP.md RELEASE_NOTES_*.md docs examples
%{_docdir}/fluxheim/systemd/actalis-eab.conf
%{_docdir}/fluxheim/systemd/actalis-eab-acme.conf
%{_bindir}/fluxheim
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
* Tue May 12 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.2.2-1
- Start focused storage-bin disk cache follow-up.

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
