%global fluxheim_features profile-core
%global rust_min_version 1.95
%bcond_without tests

%{!?_tmpfilesdir:%global _tmpfilesdir %{_prefix}/lib/tmpfiles.d}
%{!?_sysusersdir:%global _sysusersdir %{_prefix}/lib/sysusers.d}
%{!?_unitdir:%global _unitdir %{_prefix}/lib/systemd/system}

Name:           fluxheim
Version:        1.0.0
Release:        1%{?dist}
Summary:        Modular Pingora-based reverse proxy and static web server
License:        EUPL-1.2
URL:            https://github.com/valkyoth/fluxheim
Source0:        https://github.com/valkyoth/fluxheim/archive/refs/tags/v%{version}/%{name}-%{version}.tar.gz
# Create with:
#   cargo vendor vendor > /tmp/fluxheim-cargo-config.toml
#   tar -czf fluxheim-1.0.0-vendor.tar.gz vendor
Source1:        %{name}-%{version}-vendor.tar.gz
Source2:        fluxheim.tmpfiles
Source3:        fluxheim.service
Source4:        fluxheim.env
Source5:        fluxheim.sysusers

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
Fluxheim is a modular Rust edge server built on Pingora. The 1.0 release is the
gateway foundation for static website hosting, vhost routing, HTTP to HTTPS
redirects, static TLS certificates with SNI, secure header policy, route-level
proxy/static/redirect behavior, and native systemd deployment.

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

install -d -m0755 %{buildroot}%{_sysconfdir}/fluxheim/conf.d
install -d -m0755 %{buildroot}%{_sysconfdir}/fluxheim/tls
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
%doc README.md CHANGELOG.md ROADMAP.md RELEASE_NOTES_1.0.0.md docs examples
%{_bindir}/fluxheim
%{_tmpfilesdir}/fluxheim.conf
%{_sysusersdir}/fluxheim.conf
%{_unitdir}/fluxheim.service
%dir %{_sysconfdir}/fluxheim
%dir %{_sysconfdir}/fluxheim/conf.d
%dir %{_sysconfdir}/fluxheim/tls
%config(noreplace) %{_sysconfdir}/fluxheim/fluxheim.toml
%config(noreplace) %{_sysconfdir}/sysconfig/fluxheim
%dir %attr(0750,fluxheim,fluxheim) %{_localstatedir}/lib/fluxheim
%dir %attr(0750,fluxheim,fluxheim) %{_localstatedir}/cache/fluxheim
%dir %attr(0750,fluxheim,fluxheim) %{_localstatedir}/log/fluxheim
%dir %attr(0755,fluxheim,fluxheim) /srv/fluxheim
%config(noreplace) %attr(0644,fluxheim,fluxheim) /srv/fluxheim/index.html

%changelog
* Fri May 08 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 1.0.0-1
- Stable gateway foundation release with vhosts, TLS/SNI, redirects, static sites, routes, and systemd/RPM packaging.

* Wed May 06 2026 Fluxheim Maintainers <1921261+eldryoth@users.noreply.github.com> - 0.5.0-1
- Initial RPM packaging spec for the basic-sites preview.
