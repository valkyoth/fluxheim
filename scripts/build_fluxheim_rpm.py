#!/usr/bin/env python3
"""Build a binary Fluxheim RPM inside a disposable Linux container.

This is a convenience helper for local package testing. The release-grade RPM
source of truth remains packaging/rpm/fluxheim.spec.
"""

from __future__ import annotations

import argparse
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


OS_CONTAINERS = {
    "fedora-44": "registry.fedoraproject.org/fedora:44",
    "opensuse-tumbleweed": "registry.opensuse.org/opensuse/tumbleweed:latest",
    "opensuse-leap-15": "registry.opensuse.org/opensuse/leap:15.6",
    "opensuse-leap-16": "registry.opensuse.org/opensuse/leap:16.0",
    "ubi-9": "registry.access.redhat.com/ubi9/ubi:latest",
    "ubi-10": "registry.access.redhat.com/ubi10/ubi:latest",
}

SAFE_VERSION_TAG = re.compile(r"^(latest|v?[0-9]+(?:\.[0-9A-Za-z_+]+)*)$")
SAFE_RPM_RELEASE = re.compile(r"^[0-9][0-9A-Za-z._+~]*$")


def get_container_tool(preferred: str | None) -> str:
    if preferred:
        if shutil.which(preferred):
            return preferred
        raise SystemExit(f"error: requested container tool is not installed: {preferred}")
    for tool in ("podman", "docker"):
        if shutil.which(tool):
            return tool
    raise SystemExit("error: neither podman nor docker is installed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a binary Fluxheim RPM in a container."
    )
    parser.add_argument(
        "version_tag",
        nargs="?",
        default="latest",
        help="Fluxheim tag version, for example 0.5.0, v0.5.0, or latest",
    )
    parser.add_argument(
        "build_type",
        nargs="?",
        default="generic",
        choices=["generic", "native"],
        help="Use 'native' to build with RUSTFLAGS='-C target-cpu=native'.",
    )
    parser.add_argument(
        "--target",
        choices=sorted(OS_CONTAINERS),
        help="Build target container. If omitted, the script prompts interactively.",
    )
    parser.add_argument(
        "--container-tool",
        choices=["podman", "docker"],
        help="Container runtime to use. Defaults to podman, then docker.",
    )
    parser.add_argument(
        "--rpm-release",
        default="1",
        help="RPM release value. Use 2, 3, etc. when rebuilding the same version for a repo.",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List supported build targets and exit.",
    )
    return parser.parse_args()


def print_targets() -> None:
    for name, image in OS_CONTAINERS.items():
        print(f"{name}: {image}")


def run_container_build(
    container_tool: str,
    work_dir: Path,
    container_image: str,
    version_tag: str,
    build_type: str,
    rpm_release: str,
) -> None:
    print(
        "Executing: "
        + shlex.join(
            [
                container_tool,
                "run",
                "--rm",
                "-v",
                f"{work_dir}:/workspace:Z",
                container_image,
                "bash",
                "/workspace/build_in_container.sh",
                version_tag,
                build_type,
                rpm_release,
            ]
        )
    )
    subprocess.run(
        [
            container_tool,
            "run",
            "--rm",
            "-v",
            f"{work_dir}:/workspace:Z",
            container_image,
            "bash",
            "/workspace/build_in_container.sh",
            version_tag,
            build_type,
            rpm_release,
        ],
        check=True,
    )


def choose_target(target: str | None) -> tuple[str, str]:
    if target:
        return target, OS_CONTAINERS[target]

    print("Available build targets:")
    target_names = sorted(OS_CONTAINERS)
    for index, name in enumerate(target_names, 1):
        print(f"{index}. {name} ({OS_CONTAINERS[name]})")

    while True:
        choice = input("Select the target to build for (number): ").strip()
        try:
            selected = target_names[int(choice) - 1]
            return selected, OS_CONTAINERS[selected]
        except (ValueError, IndexError):
            print("Please enter a valid target number.")


def validate_version_tag(version_tag: str) -> None:
    if not SAFE_VERSION_TAG.fullmatch(version_tag):
        raise SystemExit(
            "error: version_tag must be 'latest' or a simple release version such as 1.0.0 or v1.0.0"
        )


def validate_rpm_release(rpm_release: str) -> None:
    if not SAFE_RPM_RELEASE.fullmatch(rpm_release):
        raise SystemExit(
            "error: --rpm-release must start with a digit and contain only RPM-safe letters, digits, '.', '_', '+', or '~'"
        )


def generate_build_script(script_path: Path) -> None:
    script_content = r"""#!/usr/bin/env bash
set -euo pipefail

TAG="$1"
BUILD_TYPE="$2"
RPM_RELEASE="$3"
WORKSPACE="/workspace"
REPO_URL="https://github.com/valkyoth/fluxheim.git"

echo "--- Installing dependencies ---"
if command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive in ca-certificates curl git-core rpm-build gcc gcc-c++ make cmake pkgconf-pkg-config perl tar gzip
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl git rpm-build gcc gcc-c++ make cmake pkgconf-pkg-config perl tar gzip
elif command -v microdnf >/dev/null 2>&1; then
    microdnf install -y ca-certificates curl git rpm-build gcc gcc-c++ make cmake pkgconf-pkg-config perl tar gzip
elif command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y ca-certificates curl git rpm gcc g++ make cmake pkg-config perl tar gzip
else
    echo "unsupported package manager" >&2
    exit 1
fi

echo "--- Installing Rust via rustup ---"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
export PATH="${HOME}/.cargo/bin:${PATH}"

echo "--- Cloning Fluxheim ---"
cd "$WORKSPACE"
git clone --depth 1 "$REPO_URL" repo
cd repo

if [ "$TAG" != "latest" ]; then
    git fetch --depth 1 origin "refs/tags/${TAG}:refs/tags/${TAG}" || true
    if [[ "$TAG" != v* ]]; then
        git fetch --depth 1 origin "refs/tags/v${TAG}:refs/tags/v${TAG}" || true
        git checkout "v${TAG}" 2>/dev/null || git checkout "$TAG"
    else
        git checkout "$TAG"
    fi
fi

echo "--- Building Fluxheim ---"
RPM_SUFFIX=""
if [ "$BUILD_TYPE" = "native" ]; then
    echo "using target-cpu=native"
    export RUSTFLAGS="-C target-cpu=native"
    RPM_SUFFIX=".native"
fi
cargo build --release --locked

echo "--- Staging files ---"
INSTALL_ROOT="${WORKSPACE}/install_root"
mkdir -p \
    "${INSTALL_ROOT}/usr/bin" \
    "${INSTALL_ROOT}/usr/lib/tmpfiles.d" \
    "${INSTALL_ROOT}/usr/lib/sysusers.d" \
    "${INSTALL_ROOT}/usr/lib/systemd/system" \
    "${INSTALL_ROOT}/usr/share/doc/fluxheim" \
    "${INSTALL_ROOT}/usr/share/licenses/fluxheim" \
    "${INSTALL_ROOT}/etc/fluxheim/conf.d" \
    "${INSTALL_ROOT}/etc/fluxheim/tls" \
    "${INSTALL_ROOT}/etc/sysconfig" \
    "${INSTALL_ROOT}/srv/fluxheim" \
    "${INSTALL_ROOT}/var/lib/fluxheim" \
    "${INSTALL_ROOT}/var/cache/fluxheim" \
    "${INSTALL_ROOT}/var/log/fluxheim"

install -Dm0755 target/release/fluxheim "${INSTALL_ROOT}/usr/bin/fluxheim"
install -Dm0644 packaging/default/fluxheim.toml "${INSTALL_ROOT}/etc/fluxheim/fluxheim.toml"
install -Dm0644 packaging/default/index.html "${INSTALL_ROOT}/srv/fluxheim/index.html"
install -Dm0644 packaging/rpm/fluxheim.tmpfiles "${INSTALL_ROOT}/usr/lib/tmpfiles.d/fluxheim.conf"
install -Dm0644 packaging/systemd/fluxheim.service "${INSTALL_ROOT}/usr/lib/systemd/system/fluxheim.service"
install -Dm0644 packaging/systemd/fluxheim.env "${INSTALL_ROOT}/etc/sysconfig/fluxheim"
install -Dm0644 packaging/systemd/fluxheim.sysusers "${INSTALL_ROOT}/usr/lib/sysusers.d/fluxheim.conf"
install -Dm0644 LICENSE "${INSTALL_ROOT}/usr/share/licenses/fluxheim/LICENSE"
for doc in README.md CHANGELOG.md ROADMAP.md SECURITY.md; do
    if [ -f "$doc" ]; then
        install -Dm0644 "$doc" "${INSTALL_ROOT}/usr/share/doc/fluxheim/$doc"
    fi
done

echo "--- Generating binary RPM spec ---"
RPMBUILD_ROOT="${WORKSPACE}/rpmbuild"
mkdir -p "${RPMBUILD_ROOT}/"{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

PACKAGE_NAME="fluxheim"
VERSION="${TAG#v}"
CONFLICTS_LINE=""
if [ "$VERSION" = "latest" ]; then
    PACKAGE_NAME="fluxheim-unstable"
    VERSION="$(date -u +%Y%m%d)"
    CONFLICTS_LINE="Conflicts:      fluxheim"
fi

SPEC_PATH="${RPMBUILD_ROOT}/SPECS/fluxheim.spec"
cat > "$SPEC_PATH" <<SPEC_EOF
Name:           ${PACKAGE_NAME}
Version:        ${VERSION}
Release:        ${RPM_RELEASE}${RPM_SUFFIX}%{?dist}
Summary:        Memory-safe edge server and reverse proxy built on Pingora
License:        EUPL-1.2
URL:            https://github.com/valkyoth/fluxheim
${CONFLICTS_LINE}

%description
Fluxheim is a memory-safe edge server and reverse proxy built on Pingora.
This binary RPM was generated by scripts/build_fluxheim_rpm.py for local
installation testing.

%pre
getent group fluxheim >/dev/null || groupadd -r fluxheim
getent passwd fluxheim >/dev/null || \\
    useradd -r -g fluxheim -d /var/lib/fluxheim \\
        -s /sbin/nologin -c "Fluxheim service user" fluxheim
exit 0

%post
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/fluxheim.conf || :
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/fluxheim.conf || :
else
    chown fluxheim:fluxheim /var/lib/fluxheim /var/cache/fluxheim /var/log/fluxheim /srv/fluxheim /srv/fluxheim/index.html || :
    chmod 0750 /var/lib/fluxheim /var/cache/fluxheim /var/log/fluxheim || :
    chmod 0755 /srv/fluxheim || :
    chmod 0644 /srv/fluxheim/index.html || :
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi

%prep

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a "${INSTALL_ROOT}/." %{buildroot}/

%files
%license /usr/share/licenses/fluxheim/LICENSE
%doc /usr/share/doc/fluxheim/*
/usr/bin/fluxheim
/usr/lib/tmpfiles.d/fluxheim.conf
/usr/lib/sysusers.d/fluxheim.conf
/usr/lib/systemd/system/fluxheim.service
%dir /etc/fluxheim
%dir /etc/fluxheim/conf.d
%dir /etc/fluxheim/tls
%config(noreplace) /etc/fluxheim/fluxheim.toml
%config(noreplace) /etc/sysconfig/fluxheim
%dir /var/lib/fluxheim
%dir /var/cache/fluxheim
%dir /var/log/fluxheim
%dir /srv/fluxheim
%config(noreplace) /srv/fluxheim/index.html
SPEC_EOF

echo "--- Building RPM ---"
rpmbuild --define "_topdir ${RPMBUILD_ROOT}" --buildroot "${RPMBUILD_ROOT}/BUILDROOT" -bb "$SPEC_PATH"

echo "--- Copying RPM out ---"
find "${RPMBUILD_ROOT}/RPMS" -name "*.rpm" -exec cp {} "$WORKSPACE/" \;
"""
    script_path.write_text(script_content, encoding="utf-8")


def main() -> int:
    args = parse_args()
    if args.list_targets:
        print_targets()
        return 0

    validate_version_tag(args.version_tag)
    validate_rpm_release(args.rpm_release)
    target_name, container_image = choose_target(args.target)
    container_tool = get_container_tool(args.container_tool)

    print(f"Selected target: {target_name} ({container_image})")
    print(f"Version: {args.version_tag}")
    print(f"RPM release: {args.rpm_release}")
    print(f"Build type: {args.build_type}")
    print(f"Container tool: {container_tool}")

    output_dir = Path.cwd().resolve()
    with tempfile.TemporaryDirectory(prefix="fluxheim-rpm-") as tmp:
        work_dir = Path(tmp)
        build_script_path = work_dir / "build_in_container.sh"
        generate_build_script(build_script_path)
        build_script_path.chmod(0o755)

        run_container_build(
            container_tool,
            work_dir,
            container_image,
            args.version_tag,
            args.build_type,
            args.rpm_release,
        )

        rpms = sorted(work_dir.glob("*.rpm"))
        if not rpms:
            raise SystemExit("error: no RPM files were produced")

        for rpm in rpms:
            destination = output_dir / rpm.name
            shutil.copy2(rpm, destination)
            print(f"Created: {destination}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
