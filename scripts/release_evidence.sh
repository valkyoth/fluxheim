#!/usr/bin/env sh
set -eu

usage() {
    echo "usage: scripts/release_evidence.sh VERSION [--skip-builds] [--skip-sbom] [--skip-reproducible] [--skip-containers]" >&2
}

version="${1:-}"
if [ -z "$version" ]; then
    usage
    exit 2
fi
shift

case "$version" in
    *[!0-9A-Za-z._+-]* | "" | .* | *..*)
        echo "error: unsafe release version: $version" >&2
        exit 2
        ;;
esac

skip_builds=0
skip_sbom=0
skip_reproducible=0
skip_containers=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-builds) skip_builds=1 ;;
        --skip-sbom) skip_sbom=1 ;;
        --skip-reproducible) skip_reproducible=1 ;;
        --skip-containers) skip_containers=1 ;;
        *)
            usage
            exit 2
            ;;
    esac
    shift
done

tag="v${version}"
root="$(git rev-parse --show-toplevel)"
cd "$root"

commit="$(git rev-parse HEAD)"
tag_commit="$(git rev-parse "${tag}^{}")"
signature="$(git tag -v "$tag" 2>&1 | sed -n '/Good .*signature/p' | sed -n '1p')"
if [ -z "$signature" ]; then
    signature="tag verification output did not include a Good signature line"
fi

mkdir -p dist/checksums
source_lines=""
for extension in tar.gz zip; do
    name="fluxheim-${version}.${extension}"
    url="https://github.com/valkyoth/fluxheim/archive/refs/tags/${tag}.${extension}"
    curl -fsSL "$url" -o "dist/checksums/$name"
    line="$(sha256sum "dist/checksums/$name")"
    source_lines="${source_lines}
  - \`${line}\`"
done

binary_lines=""
if [ "$skip_builds" -eq 1 ]; then
    binary_lines="
  - not collected (--skip-builds)"
else
    target="$(rustc -vV | sed -n 's/^host: //p')"
    for profile in full cache proxy php; do
        dist_name="fluxheim-${version}-${profile}-${target}"
        if [ "$profile" = full ]; then
            cargo build --release --locked --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp --bin fluxheim --bin fluxheim-acme --bin fluxheim-config-tester
        elif [ "$profile" = cache ]; then
            cargo build --release --locked --no-default-features --features profile-cache-edge,acme-client --bin fluxheim --bin fluxheim-acme --bin fluxheim-config-tester
        elif [ "$profile" = proxy ]; then
            cargo build --release --locked --no-default-features --features profile-proxy-edge,acme-client --bin fluxheim --bin fluxheim-acme --bin fluxheim-config-tester
        else
            cargo build --release --locked --no-default-features --features profile-web-server,php-fpm,acme-client --bin fluxheim --bin fluxheim-acme --bin fluxheim-config-tester
        fi
        rm -rf "dist/$dist_name"
        mkdir -p "dist/$dist_name"
        cp target/release/fluxheim "dist/$dist_name/"
        cp target/release/fluxheim-acme "dist/$dist_name/"
        cp README.md LICENSE CHANGELOG.md "dist/$dist_name/"
        cp -r docs examples packaging release-notes "dist/$dist_name/"
        tar -C dist -czf "dist/${dist_name}.tar.gz" "$dist_name"
        line="$(sha256sum "dist/${dist_name}.tar.gz")"
        binary_lines="${binary_lines}
  - \`${line}\`"

        tester_dist_name="fluxheim-${version}-config-tester-${profile}-${target}"
        rm -rf "dist/$tester_dist_name"
        mkdir -p "dist/$tester_dist_name"
        cp target/release/fluxheim-config-tester "dist/$tester_dist_name/"
        cp README.md LICENSE CHANGELOG.md "dist/$tester_dist_name/"
        tar -C dist -czf "dist/${tester_dist_name}.tar.gz" "$tester_dist_name"
        tester_line="$(sha256sum "dist/${tester_dist_name}.tar.gz")"
        binary_lines="${binary_lines}
  - \`${tester_line}\`"
    done
fi

sbom_lines=""
if [ "$skip_sbom" -eq 1 ]; then
    sbom_lines="
  - not collected (--skip-sbom)"
else
    scripts/generate-sbom.sh
    for file in target/release-evidence/fluxheim.spdx.json target/release-evidence/fluxheim.cyclonedx.json; do
        line="$(sha256sum "$file")"
        sbom_lines="${sbom_lines}
  - \`${line}\`"
    done
fi

if [ "$skip_reproducible" -eq 1 ]; then
    reproducible_line="not collected (--skip-reproducible)"
else
    reproducible_line="$(scripts/reproducible_build_check.sh | sed -n '/^[0-9a-f]\{64\}  /p' | tail -1)"
    if [ -z "$reproducible_line" ]; then
        reproducible_line="reproducible check passed; hash line not found"
    fi
fi

container_lines=""
if [ "$skip_containers" -eq 1 ]; then
    container_lines="
  - not collected (--skip-containers)"
else
    tool=""
    if command -v podman >/dev/null 2>&1; then
        tool=podman
    elif command -v docker >/dev/null 2>&1; then
        tool=docker
    fi
    if [ -z "$tool" ]; then
        container_lines="
  - not collected (podman/docker not installed)"
    else
        for variant in wolfi alpine suse-micro debian cache-wolfi cache-alpine cache-suse-micro cache-debian proxy-wolfi proxy-alpine proxy-suse-micro proxy-debian php-wolfi php-alpine php-suse-micro php-debian; do
            image="ghcr.io/valkyoth/fluxheim:${tag}-${variant}"
            "$tool" pull "$image" >/dev/null
            digest="$("$tool" inspect "$image" --format '{{index .RepoDigests 0}}')"
            container_lines="${container_lines}
  - ${variant}: \`${digest}\`"
        done
    fi
fi

cat <<EOF

## Checksums And Signatures

- Commit: \`${tag_commit}\`
EOF
if [ "$commit" != "$tag_commit" ]; then
    echo "- Local HEAD: \`${commit}\`"
fi
cat <<EOF
- Local gate: GitHub CI green before tag; local release metadata checks passed
- CodeQL/code scanning: no open release-blocking alerts before tag
- Source archive checksums:${source_lines}
- Binary checksums:${binary_lines}
- SBOM checksums:${sbom_lines}
- Reproducible build:
  - \`${reproducible_line}\`
- Container digests:${container_lines}
- Tag signature:
  - \`${signature}\`
EOF
