#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check | report)
        ;;
    *)
        echo "usage: scripts/validate-pingora-dependency-policy.sh [check|report]" >&2
        exit 2
        ;;
esac

exceptions="docs/pingora-dependency-exceptions.tsv"
out_dir="${FLUXHEIM_PINGORA_POLICY_DIR:-target/release-evidence/pingora-dependency-policy}"
current_version="${FLUXHEIM_PINGORA_POLICY_VERSION:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | sed -n '1p')}"

if [ ! -f "$exceptions" ]; then
    echo "pingora dependency policy: missing $exceptions" >&2
    exit 1
fi

mkdir -p "$out_dir/cargo-tree"

capture_tree() {
    profile="$1"
    tree_file="$out_dir/cargo-tree/$profile.txt"

    case "$profile" in
        default)
            cargo tree --locked >"$tree_file"
            ;;
        full)
            cargo tree --locked --no-default-features --features profile-full >"$tree_file"
            ;;
        cache-edge)
            cargo tree --locked --no-default-features --features profile-cache-edge >"$tree_file"
            ;;
        proxy-edge)
            cargo tree --locked --no-default-features --features profile-proxy-edge >"$tree_file"
            ;;
        load-balancer-edge)
            cargo tree --locked --no-default-features --features profile-load-balancer-edge >"$tree_file"
            ;;
        load-balancer-crate)
            cargo tree --locked -p fluxheim-load-balancer >"$tree_file"
            ;;
        native-web-tls)
            cargo tree --locked --no-default-features --features web,tls-rustls >"$tree_file"
            ;;
        native-web-openssl)
            cargo tree --locked --no-default-features --features web,tls-openssl >"$tree_file"
            ;;
        php)
            cargo tree --locked --no-default-features --features profile-web-server,php-fpm >"$tree_file"
            ;;
        privacy)
            cargo tree --locked --no-default-features --features profile-privacy >"$tree_file"
            ;;
        *)
            echo "pingora dependency policy: unknown profile $profile" >&2
            exit 2
            ;;
    esac
}

extract_pingora_crates() {
    profile="$1"
    tree_file="$out_dir/cargo-tree/$profile.txt"
    matches_file="$out_dir/cargo-tree/$profile.pingora-matches.txt"

    if grep -Eo 'pingora[-_a-z]* v[0-9][^ )]*' "$tree_file" >"$matches_file"; then
        sed 's/ v/\t/' "$matches_file" \
            | sort -u \
            | while IFS="$(printf '\t')" read -r crate version; do
                printf '%s\t%s\t%s\n' "$profile" "$crate" "$version"
            done
    else
        status="$?"
        if [ "$status" -ne 1 ]; then
            echo "pingora dependency policy: failed to inspect $tree_file" >&2
            exit "$status"
        fi
    fi
}

profiles="default full cache-edge proxy-edge load-balancer-edge load-balancer-crate native-web-tls native-web-openssl php privacy"
current_tsv="$out_dir/current.tsv"
current_keys="$out_dir/current.keys"
exception_keys="$out_dir/exceptions.keys"
unexpected="$out_dir/unexpected.keys"
stale="$out_dir/stale-exceptions.keys"
expired="$out_dir/expired-exceptions.tsv"
manifest_expired="$out_dir/manifest-expired-exceptions.tsv"

{
    printf 'profile\tcrate\tversion\n'
    for profile in $profiles; do
        echo "pingora dependency policy: cargo tree $profile" >&2
        capture_tree "$profile"
        extract_pingora_crates "$profile"
    done
} >"$current_tsv"

awk -F '\t' 'NR > 1 && NF >= 3 { print $1 "\t" $2 }' "$current_tsv" \
    | sort -u >"$current_keys"

awk -F '\t' '
    /^[[:space:]]*#/ { next }
    NF == 0 { next }
    $1 == "profile" { next }
    NF < 4 {
        print "pingora dependency policy: malformed exception line " NR ": " $0 > "/dev/stderr"
        exit 2
    }
    $1 == "lock" { next }
    $1 == "manifest" { next }
    { print $1 "\t" $2 }
' "$exceptions" | sort -u >"$exception_keys"

comm -23 "$current_keys" "$exception_keys" >"$unexpected"
comm -13 "$current_keys" "$exception_keys" >"$stale"

awk -F '\t' -v current_version="$current_version" -v current_keys="$current_keys" '
    function compare_version(left, right, left_parts, right_parts, i) {
        sub(/^v/, "", left)
        sub(/^v/, "", right)
        split(left, left_parts, /[^0-9]+/)
        split(right, right_parts, /[^0-9]+/)
        for (i = 1; i <= 3; i++) {
            if (left_parts[i] !~ /^[0-9]+$/ || right_parts[i] !~ /^[0-9]+$/) {
                return "invalid"
            }
            if ((left_parts[i] + 0) < (right_parts[i] + 0)) {
                return -1
            }
            if ((left_parts[i] + 0) > (right_parts[i] + 0)) {
                return 1
            }
        }
        return 0
    }
    BEGIN {
        while ((getline key < current_keys) > 0) {
            current[key] = 1
        }
        close(current_keys)
        if (compare_version(current_version, "0.0.0") == "invalid") {
            print "pingora dependency policy: invalid current version " current_version > "/dev/stderr"
            exit 2
        }
    }
    /^[[:space:]]*#/ { next }
    NF == 0 { next }
    $1 == "profile" { next }
    $1 == "lock" { next }
    $1 == "manifest" { next }
    NF < 4 { next }
    {
        key = $1 "\t" $2
        if (key in current) {
            comparison = compare_version(current_version, $3)
            if (comparison == "invalid") {
                print "pingora dependency policy: invalid removal_target " $3 " for " key > "/dev/stderr"
                exit 2
            }
            if (comparison >= 0) {
                print $1 "\t" $2 "\t" $3
            }
        }
    }
' "$exceptions" | sort -u >"$expired"

awk -F '\t' -v current_version="$current_version" '
    function compare_version(left, right, left_parts, right_parts, i) {
        sub(/^v/, "", left)
        sub(/^v/, "", right)
        split(left, left_parts, /[^0-9]+/)
        split(right, right_parts, /[^0-9]+/)
        for (i = 1; i <= 3; i++) {
            if (left_parts[i] !~ /^[0-9]+$/ || right_parts[i] !~ /^[0-9]+$/) {
                return "invalid"
            }
            if ((left_parts[i] + 0) < (right_parts[i] + 0)) {
                return -1
            }
            if ((left_parts[i] + 0) > (right_parts[i] + 0)) {
                return 1
            }
        }
        return 0
    }
    BEGIN {
        if (compare_version(current_version, "0.0.0") == "invalid") {
            print "pingora dependency policy: invalid current version " current_version > "/dev/stderr"
            exit 2
        }
    }
    /^[[:space:]]*#/ { next }
    NF == 0 { next }
    $1 != "manifest" { next }
    NF < 4 { next }
    {
        comparison = compare_version(current_version, $3)
        if (comparison == "invalid") {
            print "pingora dependency policy: invalid removal_target " $3 " for manifest/" $2 > "/dev/stderr"
            exit 2
        }
        if (comparison >= 0) {
            print $1 "\t" $2 "\t" $3
        }
    }
' "$exceptions" | while IFS="$(printf '\t')" read -r scope crate target; do
    if grep -Eq "^[[:space:]]*$crate[[:space:]]*=" Cargo.toml; then
        printf '%s\t%s\t%s\n' "$scope" "$crate" "$target"
    fi
done | sort -u >"$manifest_expired"

if [ -s "$unexpected" ]; then
    echo "pingora dependency policy: unexpected Pingora crates:" >&2
    cat "$unexpected" >&2
fi

if [ -s "$stale" ]; then
    echo "pingora dependency policy: stale Pingora exceptions:" >&2
    cat "$stale" >&2
fi

if [ -s "$expired" ]; then
    echo "pingora dependency policy: expired Pingora exceptions still present for Fluxheim $current_version:" >&2
    cat "$expired" >&2
fi

if [ -s "$manifest_expired" ]; then
    echo "pingora dependency policy: expired manifest Pingora dependencies still present for Fluxheim $current_version:" >&2
    cat "$manifest_expired" >&2
fi

if [ "$mode" = "check" ] && { [ -s "$unexpected" ] || [ -s "$stale" ] || [ -s "$expired" ] || [ -s "$manifest_expired" ]; }; then
    exit 1
fi

echo "pingora dependency policy: wrote $out_dir"
echo "pingora dependency policy: ok"
