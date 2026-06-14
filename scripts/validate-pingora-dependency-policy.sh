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

profiles="default full cache-edge proxy-edge load-balancer-edge php privacy"
current_tsv="$out_dir/current.tsv"
current_keys="$out_dir/current.keys"
exception_keys="$out_dir/exceptions.keys"
unexpected="$out_dir/unexpected.keys"
stale="$out_dir/stale-exceptions.keys"

{
    printf 'profile\tcrate\tversion\n'
    for profile in $profiles; do
        echo "pingora dependency policy: cargo tree $profile" >&2
        capture_tree "$profile"
        grep -Eo 'pingora[-_a-z]* v[0-9][^ )]*' "$out_dir/cargo-tree/$profile.txt" \
            | sed 's/ v/\t/' \
            | sort -u \
            | while IFS="$(printf '\t')" read -r crate version; do
                printf '%s\t%s\t%s\n' "$profile" "$crate" "$version"
            done || true
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
    { print $1 "\t" $2 }
' "$exceptions" | sort -u >"$exception_keys"

comm -23 "$current_keys" "$exception_keys" >"$unexpected"
comm -13 "$current_keys" "$exception_keys" >"$stale"

if [ -s "$unexpected" ]; then
    echo "pingora dependency policy: unexpected Pingora crates:" >&2
    cat "$unexpected" >&2
fi

if [ -s "$stale" ]; then
    echo "pingora dependency policy: stale Pingora exceptions:" >&2
    cat "$stale" >&2
fi

if [ "$mode" = "check" ] && { [ -s "$unexpected" ] || [ -s "$stale" ]; }; then
    exit 1
fi

echo "pingora dependency policy: wrote $out_dir"
echo "pingora dependency policy: ok"
