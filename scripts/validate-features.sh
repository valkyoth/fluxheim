#!/usr/bin/env sh
set -eu

. scripts/feature-policy.sh

requested_features="${1:-}"
features=""
tls_count=0
tls_selected=""
php_count=0
php_selected=""

for feature in $(printf '%s' "$requested_features" | tr ',' ' '); do
    expanded="$(expand_fluxheim_feature "$feature")"
    if [ -n "$features" ]; then
        features="$features,$expanded"
    else
        features="$expanded"
    fi
done

contains_feature() {
    feature="$1"
    case ",$features," in
        *",$feature,"*) return 0 ;;
        *) return 1 ;;
    esac
}

for backend in $TLS_BACKENDS; do
    if contains_feature "$backend"; then
        tls_count=$((tls_count + 1))
        if [ -n "$tls_selected" ]; then
            tls_selected="$tls_selected,$backend"
        else
            tls_selected="$backend"
        fi
    fi
done

if [ "$tls_count" -gt 1 ]; then
    echo "select only one Fluxheim TLS backend feature: tls-rustls, tls-openssl, tls-boringssl, or tls-s2n; selected $tls_selected" >&2
    exit 1
fi

for runtime in $PHP_RUNTIMES; do
    if contains_feature "$runtime"; then
        php_count=$((php_count + 1))
        if [ -n "$php_selected" ]; then
            php_selected="$php_selected,$runtime"
        else
            php_selected="$runtime"
        fi
    fi
done

if [ "$php_count" -gt 1 ]; then
    echo "select only one Fluxheim PHP runtime feature: php-fpm or experimental-pure-php; selected $php_selected" >&2
    exit 1
fi

if contains_feature privacy-mode; then
    for incompatible in $PRIVACY_INCOMPATIBLE_FEATURES; do
        if contains_feature "$incompatible"; then
            case "$incompatible" in
                metrics)
                    echo "privacy-mode cannot be combined with metrics; zero-retention builds must not compile request metrics" >&2
                    ;;
                cache)
                    echo "privacy-mode cannot be combined with the cache feature" >&2
                    ;;
                *)
                    echo "privacy-mode cannot be combined with $incompatible" >&2
                    ;;
            esac
            exit 1
        fi
    done
fi
