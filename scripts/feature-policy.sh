# Shared feature policy for shell checks.
#
# This file is sourced by scripts/validate-features.sh. Keep Cargo.toml as the
# authoritative Cargo feature graph, and keep these aliases in sync with the
# profile features declared there.

TLS_BACKENDS="tls-rustls tls-openssl tls-boringssl tls-s2n"
PRIVACY_INCOMPATIBLE_FEATURES="cache metrics metrics-otlp otel-tracing otel-otlp"

expand_fluxheim_feature() {
    case "$1" in
        default|profile-core)
            echo "proxy,web,cache,tls-rustls,security"
            ;;
        profile-static-site)
            echo "proxy,web,tls-rustls,security"
            ;;
        profile-reverse-proxy)
            echo "proxy,tls-rustls,security"
            ;;
        profile-cache-server)
            echo "proxy,web,cache,tls-rustls,security"
            ;;
        profile-load-balancer)
            echo "proxy,web,cache,load-balancer,tls-rustls,security"
            ;;
        profile-full)
            echo "proxy,web,cache,load-balancer,tls-rustls,security"
            ;;
        profile-web-server)
            echo "proxy,web,tls-rustls,security"
            ;;
        profile-cache-edge)
            echo "proxy,cache,tls-rustls,security"
            ;;
        profile-proxy-edge)
            echo "proxy,tls-rustls,security"
            ;;
        profile-load-balancer-edge)
            echo "proxy,load-balancer,tls-rustls,security"
            ;;
        profile-observability)
            echo "proxy,web,cache,tls-rustls,security,metrics,metrics-otlp,otel-tracing,otel-otlp"
            ;;
        profile-privacy)
            echo "proxy,web,tls-rustls,privacy-mode,security"
            ;;
        *)
            echo "$1"
            ;;
    esac
}
