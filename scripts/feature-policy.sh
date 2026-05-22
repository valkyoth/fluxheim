# Shared feature policy for shell checks.
#
# This file is sourced by scripts/validate-features.sh. Keep Cargo.toml as the
# authoritative Cargo feature graph, and keep these aliases in sync with the
# profile features declared there.

TLS_BACKENDS="tls-rustls tls-rustls-fips tls-openssl tls-boringssl tls-s2n"
PHP_RUNTIMES="php-fpm experimental-pure-php"
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
        profile-development)
            echo "proxy,web,cache,load-balancer,tls-rustls,security,php-fpm,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp"
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
        profile-fips-openssl)
            echo "proxy,security,tls-openssl-fips"
            ;;
        profile-iso19790-openssl)
            echo "proxy,security,tls-openssl-fips,tls-openssl-iso19790"
            ;;
        profile-fips-rustls)
            echo "proxy,security,tls-rustls-fips"
            ;;
        profile-iso19790-rustls)
            echo "proxy,security,tls-rustls-fips,tls-rustls-iso19790"
            ;;
        profile-observability)
            echo "proxy,web,cache,tls-rustls,security,metrics,metrics-otlp,otel-tracing,otel-otlp"
            ;;
        profile-privacy)
            echo "proxy,web,tls-rustls,privacy-mode,security"
            ;;
        tls-openssl-fips)
            echo "tls-openssl,tls-openssl-fips"
            ;;
        tls-openssl-iso19790)
            echo "tls-openssl,tls-openssl-fips,tls-openssl-iso19790"
            ;;
        tls-rustls-iso19790)
            echo "tls-rustls-fips,tls-rustls-iso19790"
            ;;
        *)
            echo "$1"
            ;;
    esac
}
