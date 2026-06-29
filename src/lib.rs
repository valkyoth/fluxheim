#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
mod access_log;
#[cfg(feature = "acme")]
pub mod acme;
pub mod acme_companion;
#[cfg(feature = "proxy")]
pub mod admin;
#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
mod auth_request;
#[cfg(feature = "proxy")]
mod background;
#[cfg(all(feature = "cache", feature = "pingora-compat"))]
pub mod cache;
#[cfg(all(feature = "cache", not(feature = "pingora-compat")))]
pub mod cache {
    pub use crate::cache_api::*;
}
#[cfg(all(feature = "proxy", feature = "cache"))]
mod cache_api;
pub mod cache_headers;
pub mod cli;
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
#[cfg(feature = "pingora-compat")]
mod compression;
pub mod config {
    #[allow(unused_imports)]
    pub use fluxheim_config::*;
}
pub(crate) mod config_access {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_access::*;
}
pub(crate) mod config_acme {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_acme::*;
}
pub(crate) mod config_admin {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_admin::*;
}
pub(crate) mod config_cache {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_cache::*;
}
pub(crate) mod config_compression {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_compression::*;
}
pub(crate) mod config_geoip {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_geoip::*;
}
pub(crate) mod config_header {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_header::*;
}
pub(crate) mod config_http {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_http::*;
}
pub(crate) mod config_load_balance {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_load_balance::*;
}
pub(crate) mod config_loader {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_loader::*;
}
pub(crate) mod config_logging {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_logging::*;
}
pub(crate) mod config_net {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_net::*;
}
pub(crate) mod config_observability {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_observability::*;
}
pub(crate) mod config_path {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_path::*;
}
pub(crate) mod config_php {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_php::*;
}
pub(crate) mod config_proxy {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_proxy::*;
}
pub(crate) mod config_route {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_route::*;
}
pub(crate) mod config_server {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_server::*;
}
pub(crate) mod config_stream {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_stream::*;
}
pub mod config_tester;
pub(crate) mod config_tls {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_tls::*;
}
pub(crate) mod config_types {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_types::*;
}
pub(crate) mod config_udp {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_udp::*;
}
pub(crate) mod config_web {
    #[allow(unused_imports)]
    pub(crate) use fluxheim_config::config_web::*;
}
#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
mod edge_policy;
mod flux_error;
mod fs_trust;
#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
mod geo_context;
#[cfg(feature = "geoip")]
pub mod geoip;
#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
pub mod headers;
#[cfg(all(feature = "proxy", not(feature = "pingora-compat")))]
pub mod headers {
    #[derive(Clone, Debug, Default)]
    pub struct RequestTlsClientIdentity {
        pub cipher: Option<String>,
        pub version: Option<String>,
        pub organization: Option<String>,
        pub serial_number: Option<String>,
        pub cert_sha256: Option<String>,
    }

    #[derive(Clone, Debug, Default)]
    pub struct RouteRegexCaptures {
        numbered: Vec<Option<String>>,
        named: std::collections::BTreeMap<String, String>,
    }

    impl RouteRegexCaptures {
        pub fn new(
            numbered: Vec<Option<String>>,
            named: std::collections::BTreeMap<String, String>,
        ) -> Self {
            Self { numbered, named }
        }

        pub fn variable(&self, variable: &str) -> Option<&str> {
            let key = variable.strip_prefix("route.regex.")?;
            if key.bytes().all(|byte| byte.is_ascii_digit()) {
                return key
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| self.numbered.get(index))
                    .and_then(Option::as_deref);
            }
            self.named.get(key).map(String::as_str)
        }
    }
}
#[cfg(feature = "ingress")]
mod http_types;
pub mod internal_crypto;
#[cfg(feature = "load-balancer")]
pub mod load_balancer;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "metrics-otlp")]
pub mod metrics_otlp;
#[cfg(all(feature = "web", feature = "proxy"))]
mod native_http1_static;
#[cfg(all(feature = "proxy", not(feature = "pingora-compat")))]
pub mod native_proxy_shim;
#[cfg(feature = "otel-otlp")]
pub mod otel_otlp;
#[cfg(feature = "metrics-otlp")]
mod otlp_http;
#[cfg(feature = "proxy")]
mod path_safety;
#[cfg(feature = "php-fpm")]
pub(crate) mod php_fpm;
#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
pub mod proxy;
#[cfg(all(feature = "proxy", not(feature = "pingora-compat")))]
pub use native_proxy_shim as proxy;
#[cfg(all(feature = "proxy", feature = "cache", feature = "pingora-compat"))]
mod proxy_cache;
#[cfg(all(
    any(feature = "proxy", feature = "stream-proxy"),
    feature = "pingora-compat"
))]
mod proxy_protocol;
pub mod reload;
#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
mod route_policy;
#[cfg(feature = "security")]
pub mod security;
pub mod snapshot;
#[cfg(feature = "stream-proxy")]
mod stream_proxy;
#[cfg(all(
    feature = "stream-proxy",
    any(feature = "tls-rustls-backend", feature = "tls-openssl")
))]
mod stream_tls;
#[cfg(any(
    feature = "tls",
    feature = "tls-rustls-backend",
    feature = "tls-openssl"
))]
pub mod tls;
#[cfg(feature = "otel-tracing")]
pub mod trace_context;
#[cfg(all(feature = "traffic-mirror", feature = "pingora-compat"))]
mod traffic_mirror;
#[cfg(feature = "udp-proxy")]
mod udp_proxy;
#[cfg(any(
    all(
        feature = "stream-proxy",
        any(feature = "tls-rustls-backend", feature = "tls-openssl")
    ),
    all(
        feature = "proxy",
        feature = "pingora-compat",
        any(feature = "tls-rustls-backend", feature = "tls-openssl")
    )
))]
mod upstream_tls;
#[cfg(feature = "web")]
pub mod web;

pub mod runtime;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(any(
    all(feature = "tls-rustls", feature = "tls-rustls-fips"),
    all(feature = "tls-rustls-backend", feature = "tls-openssl"),
))]
compile_error!(
    "select only one Fluxheim TLS backend feature: tls-rustls, tls-rustls-fips, or tls-openssl"
);

#[cfg(all(feature = "privacy-mode", feature = "geoip"))]
compile_error!("privacy-mode builds do not include GeoIP lookup or Geo-Context metadata");

#[cfg(all(
    feature = "tls-rustls-backend",
    not(any(feature = "tls-rustls", feature = "tls-rustls-fips"))
))]
compile_error!("tls-rustls-backend is an internal feature; select tls-rustls or tls-rustls-fips");

#[cfg(all(feature = "privacy-mode", feature = "cache"))]
compile_error!(
    "privacy-mode cannot be combined with the cache feature; build with --no-default-features --features profile-privacy or select proxy,web,tls-*,privacy-mode explicitly"
);

#[cfg(all(feature = "privacy-mode", feature = "compression"))]
compile_error!(
    "privacy-mode cannot be combined with compression; zero-retention builds must not transform response bodies"
);

#[cfg(all(feature = "privacy-mode", feature = "metrics"))]
compile_error!(
    "privacy-mode cannot be combined with metrics; zero-retention builds must not compile request metrics"
);

#[cfg(all(feature = "privacy-mode", feature = "metrics-otlp"))]
compile_error!(
    "privacy-mode cannot be combined with metrics-otlp; zero-retention builds must not compile metrics export"
);

#[cfg(all(feature = "privacy-mode", feature = "otel-tracing"))]
compile_error!(
    "privacy-mode cannot be combined with otel-tracing; zero-retention builds must not compile trace context propagation"
);

#[cfg(all(feature = "privacy-mode", feature = "otel-otlp"))]
compile_error!(
    "privacy-mode cannot be combined with otel-otlp; zero-retention builds must not compile trace export"
);

pub fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    cli::run_from_env()
}
