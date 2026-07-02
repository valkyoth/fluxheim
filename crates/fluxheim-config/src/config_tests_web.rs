use super::*;
use crate::{GeoIpConfig, MAX_WEB_INDEX_FILES, StreamConfig, TlsConfig, UdpConfig};

#[test]
fn rejects_empty_index_files() {
    let config = Config {
        server: ServerConfig::default(),
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: TlsConfig::default(),
        proxy: ProxyConfig::default(),
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig {
            root: Some(PathBuf::from("public")),
            index_files: vec![],
            deny_dotfiles: true,
            ..WebConfig::default()
        },
        geoip: GeoIpConfig::default(),
        stream: StreamConfig::default(),
        udp: UdpConfig::default(),
        vhosts: vec![],
    };

    assert_eq!(config.validate(), Err(ConfigError::EmptyIndexFiles));
}

#[test]
fn rejects_too_many_index_files() {
    let index_files = (0..=MAX_WEB_INDEX_FILES)
        .map(|index| format!("index-{index}.html"))
        .collect::<Vec<_>>();
    let config = Config {
        server: ServerConfig::default(),
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: TlsConfig::default(),
        proxy: ProxyConfig::default(),
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig {
            root: Some(PathBuf::from("public")),
            index_files,
            deny_dotfiles: true,
            ..WebConfig::default()
        },
        geoip: GeoIpConfig::default(),
        stream: StreamConfig::default(),
        udp: UdpConfig::default(),
        vhosts: vec![],
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "web.index_files".to_owned(),
            max: MAX_WEB_INDEX_FILES,
        })
    );
}

#[test]
fn route_web_wraps_too_many_index_files() {
    let index_files = (0..=MAX_WEB_INDEX_FILES)
        .map(|index| format!("\"index-{index}.html\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [[vhosts.routes]]
            name = "static"
            path_prefix = "/static/"

            [vhosts.routes.web]
            root = "public"
            index_files = [{index_files}]
            "#
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::RouteSection {
            vhost: "gateway".to_owned(),
            route: "static".to_owned(),
            section: "web",
            source: Box::new(ConfigError::InvalidConfigListLength {
                field: "web.index_files".to_owned(),
                max: MAX_WEB_INDEX_FILES,
            })
        })
    );
}

#[test]
fn rejects_nested_index_files() {
    let config = Config {
        server: ServerConfig::default(),
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: TlsConfig::default(),
        proxy: ProxyConfig::default(),
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig {
            root: Some(PathBuf::from("public")),
            index_files: vec!["pages/index.html".to_owned()],
            deny_dotfiles: true,
            ..WebConfig::default()
        },
        geoip: GeoIpConfig::default(),
        stream: StreamConfig::default(),
        udp: UdpConfig::default(),
        vhosts: vec![],
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidIndexFile {
            file: "pages/index.html".to_owned()
        })
    );
}
