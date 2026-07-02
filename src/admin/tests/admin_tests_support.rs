use super::*;

pub(super) fn app() -> AdminApp {
    app_with_config(Config::default())
}

pub(super) fn app_with_config(config: Config) -> AdminApp {
    app_with_config_and_self_healing(config, false)
}

pub(super) fn app_with_config_and_self_healing(
    config: Config,
    self_healing_enabled: bool,
) -> AdminApp {
    let store = unique_temp_path("admin-snapshot-store");
    std::fs::create_dir(&store).expect("create private admin snapshot test store");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700))
            .expect("secure private admin snapshot test store");
    }
    #[cfg(feature = "load-balancer")]
    let proxy = {
        let (_, _, load_balancer_admin_pools) =
            fluxheim_server::NativeHttp1HostRouter::from_config_with_native_load_balancer_services(
                &config,
                fluxheim_server::DownstreamHttp1Policy::default(),
                0,
            )
            .unwrap();
        FluxProxy::from_config_with_native_load_balancers(&config, load_balancer_admin_pools)
            .unwrap()
    };
    #[cfg(not(feature = "load-balancer"))]
    let proxy = FluxProxy::from_config(&config).unwrap();
    let auth_throttle = AdminAuthThrottle::new(config.admin.auth_throttle);
    let client_certificate = super::super::AdminClientCertificatePolicy::from_config(&config.admin);
    let health_unauthenticated = config.admin.health.unauthenticated;
    let health_response = config.admin.health.response;
    AdminApp {
        token: AdminToken::new("secret-token", false),
        client_certificate,
        store: SnapshotStore::new(store),
        current_config: Arc::new(ArcSwap::from_pointee(config)),
        proxy,
        health_path: "/_fluxheim/health".to_owned(),
        health_unauthenticated,
        health_response,
        self_healing_enabled,
        validation_window_secs: AdminSelfHealingConfig::default().validation_window_secs,
        min_successful_checks: AdminSelfHealingConfig::default().min_successful_checks,
        max_error_rate_per_mille: AdminSelfHealingConfig::default().max_error_rate_per_mille,
        state: Arc::new(std::sync::Mutex::new(SnapshotRuntimeState::default())),
        auth_throttle,
    }
}

pub(super) fn native_request(
    method: &str,
    target: &str,
    headers: Vec<(String, String)>,
) -> fluxheim_server::NativeHttp1Request {
    fluxheim_server::NativeHttp1Request {
        method: method.to_owned(),
        peer_addr: Some("127.0.0.1:59000".parse().unwrap()),
        local_addr: Some("127.0.0.1:8080".parse().unwrap()),
        effective_client_addr: Some("127.0.0.1:59000".parse().unwrap()),
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: target.to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers,
        body: zeroize::Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    }
}

#[cfg(feature = "load-balancer")]
pub(super) fn load_balancer_admin_config() -> Config {
    Config {
        vhosts: vec![VhostConfig {
            name: "one".to_owned(),
            hosts: vec!["one.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
                upstream_aliases: vec!["app-a".to_owned(), "app-b".to_owned()],
                ..ProxyConfig::default()
            },
            cache: CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    }
}

#[cfg(feature = "load-balancer")]
pub(super) fn load_balancer_persistent_admin_config() -> Config {
    let root = unique_temp_path("admin-lb-runtime-state");
    std::fs::create_dir_all(&root).unwrap();
    let mut config = load_balancer_admin_config();
    config.vhosts[0].proxy.load_balance.runtime_state_file =
        Some(safe_child_path(&root, "lb-state.json"));
    config
}

pub(super) fn set_test_runtime_state(
    app: &AdminApp,
    runtime_snapshot: Option<String>,
    known_good_snapshot: Option<String>,
    pending_validation: Option<PendingValidation>,
) {
    let mut state = app.state.lock().unwrap();
    state.runtime_snapshot = runtime_snapshot;
    state.known_good_snapshot = known_good_snapshot;
    state.pending_validation = pending_validation;
}

pub(super) fn auth_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        "Bearer secret-token".parse().unwrap(),
    );
    headers
}

#[cfg(feature = "cache")]
pub(super) fn cached_assets_route() -> RouteConfig {
    RouteConfig {
        name: "assets".to_owned(),
        path_exact: None,
        path_prefix: Some("/assets/".to_owned()),
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: Some(ProxyConfig::default()),
        web: None,
        php: None,
        cache: Some(CacheConfig {
            enabled: true,
            memory: crate::config::CacheMemoryConfig {
                enabled: true,
                max_size_bytes: ByteSize::from_bytes(1024),
            },
            max_object_bytes: ByteSize::from_bytes(512),
            ..CacheConfig::default()
        }),
        compression: None,
        headers: crate::config::VhostHeaderPolicyConfig::default(),
    }
}

#[cfg(feature = "cache")]
pub(super) fn cached_tiered_route(cache_path: &std::path::Path) -> RouteConfig {
    RouteConfig {
        name: "media".to_owned(),
        path_exact: None,
        path_prefix: Some("/media/".to_owned()),
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: Some(ProxyConfig::default()),
        web: None,
        php: None,
        cache: Some(CacheConfig {
            enabled: true,
            memory: crate::config::CacheMemoryConfig {
                enabled: true,
                max_size_bytes: ByteSize::from_bytes(2048),
            },
            disk: crate::config::CacheDiskConfig {
                enabled: true,
                path: Some(cache_path.to_path_buf()),
                max_size_bytes: ByteSize::from_bytes(4096),
                ..crate::config::CacheDiskConfig::default()
            },
            max_object_bytes: ByteSize::from_bytes(512),
            ..CacheConfig::default()
        }),
        compression: None,
        headers: crate::config::VhostHeaderPolicyConfig::default(),
    }
}

#[cfg(feature = "cache")]
pub(super) fn uncached_api_route() -> RouteConfig {
    RouteConfig {
        name: "api".to_owned(),
        path_exact: None,
        path_prefix: Some("/api/".to_owned()),
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: Some(ProxyConfig::default()),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: crate::config::VhostHeaderPolicyConfig::default(),
    }
}

pub(super) struct TestDir {
    pub(super) path: std::path::PathBuf,
}

impl TestDir {
    pub(super) fn new(name: &str) -> Self {
        let path = unique_temp_path(name);
        std::fs::create_dir(&path).expect("create test directory");
        Self { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
