use crate::config::{
    Config, PhpConfig, PhpFpmConfig, PhpFpmMode, RouteConfig, VhostAcmeConfig, VhostConfig,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct ManagedAcmeService {
    vhost: String,
    hosts: Vec<String>,
    config: VhostAcmeConfig,
}

pub(super) fn managed_acme_services(config: &Config) -> Vec<ManagedAcmeService> {
    config
        .vhosts
        .iter()
        .inspect(|vhost| audit_vhost_fields(vhost))
        .filter(|vhost| vhost.tls.enabled && vhost.tls.acme.enabled)
        .map(|vhost| ManagedAcmeService {
            vhost: vhost.name.clone(),
            hosts: vhost.hosts.clone(),
            config: vhost.tls.acme.clone(),
        })
        .collect()
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct ManagedPhpService {
    vhost: String,
    route: Option<String>,
    process: PhpFpmConfig,
}

pub(super) fn managed_php_services(config: &Config) -> Vec<ManagedPhpService> {
    let mut services = Vec::new();
    for vhost in &config.vhosts {
        audit_vhost_fields(vhost);
        push_managed_php_service(&mut services, &vhost.name, None, &vhost.php);
        for route in &vhost.routes {
            audit_route_fields(route);
            if let Some(php) = &route.php {
                push_managed_php_service(
                    &mut services,
                    &vhost.name,
                    Some(route.name.as_str()),
                    php,
                );
            }
        }
    }
    services
}

fn push_managed_php_service(
    services: &mut Vec<ManagedPhpService>,
    vhost: &str,
    route: Option<&str>,
    php: &PhpConfig,
) {
    if !php.enabled || php.fpm.mode != PhpFpmMode::Managed {
        return;
    }
    services.push(ManagedPhpService {
        vhost: vhost.to_owned(),
        route: route.map(str::to_owned),
        process: managed_php_process_config(&php.fpm),
    });
}

fn managed_php_process_config(config: &PhpFpmConfig) -> PhpFpmConfig {
    let PhpFpmConfig {
        mode: _,
        socket: _,
        tcp: _,
        tcp_upstreams: _,
        allow_private_tcp_upstreams: _,
        php_fpm_binary: _,
        socket_dir: _,
        workers: _,
        max_requests_per_worker: _,
        process_manager: _,
        start_servers: _,
        min_spare_servers: _,
        max_spare_servers: _,
        max_spawn_rate: _,
        process_idle_timeout_secs: _,
        listen_backlog: _,
        listen_owner: _,
        listen_group: _,
        listen_mode: _,
        request_terminate_timeout_secs: _,
        request_terminate_timeout_track_finished: _,
        request_slowlog_timeout_secs: _,
        request_slowlog_trace_depth: _,
        clear_env: _,
        catch_workers_output: _,
        decorate_workers_output: _,
        session_save_path: _,
        upload_tmp_dir: _,
        user: _,
        group: _,
        keepalive: _,
        pool_max_idle: _,
        idle_timeout_secs: _,
        connect_timeout_secs: _,
        read_timeout_secs: _,
        write_timeout_secs: _,
        max_retries: _,
        retry_timeout_secs: _,
        retry_methods: _,
        retry_invalid_response: _,
        retry_statuses: _,
    } = config;

    let defaults = PhpFpmConfig::default();
    let mut process = config.clone();
    process.socket = defaults.socket;
    process.tcp = defaults.tcp;
    process.tcp_upstreams = defaults.tcp_upstreams;
    process.allow_private_tcp_upstreams = defaults.allow_private_tcp_upstreams;
    process.keepalive = defaults.keepalive;
    process.pool_max_idle = defaults.pool_max_idle;
    process.idle_timeout_secs = defaults.idle_timeout_secs;
    process.connect_timeout_secs = defaults.connect_timeout_secs;
    process.read_timeout_secs = defaults.read_timeout_secs;
    process.write_timeout_secs = defaults.write_timeout_secs;
    process.max_retries = defaults.max_retries;
    process.retry_timeout_secs = defaults.retry_timeout_secs;
    process.retry_methods = defaults.retry_methods;
    process.retry_invalid_response = defaults.retry_invalid_response;
    process.retry_statuses = defaults.retry_statuses;
    process
}

fn audit_vhost_fields(vhost: &VhostConfig) {
    let VhostConfig {
        name: _,
        hosts: _,
        max_request_body_bytes: _,
        access: _,
        rate_limit: _,
        concurrency: _,
        tls: _,
        acme_challenge: _,
        redirect: _,
        proxy: _,
        cache: _,
        compression: _,
        headers: _,
        php: _,
        web: _,
        routes: _,
    } = vhost;
}

fn audit_route_fields(route: &RouteConfig) {
    let RouteConfig {
        name: _,
        path_exact: _,
        path_prefix: _,
        path_regex: _,
        methods: _,
        fallback: _,
        https_redirect_exempt: _,
        strip_prefix: _,
        rewrite_prefix: _,
        rewrite_template: _,
        max_request_body_bytes: _,
        access: _,
        rate_limit: _,
        concurrency: _,
        grpc: _,
        redirect: _,
        proxy: _,
        web: _,
        php: _,
        cache: _,
        compression: _,
        headers: _,
    } = route;
}
