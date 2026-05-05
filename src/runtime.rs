use std::error::Error;

use crate::config::Config;

#[cfg(feature = "proxy")]
pub fn run(config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    env_logger::init();

    let mut server = pingora::server::Server::new(None)?;
    server.bootstrap();

    #[cfg(feature = "load-balancer")]
    let (proxy, load_balancer_services) =
        crate::proxy::FluxProxy::from_config_with_background_services(&config)?;

    #[cfg(not(feature = "load-balancer"))]
    let proxy = crate::proxy::FluxProxy::from_config(&config)?;

    let admin_proxy = proxy.clone();
    let mut proxy_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);

    for listen in &config.server.listen {
        log::info!("proxy listener enabled on {listen}");
        proxy_service.add_tcp(listen);
    }
    add_tls_listeners(&mut proxy_service, &config)?;

    #[cfg(feature = "load-balancer")]
    for service in load_balancer_services {
        log::info!("load-balancer health-check service enabled");
        server.add_service(service);
    }

    if let Some(admin_services) = crate::admin::admin_services_from_config(&config, admin_proxy)? {
        log::info!("admin control plane enabled on {}", config.admin.listen);
        if let Some(watchdog) = admin_services.watchdog {
            log::info!("admin self-healing watchdog enabled");
            server.add_service(watchdog);
        }
        server.add_service(admin_services.control_plane);
    }

    #[cfg(feature = "metrics")]
    if config.metrics.enabled {
        crate::metrics::init()?;
        let mut metrics_service = pingora::services::listening::Service::prometheus_http_service();
        log::info!("metrics listener enabled on {}", config.metrics.listen);
        metrics_service.add_tcp(&config.metrics.listen);
        server.add_service(metrics_service);
    }

    server.add_service(proxy_service);
    server.run_forever();
}

#[cfg(not(feature = "proxy"))]
pub fn run(_config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("no runnable Fluxheim module is enabled; enable the `proxy` feature".into())
}

#[cfg(all(
    feature = "proxy",
    any(
        feature = "tls",
        feature = "tls-rustls",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    )
))]
fn add_tls_listeners<S>(
    service: &mut pingora::services::listening::Service<S>,
    config: &Config,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if config.server.tls_listen.is_empty() {
        return Ok(());
    }
    if !config.tls.enabled {
        return Err("server.tls_listen requires tls.enabled = true".into());
    }

    let Some(certificate) = crate::tls::default_downstream_certificate(config) else {
        return Err("server.tls_listen requires at least one [[tls.certificates]] entry".into());
    };
    let cert_path = certificate
        .cert_path
        .to_str()
        .ok_or("TLS certificate path must be valid UTF-8 for Pingora")?;
    let key_path = certificate
        .key_path
        .to_str()
        .ok_or("TLS private key path must be valid UTF-8 for Pingora")?;

    for listen in &config.server.tls_listen {
        log::info!("proxy TLS listener enabled on {listen}");
        service.add_tls(listen, cert_path, key_path)?;
    }

    Ok(())
}

#[cfg(all(
    feature = "proxy",
    not(any(
        feature = "tls",
        feature = "tls-rustls",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))
))]
fn add_tls_listeners<S>(
    _service: &mut pingora::services::listening::Service<S>,
    config: &Config,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if config.server.tls_listen.is_empty() {
        Ok(())
    } else {
        Err("server.tls_listen requires a TLS feature".into())
    }
}
