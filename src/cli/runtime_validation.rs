use std::error::Error;

use crate::config::Config;

pub fn validate_compiled_module_config(
    config: &Config,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(all(feature = "web", feature = "cache", feature = "php-fpm"))]
    let _ = config;
    #[cfg(not(feature = "web"))]
    validate_web_module_absent(config)?;
    #[cfg(not(feature = "cache"))]
    validate_cache_module_absent(config)?;
    #[cfg(not(feature = "php-fpm"))]
    validate_php_module_absent(config)?;
    Ok(())
}

#[cfg(not(feature = "web"))]
fn validate_web_module_absent(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    if config.web.enabled() {
        return Err(
            "web module not compiled; remove [web] root config or build with the `web` feature"
                .into(),
        );
    }
    for vhost in &config.vhosts {
        if vhost.web.enabled() {
            return Err(format!(
                "web module not compiled; remove [vhosts.web] root config for vhost {:?} or build with the `web` feature",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route
                .web
                .as_ref()
                .is_some_and(crate::config::WebConfig::enabled)
            {
                return Err(format!(
                    "web module not compiled; remove [vhosts.routes.web] config for vhost {:?} route {:?} or build with the `web` feature",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "cache"))]
fn validate_cache_module_absent(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    if cache_policy_requires_module(&config.cache) {
        return Err("cache module not compiled; remove enabled [cache] config or build with the `cache` feature".into());
    }
    for vhost in &config.vhosts {
        if cache_policy_requires_module(&vhost.cache) {
            return Err(format!(
                "cache module not compiled; remove enabled [vhosts.cache] config for vhost {:?} or build with the `cache` feature",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route
                .cache
                .as_ref()
                .is_some_and(cache_policy_requires_module)
            {
                return Err(format!(
                    "cache module not compiled; remove enabled [vhosts.routes.cache] config for vhost {:?} route {:?} or build with the `cache` feature",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "cache"))]
fn cache_policy_requires_module(config: &crate::config::CacheConfig) -> bool {
    config.enabled
        || config.local_static
        || config.memory.enabled
        || config.disk.enabled
        || config.peer_fill.enabled
}

#[cfg(not(feature = "php-fpm"))]
fn validate_php_module_absent(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    for vhost in &config.vhosts {
        if vhost.php.enabled() {
            return Err(format!(
                "php-fpm module not compiled; remove enabled [vhosts.php] config for vhost {:?} or build with the `php-fpm` feature",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route
                .php
                .as_ref()
                .is_some_and(crate::config::PhpConfig::enabled)
            {
                return Err(format!(
                    "php-fpm module not compiled; remove enabled [vhosts.routes.php] config for vhost {:?} route {:?} or build with the `php-fpm` feature",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

#[cfg(feature = "proxy")]
pub fn validate_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    config.validate()?;
    validate_compiled_module_config(config)?;
    validate_fips_runtime_config(config)?;
    #[cfg(feature = "web")]
    validate_web_runtime_config(config)?;
    fluxheim_server::NativeHttp1HostRouter::from_config(
        config,
        fluxheim_server::DownstreamHttp1Policy::default(),
        0,
    )
    .map_err(|error| format!("proxy runtime validation failed: {error}"))?;
    #[cfg(feature = "stream-proxy")]
    crate::stream_proxy::stream_services_from_config(config)?;
    Ok(())
}

#[cfg(feature = "web")]
fn validate_web_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_web_runtime_scope("global web", &config.web)?;
    for vhost in &config.vhosts {
        validate_web_runtime_scope(&format!("vhost {:?} web", vhost.name), &vhost.web)?;
        for route in &vhost.routes {
            if let Some(web) = &route.web {
                validate_web_runtime_scope(
                    &format!("vhost {:?} route {:?} web", vhost.name, route.name),
                    web,
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(all(feature = "web", not(feature = "proxy")))]
pub fn validate_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    config.validate()?;
    validate_compiled_module_config(config)?;
    validate_fips_runtime_config(config)?;
    validate_web_runtime_config(config)?;
    Ok(())
}

#[cfg(feature = "web")]
fn validate_web_runtime_scope(
    scope: &str,
    config: &crate::config::WebConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::web::StaticFileServer::from_config(config)
        .map_err(|error| format!("{scope}: {error}"))?;
    Ok(())
}

#[cfg(not(any(feature = "proxy", feature = "web")))]
pub fn validate_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    config.validate()?;
    validate_compiled_module_config(config)?;
    validate_fips_runtime_config(config)?;
    Ok(())
}

fn validate_fips_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(any(
        feature = "tls",
        feature = "tls-rustls-backend",
        feature = "tls-openssl"
    ))]
    {
        crate::tls::validate_fips_runtime_config(config)
    }

    #[cfg(not(any(
        feature = "tls",
        feature = "tls-rustls-backend",
        feature = "tls-openssl"
    )))]
    {
        let compliance_mode = config.tls.compliance_mode();
        if compliance_mode.required() {
            Err(format!(
                "{} required mode requires a FIPS/ISO-capable TLS backend feature such as tls-rustls-fips, tls-openssl-fips, or tls-openssl-iso19790",
                compliance_mode.label()
            )
            .into())
        } else {
            Ok(())
        }
    }
}
