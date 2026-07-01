use std::error::Error;

use clap::ValueEnum;

use crate::config::{CacheConfig, Config, PhpConfig, TlsBackend, WebConfig};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ConfigTesterProfile {
    Full,
    Cache,
    Proxy,
    FipsOpenssl,
    Iso19790Openssl,
    FipsRustls,
    Iso19790Rustls,
    WebPhp,
    Development,
    LoadBalancer,
}

pub(crate) fn validate_profile_config(
    config: &Config,
    profile: ConfigTesterProfile,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let policy = ProfilePolicy::for_profile(profile);
    if !policy.web {
        reject_web_config(config)?;
    }
    if !policy.cache {
        reject_cache_config(config)?;
    }
    if !policy.php {
        reject_php_config(config)?;
    }
    if !policy.proxy {
        reject_proxy_config(config)?;
    }
    if matches!(
        profile,
        ConfigTesterProfile::FipsOpenssl | ConfigTesterProfile::Iso19790Openssl
    ) {
        validate_fips_openssl_profile_config(config, profile)?;
    }
    if matches!(
        profile,
        ConfigTesterProfile::FipsRustls | ConfigTesterProfile::Iso19790Rustls
    ) {
        validate_fips_rustls_profile_config(config, profile)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ProfilePolicy {
    proxy: bool,
    web: bool,
    cache: bool,
    php: bool,
}

impl ProfilePolicy {
    fn for_profile(profile: ConfigTesterProfile) -> Self {
        match profile {
            ConfigTesterProfile::Full | ConfigTesterProfile::Development => Self {
                proxy: true,
                web: true,
                cache: true,
                php: matches!(profile, ConfigTesterProfile::Development),
            },
            ConfigTesterProfile::Cache => Self {
                proxy: true,
                web: false,
                cache: true,
                php: false,
            },
            ConfigTesterProfile::Proxy
            | ConfigTesterProfile::FipsOpenssl
            | ConfigTesterProfile::Iso19790Openssl
            | ConfigTesterProfile::FipsRustls
            | ConfigTesterProfile::Iso19790Rustls
            | ConfigTesterProfile::LoadBalancer => Self {
                proxy: true,
                web: false,
                cache: false,
                php: false,
            },
            ConfigTesterProfile::WebPhp => Self {
                proxy: false,
                web: true,
                cache: false,
                php: true,
            },
        }
    }
}

impl ConfigTesterProfile {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Cache => "cache",
            Self::Proxy => "proxy",
            Self::FipsOpenssl => "fips-openssl",
            Self::Iso19790Openssl => "iso19790-openssl",
            Self::FipsRustls => "fips-rustls",
            Self::Iso19790Rustls => "iso19790-rustls",
            Self::WebPhp => "web-php",
            Self::Development => "development",
            Self::LoadBalancer => "load-balancer",
        }
    }
}

fn reject_web_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    if config.web.enabled() {
        return Err("target profile does not include web; remove enabled [web] config".into());
    }
    for vhost in &config.vhosts {
        if vhost.web.enabled() {
            return Err(format!(
                "target profile does not include web; remove enabled [vhosts.web] from vhost {:?}",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route.web.as_ref().is_some_and(WebConfig::enabled) {
                return Err(format!(
                    "target profile does not include web; remove enabled [vhosts.routes.web] from vhost {:?} route {:?}",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_fips_openssl_profile_config(
    config: &Config,
    profile: ConfigTesterProfile,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if config.tls.backend != TlsBackend::Openssl {
        return Err(format!(
            "target profile {} requires [tls] backend = \"openssl\"",
            profile.as_str()
        )
        .into());
    }
    if !config.tls.compliance_mode().required() {
        return Err(format!(
            "target profile {} requires [tls.fips] required = true or [tls.iso19790] required = true",
            profile.as_str()
        )
        .into());
    }
    Ok(())
}

fn validate_fips_rustls_profile_config(
    config: &Config,
    profile: ConfigTesterProfile,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if config.tls.backend != TlsBackend::Rustls {
        return Err(format!(
            "target profile {} requires [tls] backend = \"rustls\"",
            profile.as_str()
        )
        .into());
    }
    if !config.tls.compliance_mode().required() {
        return Err(format!(
            "target profile {} requires [tls.fips] required = true or [tls.iso19790] required = true",
            profile.as_str()
        )
        .into());
    }
    Ok(())
}

fn reject_cache_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    if cache_policy_requires_module(&config.cache) {
        return Err("target profile does not include cache; remove enabled [cache] config".into());
    }
    for vhost in &config.vhosts {
        if cache_policy_requires_module(&vhost.cache) {
            return Err(format!(
                "target profile does not include cache; remove enabled [vhosts.cache] from vhost {:?}",
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
                    "target profile does not include cache; remove enabled [vhosts.routes.cache] from vhost {:?} route {:?}",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

fn cache_policy_requires_module(config: &CacheConfig) -> bool {
    config.enabled
        || config.local_static
        || config.memory.enabled
        || config.disk.enabled
        || config.peer_fill.enabled
}

fn reject_php_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    for vhost in &config.vhosts {
        if vhost.php.enabled() {
            return Err(format!(
                "target profile does not include php-fpm; remove enabled [vhosts.php] from vhost {:?}",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route.php.as_ref().is_some_and(PhpConfig::enabled) {
                return Err(format!(
                    "target profile does not include php-fpm; remove enabled [vhosts.routes.php] from vhost {:?} route {:?}",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

fn reject_proxy_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    for vhost in &config.vhosts {
        if vhost.proxy.has_configured_upstream() {
            return Err(format!(
                "target profile does not include reverse proxying; remove [vhosts.proxy] from vhost {:?}",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route.proxy.is_some() {
                return Err(format!(
                    "target profile does not include reverse proxying; remove [vhosts.routes.proxy] from vhost {:?} route {:?}",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}
