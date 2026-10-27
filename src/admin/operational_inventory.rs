use serde::Serialize;

use crate::config::{CacheConfig, Config, PhpConfig, ProxyConfig};

pub(super) const MAX_SCOPES: usize = 1024;

#[derive(Clone, Copy, Serialize)]
pub(super) struct Component {
    pub state: &'static str,
    pub configured_sections: u64,
    pub configured_items: u64,
    pub runtime: &'static str,
}

impl Component {
    fn new(compiled: bool) -> Self {
        Self {
            state: if compiled { "disabled" } else { "not_compiled" },
            configured_sections: 0,
            configured_items: 0,
            runtime: "unavailable",
        }
    }

    fn add(&mut self, sections: u64, items: usize) {
        if self.state == "not_compiled" {
            return;
        }
        self.configured_sections = self.configured_sections.saturating_add(sections);
        self.configured_items = self.configured_items.saturating_add(items as u64);
        if self.configured_sections > 0 {
            self.state = "configured";
        }
    }
}

/// Counts explicit configuration, not effective routing or discovered live state.
/// Never copies names, endpoints, paths, certificate identities or credentials.
#[derive(Clone, Copy, Serialize)]
pub(super) struct Inventory {
    pub complete: bool,
    pub inspected_scopes: usize,
    pub vhosts: usize,
    pub listeners: Component,
    pub upstreams: Component,
    pub cache: Component,
    pub php: Component,
    pub acme: Component,
    pub metrics_otlp: bool,
    pub traces_otlp: bool,
}

impl Inventory {
    pub fn new(config: &Config) -> Self {
        let mut value = Self {
            complete: true,
            inspected_scopes: 1,
            vhosts: config.vhosts.len(),
            listeners: Component::new(true),
            upstreams: Component::new(cfg!(feature = "proxy")),
            cache: Component::new(cfg!(feature = "cache")),
            php: Component::new(cfg!(feature = "php-fpm")),
            acme: Component::new(cfg!(feature = "acme")),
            metrics_otlp: config.metrics.enabled && config.metrics.otlp.enabled,
            traces_otlp: config.tracing.enabled && config.tracing.otlp.enabled,
        };
        value.listeners.add(
            1,
            config
                .server
                .listen
                .len()
                .saturating_add(config.server.tls_listen.len()),
        );
        value.proxy(&config.proxy);
        value.cache(&config.cache);
        value.acme.add(u64::from(config.tls.acme.enabled), 0);
        for vhost in &config.vhosts {
            if !value.take_scope() {
                break;
            }
            value.proxy(&vhost.proxy);
            value.cache(&vhost.cache);
            value.php(&vhost.php);
            value.acme.add(u64::from(vhost.tls.acme.enabled), 0);
            for route in &vhost.routes {
                if !value.take_scope() {
                    break;
                }
                if let Some(proxy) = &route.proxy {
                    value.proxy(proxy);
                }
                if let Some(cache) = &route.cache {
                    value.cache(cache);
                }
                if let Some(php) = &route.php {
                    value.php(php);
                }
            }
            if !value.complete {
                break;
            }
        }
        value
    }

    fn take_scope(&mut self) -> bool {
        if self.inspected_scopes == MAX_SCOPES {
            self.complete = false;
            return false;
        }
        self.inspected_scopes += 1;
        true
    }

    fn proxy(&mut self, config: &ProxyConfig) {
        let items = config
            .upstreams
            .len()
            .saturating_add(config.backup_upstreams.len())
            .saturating_add(usize::from(config.upstream.is_some()));
        self.upstreams.add(
            u64::from(
                items > 0 || config.upstreams_file.is_some() || config.upstreams_http_url.is_some(),
            ),
            items,
        );
    }

    fn cache(&mut self, config: &CacheConfig) {
        self.cache.add(u64::from(config.enabled), 0);
    }

    fn php(&mut self, config: &PhpConfig) {
        self.php.add(u64::from(config.enabled), 0);
    }
}
