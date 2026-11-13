use std::io::{self, Write};

use fluxheim_config::{CacheConfig, Config};
use sha2::{Digest, Sha256};

use crate::NativeHttp1ProxyConfigError;

/// Stable identity for configuration-owned representation selection. Operational
/// listeners and presentation-only cache headers do not affect origin content.
pub fn native_cache_representation(
    config: &Config,
) -> Result<[u8; 32], NativeHttp1ProxyConfigError> {
    let caching = config.cache.enabled
        || config.vhosts.iter().any(|vhost| {
            vhost.cache.enabled
                || vhost
                    .routes
                    .iter()
                    .any(|route| route.cache.as_ref().is_some_and(|cache| cache.enabled))
        });
    if caching
        && config.wasm.enabled
        && config.wasm.plugins.iter().any(|plugin| {
            !plugin.sha256.as_ref().is_some_and(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        })
    {
        // A pathname alone cannot identify code which modifies representations.
        return Err(NativeHttp1ProxyConfigError::CachePolicy);
    }
    let mut normalized = config.clone();
    normalized.admin = Default::default();
    normalized.logging = Default::default();
    normalized.logging.access = config.logging.access.clone();
    normalized.metrics = Default::default();
    normalized.server.listen = Default::default();
    normalized.server.process = Default::default();
    normalize_cache(&mut normalized.cache);
    for vhost in &mut normalized.vhosts {
        normalize_cache(&mut vhost.cache);
        for route in &mut vhost.routes {
            if let Some(cache) = &mut route.cache {
                normalize_cache(cache);
            }
        }
    }
    let mut writer = DigestWriter(Sha256::new());
    writer.0.update(b"fluxheim-representation-v1\0");
    // Configuration maps are ordered. Stream into the digest instead of keeping
    // a serialized copy of injected credentials in another allocation.
    serde_json::to_writer(&mut writer, &normalized)
        .map_err(|_| NativeHttp1ProxyConfigError::CacheInitialization)?;
    Ok(writer.0.finalize().into())
}

fn normalize_cache(cache: &mut CacheConfig) {
    // Storage location, peer topology and admission tuning do not identify the
    // representation. The caller's explicit namespace is bound separately.
    *cache = CacheConfig::default();
}

/// Apply the same identity to serving, offline inspection and exact purge keys.
pub fn native_representation_cache_config(
    cache: &CacheConfig,
    representation: &[u8; 32],
    vhost: &str,
    route: Option<&str>,
) -> CacheConfig {
    let mut hash = Sha256::new();
    hash.update(b"fluxheim-cache-context-v1\0");
    hash.update(representation);
    for value in [Some(vhost), route, cache.key_namespace.as_deref()] {
        hash.update([u8::from(value.is_some())]);
        let value = value.unwrap_or_default().as_bytes();
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    let mut scoped = cache.clone();
    let hex: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    scoped.key_namespace = Some(format!("context-v1-{hex}"));
    scoped
}

struct DigestWriter(Sha256);

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Config {
        serde_json::from_value(serde_json::json!({
            "vhosts": [{"name": "tenant", "hosts": ["tenant.test"], "routes": [{
                "name": "assets", "path_prefix": "/", "proxy": {"upstream": "127.0.0.1:9001", "upstream_tls": false}
            }]}]
        })).unwrap()
    }

    #[test]
    fn representation_binds_origins_headers_rewrites_auth_access_and_wasm() {
        let original = fixture();
        let identity = native_cache_representation(&original).unwrap();
        for mutation in 0..8 {
            let mut changed = original.clone();
            let route = &mut changed.vhosts[0].routes[0];
            match mutation {
                0 => route.proxy.as_mut().unwrap().upstream = Some("127.0.0.1:9002".into()),
                1 => route.rewrite_template = Some("/private{path}".into()),
                2 => {
                    route
                        .headers
                        .request
                        .set
                        .insert("authorization".into(), "secret-canary".into());
                }
                3 => {
                    route.proxy.as_mut().unwrap().auth_request.url =
                        Some("https://auth.example/check".into())
                }
                4 => route.access.require_client_cert = true,
                5 => {
                    changed
                        .headers
                        .request
                        .set
                        .insert("x-tenant".into(), "new-tenant".into());
                }
                6 => changed.server.trusted_proxies = vec!["127.0.0.1".into()],
                _ => changed.wasm.enabled = true,
            }
            assert_ne!(
                identity,
                native_cache_representation(&changed).unwrap(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn representation_is_stable_and_namespace_is_bounded_and_scope_bound() {
        let original = fixture();
        let identity = native_cache_representation(&original).unwrap();
        let mut operational = original.clone();
        operational.admin.enabled = true;
        operational.vhosts[0].cache.status_header = Some("x-next-cache".into());
        operational.vhosts[0].cache.disk.path = Some("/different/root".into());
        assert_eq!(identity, native_cache_representation(&operational).unwrap());
        let cache = CacheConfig::default();
        let scoped = native_representation_cache_config(&cache, &identity, "tenant", None);
        assert_eq!(scoped.key_namespace.as_ref().unwrap().len(), 75);
        assert_ne!(
            scoped.key_namespace,
            native_representation_cache_config(&cache, &identity, "tenant", Some("")).key_namespace
        );
        let mut explicit = cache.clone();
        explicit.key_namespace = Some("cutover".into());
        assert_ne!(
            scoped.key_namespace,
            native_representation_cache_config(&explicit, &identity, "tenant", None).key_namespace
        );
        let roundtrip: Config =
            serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert_eq!(identity, native_cache_representation(&roundtrip).unwrap());
    }

    #[test]
    fn cached_wasm_requires_a_content_pin_and_pin_changes_invalidate_identity() {
        let mut config = fixture();
        config.cache.enabled = true;
        config.wasm.enabled = true;
        config.wasm.plugins.push(
            serde_json::from_value(serde_json::json!({
                "name": "headers", "path": "/private/plugins/headers.wasm"
            }))
            .unwrap(),
        );
        assert!(native_cache_representation(&config).is_err());
        config.wasm.plugins[0].sha256 = Some("a".repeat(64));
        let first = native_cache_representation(&config).unwrap();
        config.wasm.plugins[0].sha256 = Some("b".repeat(64));
        assert_ne!(first, native_cache_representation(&config).unwrap());
    }
}
