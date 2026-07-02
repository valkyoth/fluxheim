use std::fs;
use std::path::{Path, PathBuf};

use super::run_from_args;
use fluxheim_common::test_support::{safe_child_path, unique_temp_path};

#[path = "cli_tests_cache_key.rs"]
mod cache_key;
#[path = "cli_tests_cache_key_preview.rs"]
mod cache_key_preview;
#[path = "cli_tests_cache_lookup.rs"]
mod cache_lookup;
#[path = "cli_tests_cache_warm.rs"]
mod cache_warm;
#[path = "cli_tests_core.rs"]
mod core;
struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let path = unique_temp_path(name);
        fs::create_dir(&path).expect("create test directory");
        Self { path }
    }

    fn file(&self, name: &str, mode: u32) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::write(&path, "test").expect("write test file");
        set_mode(&path, mode);
        path
    }

    fn dir(&self, name: &str, mode: u32) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::create_dir(&path).expect("create child directory");
        set_mode(&path, mode);
        path
    }

    fn config(&self, cert: &Path, key: &Path, acme: &Path) -> PathBuf {
        let path = self.path.join("fluxheim.toml");
        fs::write(
            &path,
            format!(
                r#"
                    [tls]
                    enabled = true

                    [[tls.certificates]]
                    cert_path = "{}"
                    key_path = "{}"

                    [tls.acme]
                    enabled = true
                    storage = "{}"
                    contact_email = "admin@example.test"
                    "#,
                cert.display(),
                key.display(),
                acme.display()
            ),
        )
        .expect("write config");
        path
    }

    fn simple_config(&self, name: &str, vhost_name: &str, host: &str) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::write(
            &path,
            format!(
                r#"
                    [[vhosts]]
                    name = "{vhost_name}"
                    hosts = ["{host}"]
                    "#
            ),
        )
        .expect("write config");
        path
    }

    #[cfg(feature = "web")]
    fn web_config(&self, name: &str, vhost_name: &str, host: &str, root: &Path) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::write(
            &path,
            format!(
                r#"
                    [[vhosts]]
                    name = "{vhost_name}"
                    hosts = ["{host}"]

                    [vhosts.web]
                    root = "{}"
                    "#,
                root.display()
            ),
        )
        .expect("write config");
        path
    }

    #[cfg(feature = "web")]
    fn route_web_config(
        &self,
        name: &str,
        vhost_name: &str,
        host: &str,
        route_name: &str,
        root: &Path,
    ) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::write(
            &path,
            format!(
                r#"
                    [[vhosts]]
                    name = "{vhost_name}"
                    hosts = ["{host}"]

                    [[vhosts.routes]]
                    name = "{route_name}"
                    path_prefix = "/assets/"

                    [vhosts.routes.web]
                    root = "{}"
                    "#,
                root.display()
            ),
        )
        .expect("write config");
        path
    }

    #[cfg(all(feature = "proxy", not(feature = "web")))]
    fn web_module_config(&self, name: &str, root: &Path) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::write(
            &path,
            format!(
                r#"
                    [[vhosts]]
                    name = "web-disabled"
                    hosts = ["web-disabled.test"]

                    [vhosts.web]
                    root = "{}"
                    "#,
                root.display()
            ),
        )
        .expect("write config");
        path
    }

    #[cfg(all(feature = "proxy", not(feature = "cache")))]
    fn cache_module_config(&self, name: &str) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::write(
            &path,
            r#"
                [[vhosts]]
                name = "cache-disabled"
                hosts = ["cache-disabled.test"]

                [vhosts.cache]
                enabled = true

                [vhosts.cache.memory]
                enabled = true
                "#,
        )
        .expect("write config");
        path
    }

    #[cfg(all(feature = "proxy", not(feature = "php-fpm")))]
    fn php_module_config(&self, name: &str, root: &Path) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::write(
            &path,
            format!(
                r#"
                    [[vhosts]]
                    name = "php-disabled"
                    hosts = ["php-disabled.test"]

                    [vhosts.php]
                    enabled = true
                    root = "{}"

                    [vhosts.php.fpm]
                    tcp = "127.0.0.1:9000"
                    allow_private_tcp_upstreams = true
                    "#,
                root.display()
            ),
        )
        .expect("write config");
        path
    }

    fn minimal_config(&self, name: &str, listen: &str) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::write(
            &path,
            format!(
                r#"
                    [server]
                    listen = ["{listen}"]
                    "#
            ),
        )
        .expect("write config");
        path
    }
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn cache_lookup_with_state(
    state: fluxheim_cache::CacheObjectFreshnessState,
) -> fluxheim_cache::CacheObjectLookup {
    let mut lookup = cache_lookup_without_objects();
    lookup.objects.push(fluxheim_cache::CacheObjectMetadata {
        tier: fluxheim_cache::CacheObjectTier::Memory,
        purge_indexed: true,
        status: 200,
        fresh: state == fluxheim_cache::CacheObjectFreshnessState::Fresh,
        freshness_state: state,
        serve_stale_while_revalidate: state == fluxheim_cache::CacheObjectFreshnessState::Stale,
        serve_stale_if_error: false,
        body_bytes: 4,
        weight_bytes: 4,
        created_unix_secs: Some(1),
        updated_unix_secs: Some(1),
        fresh_until_unix_secs: Some(2),
        age_secs: 1,
        fresh_ttl_secs: 0,
        stale_while_revalidate_secs: 30,
        stale_if_error_secs: 0,
        cache_tags: vec!["asset:logo".to_owned()],
        header_names: vec![
            "cache-control".to_owned(),
            "etag".to_owned(),
            "vary".to_owned(),
        ],
        header_values: vec![
            fluxheim_cache::CacheObjectHeaderValue {
                name: "cache-control".to_owned(),
                value: "public, max-age=60".to_owned(),
            },
            fluxheim_cache::CacheObjectHeaderValue {
                name: "etag".to_owned(),
                value: "\"cached\"".to_owned(),
            },
        ],
    });
    lookup
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn cache_lookup_without_objects() -> fluxheim_cache::CacheObjectLookup {
    fluxheim_cache::CacheObjectLookup {
        preview: fluxheim_cache::CacheKeyPreview {
            vhost: "cached".to_owned(),
            route: Some("assets".to_owned()),
            scope: fluxheim_cache::CacheKeyPreviewScope::Route,
            eligible: true,
            cache_lock_enabled: true,
            cache_lock_wait_timeout_secs: 30,
            cache_predictor_enabled: false,
            origin_protection_enabled: false,
            origin_protection_max_concurrent_fills: 32,
            peer_fill_enabled: false,
            peer_fill_peer_count: 0,
            peer_fill_max_concurrent_requests: 64,
            peer_fill_fail_open: true,
            memory_tier_enabled: true,
            disk_tier_enabled: false,
            storage_tiers: 1,
            reason: None,
            namespace: Some("fluxheim-image-v1".to_owned()),
            key_namespace: Some("route-assets-v1".to_owned()),
            primary_key: None,
            primary_hash: Some("primary".to_owned()),
            variance_hash: None,
            combined_hash: Some("primary".to_owned()),
            user_tag: Some("cached:route:assets".to_owned()),
        },
        objects: Vec::new(),
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}
