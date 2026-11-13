use super::{FluxProxy, NativeProxySnapshot};
use fluxheim_cache::{CacheKeyPreviewScope, NativeCachePreviewRequest};

fn snapshot(source: &str) -> NativeProxySnapshot {
    FluxProxy::from_config(&toml::from_str(source).unwrap())
        .unwrap()
        .snapshot()
}

fn request(host: &str, path: &str) -> NativeCachePreviewRequest {
    let mut request = NativeCachePreviewRequest::build("GET", path.as_bytes(), None).unwrap();
    request.insert_header("host", host).unwrap();
    request
}

const ROOT: &str = r#"
[proxy]
upstream = "127.0.0.1:9"
[cache]
enabled = true
extensions = ["css"]
include_query = true
[cache.memory]
enabled = true
"#;

#[test]
fn root_preview_has_explicit_scope_without_a_fictitious_vhost() {
    let snapshot = snapshot(ROOT);
    let request = request("cache.test", "/asset.css?v=1");
    let preview = snapshot.native_image_cache_key_preview_for_request(&request);
    assert!(preview.eligible, "{preview:?}");
    assert_eq!(preview.scope, CacheKeyPreviewScope::Root);
    assert_eq!(preview.scope.as_str(), "root");
    assert_eq!(preview.vhost, "");
    assert_eq!(preview.route, None);
    assert_eq!(preview.user_tag.as_deref(), Some("root"));
    let expected = fluxheim_cache::image_cache_key(
        &snapshot.config.cache,
        &fluxheim_cache::CacheRequest {
            method: "GET",
            host: Some("cache.test"),
            path: "/asset.css",
            query: Some("v=1"),
        },
    )
    .unwrap();
    assert_eq!(preview.primary_key.as_deref(), Some(expected.as_str()));
    let other = snapshot
        .native_image_cache_key_preview_for_request(&self::request("other.test", "/asset.css?v=1"));
    assert_ne!(preview.primary_key, other.primary_key);
    let other = snapshot
        .native_image_cache_key_preview_for_request(&self::request("cache.test", "/asset.css?v=2"));
    assert_ne!(preview.primary_key, other.primary_key);
    assert!(
        snapshot
            .native_image_cache_object_lookup_for_request(&request)
            .unwrap()
            .objects
            .is_empty()
    );
}

#[test]
fn preview_rejects_disabled_unsafe_methods_and_request_bypasses() {
    let snapshot = snapshot(ROOT);
    for (name, value, reason) in [
        ("authorization", "Bearer fixture", "request-authorization"),
        (
            "proxy-authorization",
            "Basic fixture",
            "request-proxy-authorization",
        ),
        ("cache-control", "no-store", "request-no-store"),
    ] {
        let mut request = request("cache.test", "/asset.css");
        request.insert_header(name, value).unwrap();
        let preview = snapshot.native_image_cache_key_preview_for_request(&request);
        assert!(!preview.eligible);
        assert_eq!(preview.reason.as_deref(), Some(reason));
        assert!(
            snapshot
                .native_image_cache_object_lookup_for_request(&request)
                .unwrap()
                .objects
                .is_empty()
        );
    }
    for path in ["/../asset.css", "/%2e%2e/asset.css", "/asset.txt"] {
        assert!(
            !snapshot
                .native_image_cache_key_preview_for_request(&request("cache.test", path))
                .eligible,
            "{path}"
        );
    }
    let mut head = request("cache.test", "/asset.css");
    head.method = http::Method::HEAD;
    assert!(
        !snapshot
            .native_image_cache_key_preview_for_request(&head)
            .eligible
    );
    let disabled = self::snapshot(&ROOT.replace("enabled = true", "enabled = false"));
    assert_eq!(
        disabled
            .native_image_cache_key_preview_for_request(&request("cache.test", "/asset.css"))
            .reason
            .as_deref(),
        Some("cache disabled")
    );
}

#[test]
fn preview_obeys_exact_longest_wildcard_and_strict_hosts() {
    let mut config: crate::config::Config = toml::from_str(ROOT).unwrap();
    for (name, hosts) in [
        ("fallback", vec!["fallback.test"]),
        ("wide", vec!["*.test"]),
        ("narrow", vec!["*.sub.test"]),
        ("exact", vec!["a.sub.test"]),
    ] {
        let mut vhost: crate::config::VhostConfig = toml::from_str("name = 'fixture'").unwrap();
        vhost.name = name.into();
        vhost.hosts = hosts.into_iter().map(str::to_owned).collect();
        vhost.cache = config.cache.clone();
        vhost.proxy = config.proxy.clone();
        config.vhosts.push(vhost);
    }
    config.server.default_vhost = Some("fallback".into());
    for strict in [false, true] {
        config.server.host_routing.strict = strict;
        let snapshot = FluxProxy::from_config(&config).unwrap().snapshot();
        for (host, expected) in [
            ("A.SUB.TEST:80", "exact"),
            ("b.sub.test", "narrow"),
            ("sub.test", "wide"),
            ("test", "fallback"),
            ("unknown.invalid", "fallback"),
        ] {
            let preview =
                snapshot.native_image_cache_key_preview_for_request(&request(host, "/asset.css"));
            if strict && expected == "fallback" {
                assert!(!preview.eligible);
                assert!(preview.vhost.is_empty());
                assert!(
                    snapshot
                        .native_image_cache_object_lookup_for_request(&request(host, "/asset.css"))
                        .unwrap()
                        .objects
                        .is_empty()
                );
            } else {
                assert_eq!(preview.vhost, expected);
                assert!(preview.eligible, "{preview:?}");
            }
        }
    }
}

#[test]
fn matching_route_never_inherits_fallback_cache_and_precedence_is_preserved() {
    let snapshot = snapshot(
        r#"
[[vhosts]]
name = "site"
hosts = ["cache.test"]
[vhosts.proxy]
upstream = "127.0.0.1:9"
[vhosts.cache]
enabled = true
extensions = ["css"]
[vhosts.cache.memory]
enabled = true
[[vhosts.routes]]
name = "regex"
path_regex = "^/assets/.*"
[vhosts.routes.proxy]
upstream = "127.0.0.1:9"
[vhosts.routes.cache]
enabled = true
[vhosts.routes.cache.memory]
enabled = true
[[vhosts.routes]]
name = "prefix"
path_prefix = "/assets"
[vhosts.routes.proxy]
upstream = "127.0.0.1:9"
[vhosts.routes.cache]
enabled = true
[vhosts.routes.cache.memory]
enabled = true
[[vhosts.routes]]
name = "exact"
path_exact = "/assets/asset.css"
[vhosts.routes.proxy]
upstream = "127.0.0.1:9"
"#,
    );
    for (path, route, eligible) in [
        ("/assets/asset.css", Some("exact"), false),
        ("/assets/other.css", Some("prefix"), true),
        ("/other.css", None, true),
    ] {
        let preview =
            snapshot.native_image_cache_key_preview_for_request(&request("cache.test", path));
        assert_eq!(preview.route.as_deref(), route);
        assert_eq!(preview.eligible, eligible, "{preview:?}");
    }
}

#[test]
fn standalone_bin_lookup_is_explicitly_unsupported_before_opening_storage() {
    let mut snapshot = snapshot(ROOT);
    snapshot.config.cache.disk.enabled = true;
    snapshot.config.cache.disk.backend = crate::config::CacheDiskBackend::StorageBin;
    for memory in [false, true] {
        snapshot.config.cache.memory.enabled = memory;
        let error = snapshot
            .native_image_cache_object_lookup_for_request(&request("cache.test", "/asset.css"))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}

#[test]
fn admin_scopes_remain_explicit_vhosts_not_a_root_alias() {
    let proxy = FluxProxy::from_config(&toml::from_str(ROOT).unwrap()).unwrap();
    assert!(
        proxy
            .cache_config_for_request(None, None, "cache.test")
            .is_err()
    );
    assert!(
        proxy
            .cache_config_for_request(Some("root"), None, "cache.test")
            .is_err()
    );
    assert!(proxy.cache_runtime_stats().unwrap().vhosts.is_empty());
}

#[test]
fn named_root_is_not_root_policy_and_root_mode_ignores_strict_host_setting() {
    let mut root = snapshot(ROOT);
    root.config.server.host_routing.strict = true;
    assert!(
        root.native_image_cache_key_preview_for_request(&request("any.test", "/asset.css"))
            .eligible
    );
    let named = snapshot(&format!(
        "{ROOT}\n{}",
        r#"
[[vhosts]]
name = "root"
hosts = ["cache.test"]
[vhosts.proxy]
upstream = "127.0.0.1:9"
[vhosts.cache]
enabled = false
"#
    ));
    let preview =
        named.native_image_cache_key_preview_for_request(&request("cache.test", "/asset.css"));
    assert_eq!(preview.scope, CacheKeyPreviewScope::Vhost);
    assert_eq!(preview.vhost, "root");
    assert!(
        !preview.eligible,
        "root cache must not override the named site's disabled policy"
    );
}

#[test]
fn repeated_headers_keep_earlier_bypass_values() {
    let snapshot = snapshot(ROOT);
    let mut request = request("cache.test", "/asset.css");
    request.headers.append(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    request.headers.append(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("public"),
    );
    let preview = snapshot.native_image_cache_key_preview_for_request(&request);
    assert!(!preview.eligible);
    assert_eq!(preview.reason.as_deref(), Some("request-no-store"));
}
