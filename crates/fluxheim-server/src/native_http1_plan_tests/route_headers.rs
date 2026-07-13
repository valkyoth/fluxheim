use crate::{NativeHttp1ProxyCutoverStatus, ServerPlan};
use fluxheim_config::{CacheConfig, Config, RouteConfig, VhostConfig};

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_disabled_request_headers() {
    let mut config = Config::default();
    let mut route_headers = fluxheim_config::VhostHeaderPolicyConfig::default();
    route_headers.request.enabled = Some(false);
    config.vhosts = vec![VhostConfig {
        name: "native.test".to_owned(),
        hosts: vec!["native.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy: fluxheim_config::ProxyConfig::disabled(),
        cache: CacheConfig::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: vec![RouteConfig {
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
            proxy: Some(fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3002".to_owned()],
                ..Default::default()
            }),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: route_headers,
        }],
    }];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_regex_rewrite_template() {
    let mut config = Config::default();
    config.server.regex_enabled = true;
    config.vhosts = vec![VhostConfig {
        name: "native.test".to_owned(),
        hosts: vec!["native.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy: fluxheim_config::ProxyConfig::disabled(),
        cache: CacheConfig::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: vec![RouteConfig {
            name: "api".to_owned(),
            path_exact: None,
            path_prefix: None,
            path_regex: Some(r"^/api/v(?P<version>[0-9]+)/(?P<rest>.*)$".to_owned()),
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: Some(
                "/internal/v{route.regex.version}/{route.regex.rest}".to_owned(),
            ),
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3002".to_owned()],
                ..Default::default()
            }),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: Default::default(),
        }],
    }];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_prefix_rewrite() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig::disabled(),
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: vec![RouteConfig {
                name: "api".to_owned(),
                path_exact: None,
                path_prefix: Some("/api/".to_owned()),
                path_regex: None,
                methods: Vec::new(),
                fallback: false,
                https_redirect_exempt: false,
                strip_prefix: Some("/api".to_owned()),
                rewrite_prefix: None,
                rewrite_template: None,
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                grpc: Default::default(),
                redirect: None,
                proxy: Some(fluxheim_config::ProxyConfig {
                    upstreams: vec!["127.0.0.1:3002".to_owned()],
                    ..Default::default()
                }),
                web: None,
                php: None,
                cache: None,
                compression: None,
                headers: Default::default(),
            }],
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_response_header_overlay() {
    let mut response_headers = fluxheim_config::ResponseHeaderPolicyOverlayConfig::default();
    response_headers
        .set
        .insert("x-route".to_owned(), "native".to_owned());
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig::disabled(),
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: vec![RouteConfig {
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
                proxy: Some(fluxheim_config::ProxyConfig {
                    upstreams: vec!["127.0.0.1:3002".to_owned()],
                    ..Default::default()
                }),
                web: None,
                php: None,
                cache: None,
                compression: None,
                headers: fluxheim_config::VhostHeaderPolicyConfig {
                    request: Default::default(),
                    response: response_headers,
                    cors: Default::default(),
                },
            }],
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_request_header_mutation() {
    let mut request_headers = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        unset: vec!["x-remove".to_owned()],
        ..Default::default()
    };
    request_headers
        .set
        .insert("x-route".to_owned(), "native".to_owned());
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig::disabled(),
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: vec![RouteConfig {
                name: "api".to_owned(),
                path_exact: None,
                path_prefix: Some("/api/".to_owned()),
                path_regex: None,
                methods: Vec::new(),
                fallback: false,
                https_redirect_exempt: false,
                strip_prefix: Some("/api".to_owned()),
                rewrite_prefix: None,
                rewrite_template: None,
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                grpc: Default::default(),
                redirect: None,
                proxy: Some(fluxheim_config::ProxyConfig {
                    upstreams: vec!["127.0.0.1:3002".to_owned()],
                    ..Default::default()
                }),
                web: None,
                php: None,
                cache: None,
                compression: None,
                headers: fluxheim_config::VhostHeaderPolicyConfig {
                    request: request_headers,
                    response: Default::default(),
                    cors: Default::default(),
                },
            }],
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let summary = plan.native_http1_proxy_cutover_summary();

    assert_eq!(summary.status(), NativeHttp1ProxyCutoverStatus::NativeReady);
    assert_eq!(summary.total(), 1);
    assert_eq!(summary.eligible(), 1);
    assert_eq!(summary.unsupported(), 0);
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_forwarded_append_policy() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig::disabled(),
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: vec![RouteConfig {
                name: "api".to_owned(),
                path_exact: None,
                path_prefix: Some("/api/".to_owned()),
                path_regex: None,
                methods: Vec::new(),
                fallback: false,
                https_redirect_exempt: false,
                strip_prefix: Some("/api".to_owned()),
                rewrite_prefix: None,
                rewrite_template: None,
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                grpc: Default::default(),
                redirect: None,
                proxy: Some(fluxheim_config::ProxyConfig {
                    upstreams: vec!["127.0.0.1:3002".to_owned()],
                    ..Default::default()
                }),
                web: None,
                php: None,
                cache: None,
                compression: None,
                headers: fluxheim_config::VhostHeaderPolicyConfig {
                    request: fluxheim_config::RequestHeaderPolicyOverlayConfig {
                        x_forwarded_for: Some(fluxheim_config::ForwardedClientIpHeaderMode::Append),
                        ..Default::default()
                    },
                    response: Default::default(),
                    cors: Default::default(),
                },
            }],
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_owned_forwarded_policy() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig::disabled(),
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: vec![RouteConfig {
                name: "api".to_owned(),
                path_exact: None,
                path_prefix: Some("/api/".to_owned()),
                path_regex: None,
                methods: Vec::new(),
                fallback: false,
                https_redirect_exempt: false,
                strip_prefix: Some("/api".to_owned()),
                rewrite_prefix: None,
                rewrite_template: None,
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                grpc: Default::default(),
                redirect: None,
                proxy: Some(fluxheim_config::ProxyConfig {
                    upstreams: vec!["127.0.0.1:3002".to_owned()],
                    ..Default::default()
                }),
                web: None,
                php: None,
                cache: None,
                compression: None,
                headers: fluxheim_config::VhostHeaderPolicyConfig {
                    request: fluxheim_config::RequestHeaderPolicyOverlayConfig {
                        x_forwarded_for: Some(fluxheim_config::ForwardedClientIpHeaderMode::Off),
                        x_real_ip: Some(true),
                        x_forwarded_host: Some(true),
                        x_forwarded_proto: Some(true),
                        forwarded: Some(true),
                        ..Default::default()
                    },
                    response: Default::default(),
                    cors: Default::default(),
                },
            }],
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
}
