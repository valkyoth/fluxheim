use super::*;

#[test]
fn parses_vhost_routes() {
    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]
            max_request_body_bytes = "128MiB"

            [vhosts.acme_challenge]
            enabled = true
            upstreams = ["127.0.0.1:8080"]

            [[vhosts.routes]]
            name = "chat"
            path_prefix = "/chat/"
            methods = ["GET", "HEAD"]
            https_redirect_exempt = true
            strip_prefix = "/chat/"
            rewrite_prefix = "/backend/chat/"

            [vhosts.routes.grpc]
            enabled = true

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            upstream_http_version = "http2"
            connect_timeout_secs = 5
            read_timeout_secs = 600
            send_timeout_secs = 600

            [[vhosts.routes]]
            name = "repo"
            path_prefix = "/repo"
            strip_prefix = "/repo"

            [vhosts.routes.web]
            root = "/srv/repo"

            [[vhosts.routes]]
            name = "versioned-api"
            path_regex = "^/api/v(?P<version>[0-9]+)/(?P<rest>.*)$"
            rewrite_template = "/internal/v{route.regex.version}/{route.regex.rest}"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6013"]

            [[vhosts.routes]]
            name = "fallback"
            fallback = true

            [vhosts.routes.redirect]
            to = "https://gateway.example{uri}"
            status = 308
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.vhosts[0].routes.len(), 4);
    assert_eq!(
        config.vhosts[0].max_request_body_bytes,
        Some(ByteSize::from_bytes(128 * 1024 * 1024))
    );
    assert!(config.vhosts[0].acme_challenge.enabled);
    assert_eq!(
        config.vhosts[0].acme_challenge.upstreams,
        ["127.0.0.1:8080"]
    );
    assert_eq!(config.vhosts[0].routes[0].name, "chat");
    assert_eq!(config.vhosts[0].routes[0].methods, ["GET", "HEAD"]);
    assert!(config.vhosts[0].routes[0].grpc.enabled);
    assert!(config.vhosts[0].routes[0].https_redirect_exempt);
    assert_eq!(
        config.vhosts[0].routes[0].rewrite_prefix.as_deref(),
        Some("/backend/chat/")
    );
    assert_eq!(
        config.vhosts[0].routes[2].rewrite_template.as_deref(),
        Some("/internal/v{route.regex.version}/{route.regex.rest}")
    );
    assert_eq!(
        config.vhosts[0].routes[0]
            .proxy
            .as_ref()
            .unwrap()
            .primary_upstream(),
        "127.0.0.1:6012"
    );
    assert_eq!(
        config.vhosts[0].routes[0]
            .proxy
            .as_ref()
            .unwrap()
            .read_timeout_secs,
        Some(600)
    );
    assert_eq!(
        config.vhosts[0].routes[0]
            .proxy
            .as_ref()
            .unwrap()
            .upstream_http_version,
        UpstreamHttpVersion::Http2
    );
    assert_eq!(
        config.vhosts[0].routes[3].redirect.as_ref().unwrap().status,
        308
    );
}

#[test]
fn validates_regex_route_opt_in() {
    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "versioned-api"
            path_regex = "^/api/v[0-9]+/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    config.validate().unwrap();
}

#[test]
fn rejects_regex_route_without_server_opt_in() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "versioned-api"
            path_regex = "^/api/v[0-9]+/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::RouteRegexDisabled {
            vhost: "gateway".to_owned(),
            route: "versioned-api".to_owned(),
        })
    );
}

#[test]
fn rejects_invalid_regex_route_pattern() {
    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_regex = "["

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRegex {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );
}

#[test]
fn rejects_grpc_route_without_http2_upstream() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "grpc"
            path_prefix = "/grpc/"

            [vhosts.routes.grpc]
            enabled = true

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:6012"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("grpc policy is invalid") && error.contains("upstream_http_version"),
        "{error}"
    );
}

#[test]
fn rejects_invalid_vhost_body_limit() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]
            max_request_body_bytes = "0B"

            [vhosts.proxy]
            upstreams = ["127.0.0.1:6010"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidVhostLimit {
            vhost,
            field: "max_request_body_bytes"
        }) if vhost == "gateway"
    ));
}
