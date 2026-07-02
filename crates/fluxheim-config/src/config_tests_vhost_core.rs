use super::*;

#[test]
fn parses_vhosts() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "example.com"
            hosts = ["example.com", "www.example.com"]

            [vhosts.proxy]
            upstream = "127.0.0.1:3001"

            [vhosts.web]
            root = "/srv/sites/example"

            [vhosts.cache]
            enabled = true

            [vhosts.cache.memory]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(config.vhosts.len(), 1);
    assert!(config.vhosts[0].cache.enabled);
    assert_eq!(
        config.vhosts[0].normalized_hosts(),
        ["example.com".to_owned(), "www.example.com".to_owned()]
    );
    config.validate().unwrap();
}

#[test]
fn parses_vhost_and_route_access_policy() {
    let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.access]
            allow = ["10.0.0.0/8", "2001:db8::/32"]
            deny = ["10.9.0.0/16"]
            require_client_cert = true
            allow_client_cert_sha256 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

            [vhosts.rate_limit]
            enabled = true
            requests_per_second = 10
            burst = 20
            mode = "delay"
            max_delay_ms = 250

            [vhosts.concurrency]
            enabled = true
            max_in_flight = 100
            max_queue = 300
            queue_timeout_ms = 100

            [[vhosts.routes]]
            name = "admin"
            path_prefix = "/admin/"

            [vhosts.routes.access]
            allow = ["10.1.2.3"]

            [vhosts.routes.rate_limit]
            enabled = true
            requests_per_second = 2
            burst = 4
            status = 429

            [vhosts.routes.concurrency]
            enabled = true
            max_in_flight = 10
            max_queue = 20
            queue_timeout_ms = 50

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:3000"
            "#,
        )
        .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.vhosts[0].access.allow,
        ["10.0.0.0/8", "2001:db8::/32"]
    );
    assert_eq!(config.vhosts[0].access.deny, ["10.9.0.0/16"]);
    assert!(config.vhosts[0].access.require_client_cert);
    assert_eq!(
        config.vhosts[0].access.allow_client_cert_sha256,
        ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    );
    assert_eq!(config.vhosts[0].routes[0].access.allow, ["10.1.2.3"]);
    assert_eq!(config.vhosts[0].rate_limit.requests_per_second, 10);
    assert_eq!(config.vhosts[0].rate_limit.mode, RateLimitMode::Delay);
    assert_eq!(config.vhosts[0].rate_limit.max_delay_ms, 250);
    assert_eq!(config.vhosts[0].routes[0].rate_limit.burst, 4);
    assert_eq!(config.vhosts[0].concurrency.max_in_flight, 100);
    assert_eq!(config.vhosts[0].concurrency.max_queue, 300);
    assert_eq!(config.vhosts[0].concurrency.queue_timeout_ms, 100);
    assert_eq!(config.vhosts[0].routes[0].concurrency.max_in_flight, 10);
    assert_eq!(config.vhosts[0].routes[0].concurrency.max_queue, 20);
    assert_eq!(config.vhosts[0].routes[0].concurrency.queue_timeout_ms, 50);
}

#[test]
fn rejects_invalid_vhost_access_rule() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.access]
            allow = ["10.0.0.0/99"]

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("vhosts.access.allow"), "{error}");
}

#[test]
fn rejects_invalid_vhost_client_cert_access_fingerprint() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.access]
            allow_client_cert_sha256 = ["not-a-sha256"]

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("vhosts.access.allow_client_cert_sha256"),
        "{error}"
    );
}

#[test]
fn rejects_invalid_vhost_rate_limit() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.rate_limit]
            enabled = true
            requests_per_second = 0

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("vhosts.rate_limit.requests_per_second"),
        "{error}"
    );
}

#[test]
fn rejects_invalid_vhost_concurrency_limit() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.concurrency]
            enabled = true
            max_in_flight = 0

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("vhosts.concurrency.max_in_flight"),
        "{error}"
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.concurrency]
            enabled = true
            max_in_flight = 1
            max_queue = 1000001

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("vhosts.concurrency.max_queue"), "{error}");
}
