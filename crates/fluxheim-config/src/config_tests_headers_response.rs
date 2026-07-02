use super::super::*;
use crate::ResponseHeaderRewriteRuleConfig;

#[test]
fn parses_response_header_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.response]
            enabled = true
            strict_transport_security = "max-age=31536000; includeSubDomains"
            content_security_policy = "default-src 'self'"
            x_content_type_options = "nosniff"
            x_frame_options = "SAMEORIGIN"
            referrer_policy = "strict-origin-when-cross-origin"
            unset = ["server", "x-powered-by"]

            [headers.response.set]
            cache-control = "public, max-age=60"
            access-control-allow-origin = "https://example.test"

            [headers.response.append]
            vary = ["Accept-Encoding", "Origin"]
            set-cookie = "fluxheim=1; HttpOnly; Secure; SameSite=Lax"

            [[headers.response.rewrite.location]]
            from = "http://backend.internal/"
            to = "https://example.test/"

            [[headers.response.rewrite.refresh]]
            from = "/legacy/"
            to = "/"

            [[headers.response.rewrite.cookie_domain]]
            from = "backend.internal"
            to = "example.test"

            [[headers.response.rewrite.cookie_path]]
            from = "/app/"
            to = "/"
            "#,
    )
    .unwrap();

    let policy = &config.headers.response;
    assert!(policy.enabled);
    assert_eq!(
        policy.strict_transport_security.as_deref(),
        Some("max-age=31536000; includeSubDomains")
    );
    assert_eq!(
        policy.content_security_policy.as_deref(),
        Some("default-src 'self'")
    );
    assert_eq!(policy.x_frame_options.as_deref(), Some("SAMEORIGIN"));
    assert_eq!(
        policy.referrer_policy.as_deref(),
        Some("strict-origin-when-cross-origin")
    );
    assert_eq!(policy.unset, ["server", "x-powered-by"]);
    assert_eq!(
        policy.set.get("cache-control").map(String::as_str),
        Some("public, max-age=60")
    );
    assert_eq!(
        policy
            .append
            .get("vary")
            .map(|values| values.iter().collect::<Vec<_>>()),
        Some(vec!["Accept-Encoding", "Origin"])
    );
    assert_eq!(
        policy.rewrite.location,
        [ResponseHeaderRewriteRuleConfig {
            from: "http://backend.internal/".to_owned(),
            to: "https://example.test/".to_owned()
        }]
    );
    assert_eq!(
        policy.rewrite.refresh,
        [ResponseHeaderRewriteRuleConfig {
            from: "/legacy/".to_owned(),
            to: "/".to_owned()
        }]
    );
    assert_eq!(
        policy.rewrite.cookie_domain,
        [ResponseHeaderRewriteRuleConfig {
            from: "backend.internal".to_owned(),
            to: "example.test".to_owned()
        }]
    );
    assert_eq!(
        policy.rewrite.cookie_path,
        [ResponseHeaderRewriteRuleConfig {
            from: "/app/".to_owned(),
            to: "/".to_owned()
        }]
    );
    config.validate().unwrap();
}

#[test]
fn rejects_invalid_response_header_rewrite_rules() {
    let config: Config = toml::from_str(
        r#"
            [[headers.response.rewrite.location]]
            from = "backend.internal/"
            to = "https://example.test/"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.response.rewrite",
            name: "location.from".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[headers.response.rewrite.refresh]]
            from = "https://backend.internal/"
            to = "https://example.test/"

            [[headers.response.rewrite.refresh]]
            from = "https://backend.internal/"
            to = "https://example.test/other/"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::ConflictingHeaderAdd {
            field: "headers.response.rewrite",
            name: "refresh.from".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[headers.response.rewrite.cookie_domain]]
            from = "bad domain"
            to = "example.test"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.response.rewrite",
            name: "cookie_domain.from".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[headers.response.rewrite.cookie_path]]
            from = "//backend"
            to = "/"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.response.rewrite",
            name: "cookie_path.from".to_owned()
        })
    );
}

#[test]
fn parses_structured_hsts_response_header_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.hsts]
            enabled = true
            max_age_secs = 63072000
            include_subdomains = true
            preload = true
            "#,
    )
    .unwrap();

    let hsts = config.headers.response.hsts.as_ref().unwrap();
    assert_eq!(
        hsts.header_value().as_deref(),
        Some("max-age=63072000; includeSubDomains; preload")
    );
    config.validate().unwrap();
}

#[test]
fn rejects_conflicting_hsts_response_header_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.response]
            strict_transport_security = "max-age=31536000"

            [headers.response.hsts]
            max_age_secs = 63072000
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidResponseHeaderValue {
            field: "headers.response.hsts"
        })
    );
}
