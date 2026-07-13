use super::super::*;
use crate::ResponseHeaderRewriteRuleConfig;
use crate::config_header_hardening::reporting_endpoints_header_value;
use crate::{ResponseHardeningProfile, ResponsePermissionsPolicyConfig};

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

#[test]
fn parses_opt_in_response_hardening_and_reporting_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.response]
            content_security_policy_report_only = "default-src 'self'; report-to csp"
            cross_origin_opener_policy = "same-origin-allow-popups"
            cross_origin_resource_policy = "same-site"
            cross_origin_embedder_policy = "credentialless"
            x_permitted_cross_domain_policies = "none"

            [headers.response.hardening]
            profile = "baseline"

            [headers.response.permissions_policy]
            profile = "deny-all"

            [headers.response.reporting_endpoints]
            csp = "https://reports.example.test/csp"
            "#,
    )
    .unwrap();

    let response = &config.headers.response;
    assert_eq!(
        response.hardening.profile,
        ResponseHardeningProfile::Baseline
    );
    assert_eq!(
        response
            .permissions_policy
            .as_ref()
            .and_then(ResponsePermissionsPolicyConfig::header_value),
        Some(
            "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), storage-access=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()"
        )
    );
    config.validate().unwrap();
}

#[test]
fn response_hardening_is_off_by_default() {
    assert_eq!(
        Config::default().headers.response.hardening.profile,
        ResponseHardeningProfile::Off
    );
}

#[test]
fn validates_cors_credentials_and_origins() {
    let wildcard_credentials: Config = toml::from_str(
        r#"
            [headers.cors]
            enabled = true
            allow_origins = ["*"]
            allow_credentials = true
            "#,
    )
    .unwrap();
    assert_eq!(
        wildcard_credentials.validate(),
        Err(ConfigError::InvalidResponseHeaderValue {
            field: "headers.cors"
        })
    );

    let invalid_origin: Config = toml::from_str(
        r#"
            [headers.cors]
            enabled = true
            allow_origins = ["https://example.test/path"]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_origin.validate(),
        Err(ConfigError::InvalidResponseHeaderValue {
            field: "headers.cors"
        })
    );
}

#[test]
fn validates_effective_inherited_cors_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.cors]
            enabled = true
            allow_origins = ["https://app.example.test"]
            allow_credentials = true

            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.headers.cors]
            allow_origins = ["*"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::VhostSection {
            section: "headers",
            ..
        })
    ));
}

#[test]
fn allows_vhost_to_enable_inherited_cors_origins() {
    let config: Config = toml::from_str(
        r#"
            [headers.cors]
            allow_origins = ["https://app.example.test"]
            allow_credentials = true

            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.headers.cors]
            enabled = true
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    let effective = config.headers.with_vhost_overlay(&config.vhosts[0].headers);
    assert!(effective.cors.enabled);
    assert_eq!(effective.cors.allow_origins, ["https://app.example.test"]);
}

#[test]
fn rejects_invalid_reporting_endpoint_url() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.reporting_endpoints]
            csp = "file:///tmp/report"
            "#,
    )
    .unwrap();
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.response.reporting_endpoints",
            name: "csp".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_reporting_endpoint_dictionary_members() {
    for name in ["CSP", "1csp", "csp+production"] {
        let mut config = Config::default();
        config.headers.response.reporting_endpoints.insert(
            name.to_owned(),
            "https://reports.example.test/csp".to_owned(),
        );
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidHeaderValue {
                field: "headers.response.reporting_endpoints",
                ..
            })
        ));
    }

    for endpoint in [
        "http://reports.example.test/csp",
        "https://reports.example.test/csp-\u{00e5}",
    ] {
        let mut config = Config::default();
        config
            .headers
            .response
            .reporting_endpoints
            .insert("csp".to_owned(), endpoint.to_owned());
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidHeaderValue {
                field: "headers.response.reporting_endpoints",
                ..
            })
        ));
    }
}

#[test]
fn serializes_reporting_endpoints_as_bounded_structured_fields() {
    let endpoints = std::collections::BTreeMap::from([
        (
            "csp".to_owned(),
            "https://reports.example.test/csp\"primary".to_owned(),
        ),
        (
            "network-errors".to_owned(),
            "https://reports.example.test/network\\errors".to_owned(),
        ),
    ]);
    assert_eq!(
        reporting_endpoints_header_value(&endpoints).as_deref(),
        Some(
            "csp=\"https://reports.example.test/csp\\\"primary\", network-errors=\"https://reports.example.test/network\\\\errors\""
        )
    );

    let oversized = (0..9)
        .map(|index| {
            (
                format!("endpoint-{index}"),
                format!("https://reports.example.test/{}", "a".repeat(2000)),
            )
        })
        .collect();
    assert_eq!(reporting_endpoints_header_value(&oversized), None);
}
