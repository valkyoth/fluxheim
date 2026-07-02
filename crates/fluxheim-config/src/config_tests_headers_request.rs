use super::super::*;
use crate::{
    ForwardedClientIpHeaderMode, MAX_HEADER_APPEND_VALUES, MAX_HEADER_MUTATION_NAMES,
    RequestHeaderPolicyConfig,
};

#[test]
fn parses_request_header_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.request]
            enabled = true
            strip_inbound_client_ip_headers = true
            x_forwarded_for = "append"
            x_real_ip = true
            x_forwarded_host = false
            x_forwarded_proto = true
            forwarded = true
            unset = ["x-powered-by"]

            [headers.request.set]
            host = "backend.internal"
            x-proxy-by = "Fluxheim"

            [headers.request.append]
            via = "fluxheim"
            "#,
    )
    .unwrap();

    let policy = &config.headers.request;
    assert!(policy.enabled);
    assert!(policy.strip_inbound_client_ip_headers);
    assert_eq!(policy.x_forwarded_for, ForwardedClientIpHeaderMode::Append);
    assert!(policy.x_real_ip);
    assert!(!policy.x_forwarded_host);
    assert!(policy.x_forwarded_proto);
    assert!(policy.forwarded);
    assert_eq!(policy.unset, ["x-powered-by"]);
    assert_eq!(
        policy.set.get("host").map(String::as_str),
        Some("backend.internal")
    );
    assert_eq!(
        policy.set.get("x-proxy-by").map(String::as_str),
        Some("Fluxheim")
    );
    assert_eq!(
        policy
            .append
            .get("via")
            .and_then(|values| values.iter().next()),
        Some("fluxheim")
    );
    config.validate().unwrap();
}

#[test]
fn request_header_policy_default_matches_deserialization_for_real_ip() {
    let config: Config = toml::from_str(
        r#"
            [headers.request]
            enabled = true
            "#,
    )
    .unwrap();

    assert!(RequestHeaderPolicyConfig::default().x_real_ip);
    assert!(config.headers.request.x_real_ip);
    config.validate().unwrap();
}

#[test]
fn validates_dynamic_request_header_values() {
    let config: Config = toml::from_str(
        r#"
            [headers.request.add]
            host = "{host}"
            x-real-ip = "{remote_addr}"
            x-forwarded-proto = "{scheme}"
            x-original-uri = "{uri}"
            x-original-path = "{path}"
            x-original-query = "{query}"
            x-request-id = "{request_id}"
            upgrade = "{http.upgrade}"
            "#,
    )
    .unwrap();

    config.validate().unwrap();

    let config: Config = toml::from_str(
        r#"
            [headers.request.add]
            x-bad = "{client_ip}"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderTemplate {
            field: "headers.request",
            name: "x-bad".to_owned(),
            variable: "client_ip".to_owned(),
        })
    );
}

#[test]
fn rejects_tls_identity_request_header_append() {
    let config: Config = toml::from_str(
        r#"
            [headers.request.append]
            x-client-cert-sha256 = "{tls.client_cert_sha256}"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::UnsafeTlsHeaderAppend {
            field: "headers.request",
            name: "x-client-cert-sha256".to_owned(),
        })
    );
}

#[test]
fn parses_user_friendly_header_operations() {
    let config: Config = toml::from_str(
        r#"
            [headers.request]
            remove = ["x-powered-by"]

            [headers.request.add]
            x-internal-route = "true"

            [headers.request.operations]
            remove = ["server"]
            add = { x-extra-route = "edge" }

            [headers.response]
            remove = ["x-origin-banner"]

            [headers.response.operations]
            remove = ["x-debug"]
            add = { cache-control = "public, max-age=60" }
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.headers.request.effective_unset(),
        ["x-powered-by", "server"]
    );
    assert_eq!(
        config
            .headers
            .request
            .effective_set()
            .get("x-internal-route")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        config
            .headers
            .request
            .effective_set()
            .get("x-extra-route")
            .map(String::as_str),
        Some("edge")
    );
    assert!(
        config
            .headers
            .response
            .effective_unset()
            .contains(&"x-origin-banner".to_owned())
    );
    assert!(
        config
            .headers
            .response
            .effective_unset()
            .contains(&"x-debug".to_owned())
    );
    assert_eq!(
        config
            .headers
            .response
            .effective_set()
            .get("cache-control")
            .map(String::as_str),
        Some("public, max-age=60")
    );
}

#[test]
fn rejects_conflicting_header_add_aliases() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.set]
            cache-control = "public, max-age=60"

            [headers.response.add]
            Cache-Control = "private, no-store"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::ConflictingHeaderAdd {
            field: "headers.response",
            name: "Cache-Control".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "api"
            hosts = ["api.example.test"]

            [vhosts.headers.request.add]
            x-route = "api"

            [vhosts.headers.request.operations]
            add = { x-route = "legacy" }
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "api".to_owned(),
            section: "headers",
            source: Box::new(ConfigError::ConflictingHeaderAdd {
                field: "vhosts.headers.request",
                name: "x-route".to_owned()
            })
        })
    );
}

#[test]
fn rejects_too_many_header_unset_operations() {
    let headers = (0..=MAX_HEADER_MUTATION_NAMES)
        .map(|index| format!("\"x-remove-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [headers.request]
            remove = [{headers}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderMutationLength {
            field: "headers.request",
            operation: "unset",
            max: MAX_HEADER_MUTATION_NAMES,
        })
    );
}

#[test]
fn rejects_too_many_header_set_operations() {
    let headers = (0..=MAX_HEADER_MUTATION_NAMES)
        .map(|index| format!("\"x-set-{index}\" = \"value\""))
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&format!(
        r#"
            [headers.response.add]
            {headers}
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderMutationLength {
            field: "headers.response",
            operation: "set",
            max: MAX_HEADER_MUTATION_NAMES,
        })
    );
}

#[test]
fn rejects_too_many_header_append_operations() {
    let headers = (0..=MAX_HEADER_MUTATION_NAMES)
        .map(|index| format!("\"x-append-{index}\" = \"value\""))
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "api"
            hosts = ["api.example.test"]

            [vhosts.headers.response.append]
            {headers}
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "api".to_owned(),
            section: "headers",
            source: Box::new(ConfigError::InvalidHeaderMutationLength {
                field: "vhosts.headers.response",
                operation: "append",
                max: MAX_HEADER_MUTATION_NAMES,
            })
        })
    );
}

#[test]
fn rejects_too_many_header_append_values() {
    let values = (0..=MAX_HEADER_APPEND_VALUES)
        .map(|index| format!("\"value-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [headers.response.append]
            vary = [{values}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderMutationLength {
            field: "headers.response",
            operation: "append values",
            max: MAX_HEADER_APPEND_VALUES,
        })
    );
}
