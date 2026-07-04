use super::{Config, ConfigError};

#[cfg(feature = "wasm")]
fn base_wasm_config(extra: &str) -> Config {
    toml::from_str(&format!(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]

        [[wasm.plugins]]
        name = "headers"
        path = "/srv/fluxheim/plugins/headers.wasm"
        phases = ["request-headers", "response-headers"]

        [[wasm.plugins]]
        name = "access"
        path = "/srv/fluxheim/plugins/access.wasm"
        phases = ["access-decision"]

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]

        {extra}
        "#
    ))
    .unwrap()
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_and_attachments_validate() {
    let config = base_wasm_config(
        r#"
        [[wasm.attachments]]
        plugin = "headers"
        vhost = "app"
        phases = ["request-headers"]

        [[vhosts.routes]]
        name = "api"
        path_prefix = "/api/"

        [vhosts.routes.proxy]
        upstreams = ["127.0.0.1:9000"]

        [[wasm.attachments]]
        plugin = "headers"
        vhost = "app"
        route = "api"
        phases = ["response-headers"]

        [wasm.attachments.admission]
        max_concurrent_executions = 8
        queue_limit = 4
        "#,
    );

    config.validate().unwrap();
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_attachment_rejects_unknown_plugin() {
    let config = base_wasm_config(
        r#"
        [[wasm.attachments]]
        plugin = "missing"
        vhost = "app"
        phases = ["request-headers"]
        "#,
    );

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnknownWasmPlugin { .. })
    ));
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_attachment_rejects_phase_not_declared_by_plugin() {
    let config = base_wasm_config(
        r#"
        [[wasm.attachments]]
        plugin = "headers"
        vhost = "app"
        phases = ["access-decision"]
        "#,
    );

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidWasmPolicy {
            field: "wasm.phases",
            ..
        })
    ));
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_rejects_fail_open_security_decision() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]

        [[wasm.plugins]]
        name = "access"
        path = "/srv/fluxheim/plugins/access.wasm"
        phases = ["access-decision"]
        fail_mode = "fail-open"

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidWasmPolicy {
            field: "fail_mode",
            ..
        })
    ));
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_rejects_invalid_admission_budget() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]

        [wasm.default_admission]
        max_concurrent_executions = 0

        [[wasm.plugins]]
        name = "headers"
        path = "/srv/fluxheim/plugins/headers.wasm"
        phases = ["request-headers"]

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidWasmPolicy {
            field: "max_concurrent_executions",
            ..
        })
    ));
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_requires_enabled_flag_for_plugins() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [[wasm.plugins]]
        name = "headers"
        path = "/srv/fluxheim/plugins/headers.wasm"
        phases = ["request-headers"]

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidWasmPolicy {
            field: "enabled",
            ..
        })
    ));
}

#[cfg(not(feature = "wasm"))]
#[test]
fn wasm_registry_rejects_when_wasm_feature_is_absent() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::WasmNotCompiled));
}
