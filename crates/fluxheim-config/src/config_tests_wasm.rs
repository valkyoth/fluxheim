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
        sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
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
fn wasm_registry_builds_loader_manifests_with_defaults() {
    let config = base_wasm_config(
        r#"
        [[wasm.attachments]]
        plugin = "headers"
        vhost = "app"
        phases = ["request-headers"]
        "#,
    );

    config.validate().unwrap();
    let manifests = config.wasm.plugin_manifests().unwrap();

    assert_eq!(manifests.len(), 2);
    assert_eq!(manifests[0].name, "headers");
    assert_eq!(manifests[0].expected_sha256, None);
    assert_eq!(
        manifests[0].abi,
        fluxheim_wasm::WasmPluginAbi::FluxheimPolicyV1
    );
    assert_eq!(
        manifests[0].phases,
        vec![
            fluxheim_wasm::WasmPluginPhase::RequestHeaders,
            fluxheim_wasm::WasmPluginPhase::ResponseHeaders,
        ]
    );
    assert_eq!(manifests[0].limits.max_module_bytes, 1_048_576);
    assert_eq!(manifests[0].limits.max_memory_bytes, 16 * 1024 * 1024);
    fluxheim_wasm::validate_plugin_manifest(manifests[0].clone(), false).unwrap();
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_builds_loader_manifest_with_plugin_overrides() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]

        [wasm.default_limits]
        max_module_bytes = "2MiB"
        max_memory_bytes = "32MiB"
        max_table_elements = 20000
        fuel = 6000000
        timeout_ms = 60
        compile_timeout_ms = 600

        [[wasm.plugins]]
        name = "headers"
        path = "/srv/fluxheim/plugins/headers.wasm"
        sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        phases = ["request-headers"]

        [wasm.plugins.limits]
        max_module_bytes = "3MiB"
        max_memory_bytes = "64MiB"
        max_table_elements = 30000
        fuel = 7000000
        timeout_ms = 70
        compile_timeout_ms = 700

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#,
    )
    .unwrap();

    config.validate().unwrap();
    let manifests = config.wasm.plugin_manifests().unwrap();

    assert_eq!(manifests.len(), 1);
    assert_eq!(
        manifests[0].expected_sha256.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(manifests[0].limits.max_module_bytes, 3 * 1024 * 1024);
    assert_eq!(manifests[0].limits.max_memory_bytes, 64 * 1024 * 1024);
    assert_eq!(manifests[0].limits.max_table_elements, 30000);
    assert_eq!(manifests[0].limits.fuel, 7_000_000);
    assert_eq!(
        manifests[0].limits.timeout,
        std::time::Duration::from_millis(70)
    );
    assert_eq!(
        manifests[0].limits.compile_timeout,
        std::time::Duration::from_millis(700)
    );
    fluxheim_wasm::validate_plugin_manifest(manifests[0].clone(), false).unwrap();
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
        sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
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
fn wasm_registry_rejects_plugin_outside_roots() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]

        [[wasm.plugins]]
        name = "headers"
        path = "/opt/other/headers.wasm"
        phases = ["request-headers"]

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidWasmPolicy { field: "path", .. })
    ));
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_rejects_broad_plugin_roots() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/etc"]

        [[wasm.plugins]]
        name = "headers"
        path = "/etc/headers.wasm"
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
            field: "wasm.plugin_roots",
            ..
        })
    ));
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_requires_sha256_for_security_decision_plugins() {
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

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidWasmPolicy {
            field: "sha256",
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
