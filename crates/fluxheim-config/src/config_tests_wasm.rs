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
fn irules_access_policy_example_config_validates() {
    let config: Config = toml::from_str(include_str!(
        "../../../examples/wasm/irules-access-policy.toml"
    ))
    .unwrap();

    assert_eq!(config.validate(), Ok(()));
}

#[cfg(feature = "wasm")]
fn proxy_preview_wasm_config(plugin_fields: &str) -> Config {
    toml::from_str(&format!(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        allow_preview_abi = true
        plugin_roots = ["/srv/fluxheim/plugins"]

        [[wasm.plugins]]
        name = "proxy_preview"
        path = "/srv/fluxheim/plugins/proxy_preview.wasm"
        sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        {plugin_fields}
        phases = ["access-decision"]

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#
    ))
    .unwrap()
}

#[cfg(feature = "wasm")]
fn wasi_preview_wasm_config(plugin_fields: &str) -> Config {
    toml::from_str(&format!(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        allow_preview_abi = true
        plugin_roots = ["/srv/fluxheim/plugins"]

        [[wasm.plugins]]
        name = "wasi_preview"
        path = "/srv/fluxheim/plugins/wasi_preview.wasm"
        sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        phases = ["access-decision"]
        {plugin_fields}

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
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
        priority = 100
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
        priority = 200
        phases = ["response-headers"]

        [wasm.attachments.admission]
        max_concurrent_executions = 8
        queue_limit = 4
        "#,
    );

    config.validate().unwrap();
    assert_eq!(config.wasm.attachments[0].priority, 100);
    assert_eq!(config.wasm.attachments[1].priority, 200);
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_orders_attachments_by_priority_then_declaration_order() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]

        [[wasm.plugins]]
        name = "third"
        path = "/srv/fluxheim/plugins/third.wasm"
        phases = ["request-headers"]

        [[wasm.plugins]]
        name = "first"
        path = "/srv/fluxheim/plugins/first.wasm"
        phases = ["request-headers"]

        [[wasm.plugins]]
        name = "second"
        path = "/srv/fluxheim/plugins/second.wasm"
        phases = ["request-headers"]

        [[wasm.attachments]]
        plugin = "third"
        vhost = "app"
        priority = 30
        phases = ["request-headers"]

        [[wasm.attachments]]
        plugin = "first"
        vhost = "app"
        priority = 10
        phases = ["request-headers"]

        [[wasm.attachments]]
        plugin = "second"
        vhost = "app"
        priority = 10
        phases = ["request-headers"]

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#,
    )
    .unwrap();

    config.validate().unwrap();
    let ordered = config
        .wasm
        .ordered_attachments()
        .into_iter()
        .map(|attachment| attachment.plugin.as_str())
        .collect::<Vec<_>>();

    assert_eq!(ordered, vec!["first", "second", "third"]);
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
fn wasm_registry_rejects_limits_above_runtime_hard_ceiling() {
    let mut cases = Vec::new();

    let mut config = base_wasm_config("");
    config.wasm.default_limits.max_module_bytes = super::ByteSize::from_bytes(16 * 1024 * 1024 + 1);
    cases.push(("max_module_bytes", config));

    let mut config = base_wasm_config("");
    config.wasm.default_limits.max_memory_bytes =
        super::ByteSize::from_bytes(256 * 1024 * 1024 + 1);
    cases.push(("max_memory_bytes", config));

    let mut config = base_wasm_config("");
    config.wasm.default_limits.max_table_elements = 100_001;
    cases.push(("max_table_elements", config));

    let mut config = base_wasm_config("");
    config.wasm.default_limits.fuel = 100_000_001;
    cases.push(("fuel", config));

    let mut config = base_wasm_config("");
    config.wasm.default_limits.timeout_ms = 5_001;
    cases.push(("timeout_ms", config));

    let mut config = base_wasm_config("");
    config.wasm.default_limits.compile_timeout_ms = 10_001;
    cases.push(("compile_timeout_ms", config));

    for (expected_field, config) in cases {
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidWasmPolicy { field, .. }) if field == expected_field
        ));
    }
}

#[cfg(all(feature = "wasm", not(feature = "wasm-proxy-abi")))]
#[test]
fn wasm_proxy_preview_namespace_requires_feature() {
    let config = proxy_preview_wasm_config(
        r#"
        abi = "proxy-wasm-preview"
        host_call_namespace = "proxy-wasm-preview"
        "#,
    );

    let error = config.validate().unwrap_err();

    assert!(
        matches!(error, ConfigError::InvalidWasmPolicy { field, reason, .. }
        if field == "host_call_namespace"
            && reason == "proxy-wasm-preview host calls require the wasm-proxy-abi feature")
    );
}

#[cfg(all(feature = "wasm", feature = "wasm-proxy-abi"))]
#[test]
fn wasm_proxy_preview_namespace_builds_loader_manifest() {
    let config = proxy_preview_wasm_config(
        r#"
        abi = "proxy-wasm-preview"
        host_call_namespace = "proxy-wasm-preview"
        "#,
    );

    config.validate().unwrap();
    let manifests = config.wasm.plugin_manifests().unwrap();
    let manifest = manifests
        .iter()
        .find(|manifest| manifest.name == "proxy_preview")
        .unwrap();

    assert_eq!(manifest.abi, fluxheim_wasm::WasmPluginAbi::ProxyWasmPreview);
    assert_eq!(
        manifest.host_call_namespace,
        fluxheim_wasm::WasmHostCallNamespace::ProxyWasmPreview
    );
    fluxheim_wasm::validate_plugin_manifest(manifest.clone(), true).unwrap();
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_proxy_preview_namespace_requires_proxy_preview_abi() {
    let config = proxy_preview_wasm_config(
        r#"
        host_call_namespace = "proxy-wasm-preview"
        "#,
    );

    let error = config.validate().unwrap_err();

    assert!(
        matches!(error, ConfigError::InvalidWasmPolicy { field, reason, .. }
        if field == "host_call_namespace"
            && reason == "proxy-wasm-preview host calls require abi = \"proxy-wasm-preview\"")
    );
}

#[cfg(all(feature = "wasm", feature = "wasm-proxy-abi"))]
#[test]
fn wasm_proxy_preview_namespace_rejects_unreviewed_phase() {
    for phase in [
        crate::WasmPluginPhase::RouteDecision,
        crate::WasmPluginPhase::CacheStore,
    ] {
        let mut config = proxy_preview_wasm_config(
            r#"
            abi = "proxy-wasm-preview"
            host_call_namespace = "proxy-wasm-preview"
            "#,
        );
        config.wasm.plugins[0].phases = vec![phase];

        let error = config.validate().unwrap_err();

        assert!(
            matches!(error, ConfigError::InvalidWasmPolicy { field, reason, .. }
            if field == "phases"
                && reason == "proxy-wasm-preview currently supports only the access-decision phase")
        );
    }
}

#[cfg(all(feature = "wasm", not(feature = "wasm-wasi")))]
#[test]
fn wasm_wasi_preview_namespace_requires_feature() {
    let config = wasi_preview_wasm_config(
        r#"
        abi = "wasi-preview"
        host_call_namespace = "wasi-preview"
        "#,
    );

    let error = config.validate().unwrap_err();

    assert!(
        matches!(error, ConfigError::InvalidWasmPolicy { field, reason, .. }
        if field == "host_call_namespace"
            && reason == "wasi-preview host calls require the wasm-wasi feature")
    );
}

#[cfg(all(feature = "wasm", feature = "wasm-wasi"))]
#[test]
fn wasm_wasi_preview_builds_capability_manifest() {
    let config = wasi_preview_wasm_config(
        r#"
        abi = "wasi-preview"
        host_call_namespace = "wasi-preview"

        [wasm.plugins.wasi]
        clocks = true
        randomness = true
        "#,
    );

    config.validate().unwrap();
    let manifests = config.wasm.plugin_manifests().unwrap();
    let manifest = manifests
        .iter()
        .find(|manifest| manifest.name == "wasi_preview")
        .unwrap();

    assert_eq!(manifest.abi, fluxheim_wasm::WasmPluginAbi::WasiPreview);
    assert_eq!(
        manifest.host_call_namespace,
        fluxheim_wasm::WasmHostCallNamespace::WasiPreview
    );
    assert!(manifest.wasi_capabilities.clocks);
    assert!(manifest.wasi_capabilities.randomness);
    fluxheim_wasm::validate_plugin_manifest(manifest.clone(), true).unwrap();
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_wasi_grants_require_wasi_preview_abi() {
    let config = base_wasm_config(
        r#"
        [wasm.plugins.wasi]
        clocks = true
        "#,
    );

    let error = config.validate().unwrap_err();

    assert!(
        matches!(error, ConfigError::InvalidWasmPolicy { field, reason, .. }
        if field == "wasi" && reason == "WASI capability grants require abi = \"wasi-preview\"")
    );
}

#[cfg(feature = "wasm-wasi")]
#[test]
fn wasm_wasi_rejects_unreviewed_capability_fields() {
    for capability in ["environment", "filesystem", "network", "inherit_stdio"] {
        let source = format!(
            r#"
            [server]
            listen = ["127.0.0.1:8080"]
            default_vhost = "app"

            [wasm]
            enabled = true
            allow_preview_abi = true
            plugin_roots = ["/srv/fluxheim/plugins"]

            [[wasm.plugins]]
            name = "wasi_preview"
            path = "/srv/fluxheim/plugins/wasi_preview.wasm"
            sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            abi = "wasi-preview"
            host_call_namespace = "wasi-preview"
            phases = ["access-decision"]

            [wasm.plugins.wasi]
            {capability} = true

            [[vhosts]]
            name = "app"
            hosts = ["app.test"]
            "#
        );

        let error = toml::from_str::<Config>(&source).unwrap_err();

        assert!(error.to_string().contains("unknown field"));
        assert!(error.to_string().contains(capability));
    }
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
fn wasm_registry_rejects_invalid_total_admission_budget() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]
        max_total_concurrent_executions = 0

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
            field: "max_total_concurrent_executions",
            ..
        })
    ));
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_rejects_invalid_preview_admission_budget() {
    for invalid in [0, 33] {
        let source = format!(
            r#"
            [server]
            listen = ["127.0.0.1:8080"]
            default_vhost = "app"

            [wasm]
            max_total_preview_concurrent_executions = {invalid}

            [[vhosts]]
            name = "app"
            hosts = ["app.test"]
            "#
        );
        let config: Config = toml::from_str(&source).unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidWasmPolicy {
                field: "max_total_preview_concurrent_executions",
                ..
            })
        ));
    }
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_rejects_execution_budgets_above_runtime_ceiling() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]
        max_total_concurrent_executions = 257

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
            field: "max_total_concurrent_executions",
            ..
        })
    ));

    let queued: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]

        [wasm.default_admission]
        queue_limit = 257

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
        queued.validate(),
        Err(ConfigError::InvalidWasmPolicy {
            field: "queue_limit",
            ..
        })
    ));
}

#[cfg(feature = "wasm")]
#[test]
fn wasm_registry_rejects_invalid_total_cache_admission_budget() {
    let config: Config = toml::from_str(
        r#"
        [server]
        listen = ["127.0.0.1:8080"]
        default_vhost = "app"

        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]
        max_total_cache_concurrent_executions = 0

        [[wasm.plugins]]
        name = "cache"
        path = "/srv/fluxheim/plugins/cache.wasm"
        sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        phases = ["cache-store"]

        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidWasmPolicy {
            field: "max_total_cache_concurrent_executions",
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
