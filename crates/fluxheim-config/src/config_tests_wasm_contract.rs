use super::Config;
use crate::{WasmAttachmentConfig, WasmPluginPhase};

fn config(overrides: &str) -> Config {
    parse(&format!(
        r#"
        [wasm]
        enabled = true
        plugin_roots = ["/srv/fluxheim/plugins"]
        [wasm.default_limits]
        fuel = 1000
        max_memory_bytes = "1MiB"
        [wasm.default_admission]
        max_concurrent_executions = 1
        queue_limit = 1
        [[wasm.plugins]]
        name = "headers"
        path = "/srv/fluxheim/plugins/headers.wasm"
        phases = ["request-headers"]
        {overrides}
        [[vhosts]]
        name = "app"
        hosts = ["app.test"]
        [vhosts.proxy]
        upstreams = ["127.0.0.1:9000"]
        "#
    ))
}

fn parse(source: &str) -> Config {
    // Keep policy assertions native on Windows without touching its filesystem.
    let source = if cfg!(windows) {
        source
            .replace("/srv/fluxheim/plugins", "C:/fluxheim/test/plugins")
            .replace("/etc/fluxheim/plugins", "C:/fluxheim/test/plugins")
    } else {
        source.to_owned()
    };
    toml::from_str(&source).unwrap()
}

#[test]
fn documented_wasm_deployment_template_validates() {
    let guide = include_str!("../../../docs/guides/wasm-extensibility.md");
    let section = guide.split("### Access-Denial Example").nth(1).unwrap();
    let template = section.split("```toml\n").nth(1).unwrap();
    let config = parse(template.split("```").next().unwrap());
    config.validate().unwrap();
    assert_eq!(config.wasm.attachments[0].vhost, "app");
    assert_eq!(config.wasm.attachments[0].route.as_deref(), Some("admin"));
    assert_eq!(config.wasm.default_admission.max_concurrent_executions, 8);
}

#[test]
fn documented_full_wasm_override_preserves_intended_values() {
    let guide = include_str!("../../../docs/guides/wasm-extensibility.md");
    let section = guide.split("## Limits And Admission").nth(1).unwrap();
    let fragment = section.split("```toml\n").nth(1).unwrap();
    let fragment = fragment.split("```").next().unwrap().replace(
        "[wasm.attachments.admission]",
        "[[wasm.attachments]]\nplugin = \"headers\"\nvhost = \"app\"\n[wasm.attachments.admission]",
    );
    let config = config(&fragment);
    config.validate().unwrap();
    let limits = config.wasm.plugin_manifests().unwrap()[0].limits;
    assert_eq!(limits.fuel, 1000);
    assert_eq!(limits.max_memory_bytes, 1024 * 1024);
    assert_eq!(limits.timeout.as_millis(), 10);
    assert_eq!(
        config.wasm.plugins[0]
            .effective_admission(config.wasm.default_admission)
            .unwrap()
            .max_concurrent_executions,
        2
    );
    assert_eq!(
        config.wasm.attachments[0]
            .effective_admission(config.wasm.default_admission)
            .unwrap()
            .max_concurrent_executions,
        1
    );
}

#[test]
fn documented_partial_wasm_override_preserves_parent_values() {
    let guide = include_str!("../../../docs/guides/wasm-extensibility.md");
    let section = guide.split("## Limits And Admission").nth(1).unwrap();
    let fragment = section
        .split("```toml\n")
        .nth(2)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    let config = config(fragment);
    config.validate().unwrap();
    let plugin = &config.wasm.plugins[0];
    let limits = plugin.effective_limits(config.wasm.default_limits).unwrap();
    assert_eq!(limits.fuel, 1000);
    assert_eq!(limits.max_memory_bytes.as_u64(), 1024 * 1024);
    assert_eq!(limits.timeout_ms, 10);
    let admission = plugin
        .effective_admission(config.wasm.default_admission)
        .unwrap();
    assert_eq!(admission.max_concurrent_executions, 1);
    assert_eq!(admission.queue_limit, 2);
}

#[test]
fn documented_http_only_wasm_fragment_validates_with_its_complete_example() {
    let guide = include_str!("../../../docs/guides/wasm-extensibility.md");
    let fragment = guide.split("```toml\n").nth(1).unwrap();
    let fragment: toml::Value = toml::from_str(fragment.split("```").next().unwrap()).unwrap();
    let mut config = parse(include_str!(
        "../../../examples/wasm/openresty-header-policy.toml"
    ));
    config.vhosts[0].routes[0].proxy = Some(
        fragment["vhosts"]["routes"]["proxy"]
            .clone()
            .try_into()
            .unwrap(),
    );
    config.wasm.attachments = fragment["wasm"]["attachments"].clone().try_into().unwrap();
    config.validate().unwrap();
    config.vhosts[0].routes[0].proxy.as_mut().unwrap().websocket = true;
    assert!(matches!(
        config.validate(),
        Err(crate::ConfigError::InvalidWasmPolicy {
            field: "phases",
            ..
        })
    ));
}

#[test]
fn websocket_config_rejects_unsupported_wasm_phases() {
    for phase in [
        WasmPluginPhase::RouteDecision,
        WasmPluginPhase::RequestHeaders,
        WasmPluginPhase::ResponseHeaders,
    ] {
        let mut config = config("");
        config.vhosts[0].proxy.websocket = true;
        config.wasm.plugins[0].phases = vec![phase];
        config.wasm.plugins[0].sha256 = Some("a".repeat(64));
        config.wasm.attachments.push(WasmAttachmentConfig {
            plugin: "headers".to_owned(),
            vhost: "app".to_owned(),
            route: None,
            phases: vec![phase],
            priority: 1000,
            admission: None,
        });
        assert!(matches!(
            config.validate(),
            Err(crate::ConfigError::InvalidWasmPolicy {
                field: "phases",
                ..
            })
        ));
        config.vhosts[0].proxy.websocket = false;
        config.validate().unwrap();
    }
}

#[test]
fn websocket_wasm_validation_tracks_attachment_scope_and_inherited_phases() {
    for phase in [
        WasmPluginPhase::RouteDecision,
        WasmPluginPhase::RequestHeaders,
        WasmPluginPhase::ResponseHeaders,
    ] {
        let mut config = config("");
        config.wasm.plugins[0].phases = vec![phase];
        config.wasm.plugins[0].sha256 = Some("a".repeat(64));
        let http: crate::RouteConfig = toml::from_str(
            r#"
            name = "http"
            path_prefix = "/http"
            [proxy]
            upstreams = ["127.0.0.1:9000"]
        "#,
        )
        .unwrap();
        let mut socket = http.clone();
        socket.name = "socket".into();
        socket.path_prefix = Some("/socket".into());
        socket.proxy.as_mut().unwrap().websocket = true;
        config.vhosts[0].routes = vec![http, socket];
        config.wasm.attachments.push(WasmAttachmentConfig {
            plugin: "headers".into(),
            vhost: "app".into(),
            route: Some("http".into()),
            phases: vec![],
            priority: 100,
            admission: None,
        });
        config.validate().unwrap();
        for scope in [Some("socket"), None] {
            config.wasm.attachments[0].route = scope.map(str::to_owned);
            assert!(matches!(
                config.validate(),
                Err(crate::ConfigError::InvalidWasmPolicy {
                    field: "phases",
                    ..
                })
            ));
        }
        config.wasm.attachments[0].route = Some("http".into());
        config.vhosts[0].proxy.websocket = true;
        config.validate().unwrap();
        config.wasm.attachments[0].route = None;
        assert!(config.validate().is_err());
    }
}

#[test]
fn websocket_wasm_allows_supported_subset_but_not_inherited_header_phase() {
    let mut config = config("");
    config.vhosts[0].proxy.websocket = true;
    config.wasm.plugins[0].sha256 = Some("a".repeat(64));
    config.wasm.plugins[0].phases = vec![
        WasmPluginPhase::AccessDecision,
        WasmPluginPhase::RequestHeaders,
        WasmPluginPhase::CacheLookup,
        WasmPluginPhase::CacheStore,
    ];
    config.wasm.attachments.push(WasmAttachmentConfig {
        plugin: "headers".into(),
        vhost: "app".into(),
        route: None,
        phases: vec![
            WasmPluginPhase::AccessDecision,
            WasmPluginPhase::CacheLookup,
            WasmPluginPhase::CacheStore,
        ],
        priority: 100,
        admission: None,
    });
    config.validate().unwrap();
    config.wasm.attachments[0].phases.clear();
    assert!(matches!(
        config.validate(),
        Err(crate::ConfigError::InvalidWasmPolicy {
            field: "phases",
            ..
        })
    ));
    config.wasm.plugins[0].phases = vec![WasmPluginPhase::RequestHeaders];
    config.wasm.plugins[0].fail_mode = crate::WasmPluginFailMode::FailOpen;
    assert!(config.validate().is_err());
    config.vhosts[0].proxy.websocket = false;
    config.validate().unwrap();
}

#[test]
fn omitted_wasm_override_tables_use_configured_defaults() {
    let config = config("");
    config.validate().unwrap();
    let manifests = config.wasm.plugin_manifests().unwrap();
    assert_eq!(manifests[0].limits.fuel, 1000);
    assert_eq!(manifests[0].limits.max_memory_bytes, 1024 * 1024);
    assert!(config.wasm.plugins[0].admission.is_none());
}

#[test]
fn partial_wasm_limits_inherit_omitted_fields() {
    let config = config("[wasm.plugins.limits]\ntimeout_ms = 10");
    config.validate().unwrap();
    let limits = config.wasm.plugin_manifests().unwrap()[0].limits;
    assert_eq!(limits.timeout.as_millis(), 10);
    assert_eq!(limits.fuel, 1000);
    assert_eq!(limits.max_memory_bytes, 1024 * 1024);
}

#[test]
fn partial_wasm_admission_inherits_plugin_and_attachment_budgets() {
    let config = config(
        r#"
        [wasm.plugins.admission]
        queue_limit = 2
        [[wasm.attachments]]
        plugin = "headers"
        vhost = "app"
        [wasm.attachments.admission]
        queue_limit = 3
        "#,
    );
    config.validate().unwrap();
    assert_eq!(config.wasm.default_admission.max_concurrent_executions, 1);
    let plugin = config.wasm.plugins[0]
        .effective_admission(config.wasm.default_admission)
        .unwrap();
    let attachment = config.wasm.attachments[0]
        .effective_admission(config.wasm.default_admission)
        .unwrap();
    assert_eq!(plugin.max_concurrent_executions, 1);
    assert_eq!(attachment.max_concurrent_executions, 1);
    assert_eq!(plugin.queue_limit, 2);
    assert_eq!(attachment.queue_limit, 3);
}

#[test]
fn wasm_empty_overrides_and_serialization_preserve_inheritance() {
    let config = config("[wasm.plugins.limits]\n[wasm.plugins.admission]");
    config.validate().unwrap();
    let plugin = &config.wasm.plugins[0];
    assert_eq!(
        plugin.effective_limits(config.wasm.default_limits).unwrap(),
        config.wasm.default_limits
    );
    assert_eq!(
        plugin
            .effective_admission(config.wasm.default_admission)
            .unwrap(),
        config.wasm.default_admission
    );
    let serialized = toml::to_string(&config).unwrap();
    let restored: Config = toml::from_str(&serialized).unwrap();
    assert_eq!(restored.wasm, config.wasm);
}

#[test]
fn wasm_each_explicit_limit_can_reset_to_stock_without_resetting_others() {
    use crate::{WasmSandboxLimitsConfig, WasmSandboxLimitsOverride};
    let parent: WasmSandboxLimitsConfig = toml::from_str(
        r#"
        max_module_bytes = "2MiB"
        max_compiled_artifact_bytes = "64MiB"
        max_memory_bytes = "1MiB"
        max_table_elements = 500
        fuel = 1000
        timeout_ms = 10
        compile_timeout_ms = 1000
    "#,
    )
    .unwrap();
    let stock = WasmSandboxLimitsConfig::default();
    let stock_values = toml::Value::try_from(stock).unwrap();
    for (key, value) in stock_values.as_table().unwrap() {
        let mut one = toml::Table::new();
        one.insert(key.clone(), value.clone());
        let patch: WasmSandboxLimitsOverride = toml::Value::Table(one).try_into().unwrap();
        let mut expected = toml::Value::try_from(parent).unwrap();
        expected
            .as_table_mut()
            .unwrap()
            .insert(key.clone(), value.clone());
        let expected: WasmSandboxLimitsConfig = expected.try_into().unwrap();
        assert_eq!(patch.resolve(parent), expected, "{key}");
    }
    assert_eq!(
        WasmSandboxLimitsOverride::from(stock).resolve(parent),
        stock
    );
}

#[test]
fn wasm_admission_reset_and_attachment_parent_are_explicit() {
    let config = config(
        r#"
        [wasm.plugins.admission]
        max_concurrent_executions = 64
        queue_limit = 0
        [[wasm.attachments]]
        plugin = "headers"
        vhost = "app"
        [wasm.attachments.admission]
        queue_limit = 0
    "#,
    );
    config.validate().unwrap();
    let plugin = config.wasm.plugins[0]
        .effective_admission(config.wasm.default_admission)
        .unwrap();
    let attachment = config.wasm.attachments[0]
        .effective_admission(config.wasm.default_admission)
        .unwrap();
    assert_eq!(plugin.max_concurrent_executions, 64);
    assert_eq!(plugin.queue_limit, 0);
    assert_eq!(attachment.max_concurrent_executions, 1);
    assert_eq!(attachment.queue_limit, 0);
}

#[test]
fn wasm_effective_overrides_keep_validation_and_unknown_field_rejection() {
    for field in [
        "max_module_bytes",
        "max_compiled_artifact_bytes",
        "max_memory_bytes",
        "max_table_elements",
        "fuel",
        "timeout_ms",
        "compile_timeout_ms",
    ] {
        let bad = config(&format!("[wasm.plugins.limits]\n{field} = 0"));
        assert!(bad.validate().is_err(), "{field}");
        assert!(bad.wasm.plugin_manifests().is_err(), "{field}");
    }
    for field in [
        "max_concurrent_executions = 0",
        "max_concurrent_executions = 257",
        "queue_limit = 257",
    ] {
        let bad = config(&format!("[wasm.plugins.admission]\n{field}"));
        assert!(bad.validate().is_err());
        assert!(
            bad.wasm.plugins[0]
                .effective_admission(bad.wasm.default_admission)
                .is_err()
        );
    }
    assert!(toml::from_str::<crate::WasmSandboxLimitsOverride>("fuell = 1000").is_err());
    assert!(toml::from_str::<crate::WasmAdmissionBudgetOverride>("queue_limits = 1").is_err());
}

#[test]
fn wasm_fragments_merge_defaults_before_resolving_plugin_overrides() {
    let directory = super::super::TestDir::new("wasm-inheritance-fragments");
    std::fs::create_dir_all(directory.child("conf.d")).unwrap();
    let original = config("[wasm.plugins.limits]\ntimeout_ms = 10");
    let mut document = toml::Value::try_from(&original).unwrap();
    document
        .as_table_mut()
        .unwrap()
        .insert("include_conf_d".into(), toml::Value::Boolean(true));
    std::fs::write(
        directory.child("fluxheim.toml"),
        toml::to_string(&document).unwrap(),
    )
    .unwrap();
    std::fs::write(
        directory.child("conf.d/10-defaults.toml"),
        r#"
        [wasm.default_limits]
        compile_timeout_ms = 1000
        [wasm.default_admission]
        queue_limit = 0
    "#,
    )
    .unwrap();
    std::fs::write(
        directory.child("conf.d/20-empty.toml"),
        "[wasm.default_limits]\n[wasm.default_admission]",
    )
    .unwrap();
    let loaded = Config::load(Some(&directory.child("fluxheim.toml"))).unwrap();
    assert_eq!(loaded.wasm.default_limits.fuel, 1000);
    assert_eq!(loaded.wasm.default_limits.compile_timeout_ms, 1000);
    assert_eq!(loaded.wasm.default_admission.max_concurrent_executions, 1);
    assert_eq!(loaded.wasm.default_admission.queue_limit, 0);
    let effective = loaded.wasm.plugins[0]
        .effective_limits(loaded.wasm.default_limits)
        .unwrap();
    assert_eq!(effective.fuel, 1000);
    assert_eq!(effective.timeout_ms, 10);
    assert_eq!(effective.compile_timeout_ms, 1000);
}

#[test]
fn wasm_override_presence_and_inherited_changes_require_upgrade() {
    let original = config("[wasm.plugins.limits]\ntimeout_ms = 10");
    let mut changed = original.clone();
    changed.wasm.plugins[0].limits.as_mut().unwrap().fuel = Some(1000);
    assert_eq!(
        crate::reload::classify_reload(&original, &changed).to_string(),
        "process-upgrade: wasm-runtime-changed"
    );
    let mut changed = original.clone();
    changed.wasm.default_limits.fuel = 2000;
    assert_eq!(
        crate::reload::classify_reload(&original, &changed).to_string(),
        "process-upgrade: wasm-runtime-changed"
    );
}
