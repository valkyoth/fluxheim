use super::*;

impl NativeWasmHooks {
    pub(crate) fn access_plugin_admission_for_test(&self) -> FluxWasmAdmissionController {
        self.access_decision[0].plugin.admission.clone()
    }
}

#[tokio::test]
async fn access_union_preserves_attachment_order_and_deduplicates_shared_hooks() {
    use sha2::{Digest, Sha256};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let bytes = wat::parse_str(
        "(module (func (export \"fluxheim_access_decision\") (result i32) i32.const 1))",
    )
    .unwrap();
    let path = root.join("allow.wasm");
    std::fs::write(&path, &bytes).unwrap();
    let mut config = Config::default();
    config.wasm.enabled = true;
    config.wasm.plugin_roots = vec![root];
    config.wasm.plugins = vec![fluxheim_config::WasmPluginConfig {
        name: "allow".into(),
        path,
        sha256: Some(
            Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ),
        abi: fluxheim_config::WasmPluginAbi::FluxheimPolicyV1,
        host_call_namespace: fluxheim_config::WasmHostCallNamespace::FluxheimPolicyV1,
        wasi: Default::default(),
        phases: vec![WasmPluginPhase::AccessDecision],
        fail_mode: WasmPluginFailMode::FailClosed,
        limits: Some(
            fluxheim_config::WasmSandboxLimitsConfig {
                timeout_ms: 500,
                compile_timeout_ms: 5_000,
                ..Default::default()
            }
            .into(),
        ),
        admission: None,
    }];
    // One plugin may have multiple distinct attachments. Deduplication must
    // identify the attachment, not its plugin name or the enclosing route.
    config.wasm.attachments = [(Some("raw"), 30), (None, 20), (Some("decoded"), 10)]
        .into_iter()
        .map(|(route, priority)| WasmAttachmentConfig {
            plugin: "allow".into(),
            vhost: "app".into(),
            route: route.map(str::to_owned),
            phases: vec![WasmPluginPhase::AccessDecision],
            priority,
            admission: None,
        })
        .collect();
    let registry = NativeWasmHookRegistry::from_config(&config)
        .unwrap()
        .unwrap();
    let vhost = registry.hooks_for("app", None);
    let raw = registry.hooks_for("app", Some("raw"));
    let decoded = registry.hooks_for("app", Some("decoded"));
    assert_eq!(raw.access_decision.len(), 2);
    assert_eq!(decoded.access_decision.len(), 2);
    let scopes = [&raw, &decoded, &raw];
    let hooks = vhost.access_hooks(&scopes);
    assert_eq!(
        hooks.iter().map(|h| h.attachment_order).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(matches!(
        vhost.access_decision(&scopes).await,
        NativeWasmAccessOutcome::Allow
    ));
    assert_eq!(vhost.access_hooks(&[&raw, &raw]).len(), 2);
    assert_eq!(vhost.access_hooks(&[]).len(), 1);
}

#[test]
fn documented_wasm_symbolic_header_ids_and_limits_match_runtime() {
    for (id, value) in [(1, "standard"), (2, "api"), (3, "static"), (4, "gold")] {
        assert_eq!(
            wasm_request_header_mutation(1, id).unwrap(),
            ("x-policy-tier", value)
        );
        assert_eq!(
            wasm_response_header_mutation(2, id).unwrap(),
            ("x-fluxheim-policy-branch", value)
        );
    }
    assert_eq!(wasm_response_removable_header(3).unwrap(), "x-powered-by");
    assert!(wasm_request_header_mutation(2, 1).is_err());
    assert!(wasm_response_header_mutation(1, 1).is_err());
    assert!(wasm_response_removable_header(1).is_err());

    let mut mutations = NativeWasmHeaderMutations::default();
    for _ in 0..16 {
        // Repeated legal header sets count toward the budget, but are allowed.
        assert_eq!(
            mutations
                .push_set("x-policy-tier".into(), "gold".into())
                .unwrap(),
            0
        );
    }
    assert!(mutations.push_remove("x-powered-by".into()).is_err());
}

#[test]
fn documented_wasm_path_classes_and_cache_ids_match_runtime() {
    for (path, class) in [
        ("/", 0),
        ("/api", 1),
        ("/api/item", 1),
        ("/apiary", 0),
        ("/static", 2),
        ("/static/file", 2),
        ("/gold", 3),
        ("/gold/item", 3),
        ("/Gold", 0),
        ("/%67old", 0),
    ] {
        assert_eq!(wasm_path_class(path), class, "{path}");
    }
    for (id, value) in [(5, "mobile"), (6, "desktop")] {
        let key = wasm_cache_key_component(1, id).unwrap();
        assert_eq!((key.label, key.value), ("wasm-device-class", value));
    }
    assert!(wasm_cache_key_component(1, 0).is_err());
    assert_eq!(wasm_cache_ttl(1).unwrap().as_secs(), 1);
    assert_eq!(wasm_cache_ttl(2).unwrap().as_secs(), 300);
    assert_eq!(wasm_cache_tag(1).unwrap(), "wasm-policy");
    assert_eq!(wasm_cache_tag(2).unwrap(), "wasm-gold");
    assert_eq!(
        wasm_cache_store_header(1, 1).unwrap(),
        ("x-fluxheim-cache-policy", "wasm")
    );
    assert_eq!(
        wasm_cache_store_header(1, 2).unwrap(),
        ("x-fluxheim-cache-policy", "gold")
    );
}

#[test]
fn documented_wasm_store_chain_keeps_first_ttl_and_header() {
    let mut metadata = NativeProxyCacheStoreMetadata::default();
    for (seconds, value) in [(300, "wasm"), (1, "gold")] {
        merge_wasm_cache_store_metadata(
            &mut metadata,
            NativeProxyCacheStoreMetadata {
                ttl_override: Some(Duration::from_secs(seconds)),
                cache_tags: vec!["wasm-policy", "wasm-gold"],
                response_headers: vec![("x-fluxheim-cache-policy", value)],
            },
        );
    }
    assert_eq!(metadata.ttl_override, Some(Duration::from_secs(300)));
    assert_eq!(metadata.cache_tags, vec!["wasm-policy", "wasm-gold"]);
    assert_eq!(
        metadata.response_headers,
        vec![("x-fluxheim-cache-policy", "wasm")]
    );
}
