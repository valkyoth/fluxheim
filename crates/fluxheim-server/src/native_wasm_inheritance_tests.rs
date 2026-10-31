use super::*;
use fluxheim_config::{ByteSize, WasmAdmissionBudgetOverride, WasmSandboxLimitsOverride};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::task::Poll;

fn fixture(source: &str) -> (tempfile::TempDir, Config) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let bytes = wat::parse_str(source).unwrap();
    let path = root.join("policy.wasm");
    std::fs::write(&path, &bytes).unwrap();
    let mut config = Config::default();
    config.wasm.enabled = true;
    config.wasm.plugin_roots = vec![root];
    config.wasm.default_limits.fuel = 1000;
    config.wasm.default_limits.max_memory_bytes = ByteSize::from_bytes(1024 * 1024);
    config.wasm.default_limits.compile_timeout_ms = 5000;
    config.wasm.default_admission.max_concurrent_executions = 1;
    config.wasm.plugins = vec![fluxheim_config::WasmPluginConfig {
        name: "policy".into(),
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
        limits: Some(WasmSandboxLimitsOverride {
            timeout_ms: Some(500),
            ..Default::default()
        }),
        admission: Some(WasmAdmissionBudgetOverride {
            queue_limit: Some(1),
            ..Default::default()
        }),
    }];
    config.wasm.attachments = vec![WasmAttachmentConfig {
        plugin: "policy".into(),
        vhost: "app".into(),
        route: None,
        phases: vec![WasmPluginPhase::AccessDecision],
        priority: 100,
        admission: Some(WasmAdmissionBudgetOverride {
            queue_limit: Some(1),
            ..Default::default()
        }),
    }];
    (directory, config)
}

async fn decision(config: &Config) -> NativeWasmAccessOutcome {
    let registry = NativeWasmHookRegistry::from_config(config)
        .unwrap()
        .unwrap();
    registry.hooks_for("app", None).access_decision(&[]).await
}

#[tokio::test]
async fn partial_timeout_override_retains_real_module_fuel_limit() {
    let (_directory, mut config) = fixture(
        r#"(module
        (func (export "fluxheim_access_decision") (result i32) (local $n i32)
            i32.const 1000 local.set $n
            (loop $again
                local.get $n i32.const 1 i32.sub local.tee $n br_if $again)
            i32.const 1))"#,
    );
    assert!(matches!(
        decision(&config).await,
        NativeWasmAccessOutcome::Deny { status: 503, .. }
    ));
    config.wasm.plugins[0].limits.as_mut().unwrap().fuel = Some(100_000);
    assert!(matches!(
        decision(&config).await,
        NativeWasmAccessOutcome::Allow
    ));
}

#[tokio::test]
async fn partial_timeout_override_retains_real_module_memory_limit() {
    let (_directory, mut config) = fixture(
        r#"(module (memory 32)
        (func (export "fluxheim_access_decision") (result i32) i32.const 1))"#,
    );
    assert!(matches!(
        decision(&config).await,
        NativeWasmAccessOutcome::Deny { status: 503, .. }
    ));
    config.wasm.plugins[0]
        .limits
        .as_mut()
        .unwrap()
        .max_memory_bytes = Some(ByteSize::from_bytes(2 * 1024 * 1024));
    assert!(matches!(
        decision(&config).await,
        NativeWasmAccessOutcome::Allow
    ));
}

#[tokio::test]
async fn queue_only_overrides_retain_active_caps_and_release_cancelled_admission() {
    let (_directory, config) = fixture(
        r#"(module
        (func (export "fluxheim_access_decision") (result i32) i32.const 1))"#,
    );
    for plugin_scope in [false, true] {
        let registry = NativeWasmHookRegistry::from_config(&config)
            .unwrap()
            .unwrap();
        let hooks = registry.hooks_for("app", None);
        let hook = &hooks.access_decision[0];
        let admission = if plugin_scope {
            &hook.plugin.admission
        } else {
            &hook.attachment_admission
        };
        let held = admission.try_acquire().unwrap();
        let mut pending = Box::pin(hook.run_access_decision());
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(admission.active_executions(), 1);
        assert_eq!(admission.queued_executions(), 1);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), admission.acquire())
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(hook.global_admission.active_executions(), 0);
        drop(pending);
        assert_eq!(admission.queued_executions(), 0);
        drop(held);
        assert_eq!(hook.plugin.admission.active_executions(), 0);
        assert_eq!(hook.attachment_admission.active_executions(), 0);
        assert!(matches!(
            hook.run_access_decision().await,
            WasmAccessDecision::Allow
        ));
        assert_eq!(hook.plugin.admission.active_executions(), 0);
        assert_eq!(hook.attachment_admission.active_executions(), 0);
    }
}
