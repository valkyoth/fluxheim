use super::*;

#[test]
fn companion_incident_target_gate_currently_rejects_disabled_renewal() {
    let mut config: Config = toml::from_str(
        r#"
[tls]
enabled = true
[tls.acme]
enabled = true
storage = "unused-test-storage"
[[vhosts]]
name = "incident"
hosts = ["incident.example.test"]
[vhosts.tls]
enabled = true
[vhosts.tls.acme]
enabled = true
"#,
    )
    .unwrap();
    ensure_acme_target_exists(&config, "incident").unwrap();
    config.tls.acme.renewal.enabled = false;
    let incident_targets = fluxheim_acme::managed_acme_targets(&config);
    assert_eq!(incident_targets.len(), 1);
    assert_eq!(incident_targets[0].vhost_name, "incident");
    // documented contract: run_revoke applies this renewal-only guard before calling
    // the incident-capable library. No storage or remote operation is invoked.
    let error = ensure_acme_target_exists(&config, "incident").unwrap_err();
    assert!(error.to_string().contains("unknown ACME vhost target"));
}
