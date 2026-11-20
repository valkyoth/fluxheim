use super::*;

fn inventory_config(root: &std::path::Path, names: &[&str]) -> Config {
    let mut config = Config::default();
    config.tls.enabled = true;
    config.tls.acme.enabled = true;
    config.tls.acme.renewal.enabled = false;
    config.tls.acme.storage = Some(root.into());
    for &name in names {
        let mut vhost: fluxheim_config::VhostConfig = toml::from_str("name = 'fixture'").unwrap();
        vhost.name = name.into();
        vhost.tls.enabled = true;
        vhost.tls.acme.enabled = true;
        config.vhosts.push(vhost);
    }
    config
}

fn inventory(config: &Config, vhost: Option<&str>, now: i64) -> (bool, String) {
    let mut out = Vec::new();
    let result = off_status::write_inventory(config, vhost, now, &mut out);
    (result.is_ok(), String::from_utf8(out).unwrap())
}

#[test]
fn off_status_lists_every_managed_leaf_and_filters_before_reading() {
    let dir = tempfile::tempdir_in(fluxheim_common::test_support::test_root()).unwrap();
    let root = dir.path().join("storage");
    let mut config = inventory_config(
        &root,
        &["missing", "bad", "blocked", "healthy", "unmanaged"],
    );
    config.vhosts.last_mut().unwrap().tls.acme.enabled = false;
    let (ok, output) = inventory(&config, Some("missing"), 1800000000);
    assert!(!ok);
    assert!(
        output.contains("target: missing status=missing renewal=off not_after=missing"),
        "{output}"
    );
    assert!(!root.exists());
    let cert = |name| fluxheim_acme::managed_certificate_paths(&root, name).cert_path;
    for name in ["bad", "healthy"] {
        std::fs::create_dir_all(cert(name).parent().unwrap()).unwrap();
    }
    std::fs::write(cert("bad"), b"not a certificate").unwrap();
    std::fs::create_dir_all(cert("blocked")).unwrap();
    std::fs::write(
        cert("healthy"),
        include_bytes!("../tests/fixtures/tls/localhost-cert.pem"),
    )
    .unwrap();
    let (ok, output) = inventory(&config, None, 1800000000);
    assert!(!ok);
    for marker in [
        "acme status targets: 4",
        "target: bad status=invalid",
        "target: blocked status=unreadable",
        "target: healthy status=valid",
    ] {
        assert!(output.contains(marker), "{output}");
    }
    assert!(!output.contains("unmanaged"));
    let (ok, output) = inventory(&config, Some("healthy"), 1800000000);
    assert!(ok && output.contains("acme status targets: 1") && !output.contains("target: bad"));
    assert!(!inventory(&config, Some("unknown"), 1800000000).0);
    config.vhosts.clear();
    assert!(inventory(&config, None, 1800000000).0);
}

#[test]
fn off_status_uses_leaf_dates_including_exact_warning_and_expiry_boundaries() {
    let dir = tempfile::tempdir_in(fluxheim_common::test_support::test_root()).unwrap();
    let config = inventory_config(dir.path(), &["dates"]);
    let target = fluxheim_acme::managed_acme_targets(&config).pop().unwrap();
    let path = &target.certificate.cert_path;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        include_bytes!("../tests/fixtures/tls/localhost-cert.pem"),
    )
    .unwrap();
    let (start, end) = fluxheim_acme::inspect_managed_leaf_validity(&target)
        .unwrap()
        .unwrap();
    for (now, expected) in [
        (start - 1, "not-yet-valid"),
        (start, "valid"),
        (end - 7 * 86400 - 1, "valid"),
        (end - 7 * 86400, "expiring"),
        (end - 1, "expiring"),
        (end, "expired"),
        (end + 1, "expired"),
    ] {
        let (ok, output) = inventory(&config, None, now);
        assert_eq!(ok, expected == "valid");
        assert!(
            output.contains(&format!("status={expected} renewal=off not_after={end}")),
            "{output}"
        );
    }
}

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
