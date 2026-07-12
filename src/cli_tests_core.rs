use super::*;
#[test]
fn cache_keygen_hex_encoder_is_lowercase() {
    assert_eq!(
        super::super::hex_encode_lower(&[0x00, 0x0f, 0x10, 0xab, 0xff]),
        "000f10abff"
    );
}

#[test]
fn cache_keygen_command_succeeds() {
    run_from_args(["fluxheim", "cache-keygen"]).unwrap();
}

#[test]
fn check_tls_storage_accepts_secure_files() {
    let dir = TestDir::new("cli-tls-secure");
    let cert = dir.file("fullchain.pem", 0o644);
    let key = dir.file("key.pem", 0o600);
    let acme = dir.dir("acme", 0o700);
    let config = dir.config(&cert, &key, &acme);

    run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "--check-tls-storage",
    ])
    .unwrap();
}

#[cfg(unix)]
#[test]
fn check_tls_storage_rejects_insecure_private_key() {
    let dir = TestDir::new("cli-tls-insecure-key");
    let cert = dir.file("fullchain.pem", 0o644);
    let key = dir.file("key.pem", 0o644);
    let acme = dir.dir("acme", 0o700);
    let config = dir.config(&cert, &key, &acme);

    let error = run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "--check-tls-storage",
    ])
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "TLS storage check failed with 1 issue(s)"
    );
}

#[test]
fn reload_from_accepts_snapshot_safe_changes() {
    let dir = TestDir::new("cli-reload-snapshot");
    let old_config = dir.simple_config("old.toml", "one", "one.example");
    let new_config = dir.simple_config("new.toml", "two", "two.example");

    run_from_args([
        "fluxheim",
        "--reload-from",
        old_config.to_str().unwrap(),
        "--config",
        new_config.to_str().unwrap(),
    ])
    .unwrap();
}

#[test]
fn reload_from_accepts_process_upgrade_changes() {
    let dir = TestDir::new("cli-reload-process-upgrade");
    let old_config = dir.minimal_config("old.toml", "127.0.0.1:8080");
    let new_config = dir.minimal_config("new.toml", "127.0.0.1:8081");

    run_from_args([
        "fluxheim",
        "--reload-from",
        old_config.to_str().unwrap(),
        "--config",
        new_config.to_str().unwrap(),
    ])
    .unwrap();
}

#[test]
fn validate_config_accepts_valid_config() {
    let dir = TestDir::new("cli-validate-config");
    let config = dir.simple_config("fluxheim.toml", "example", "example.test");

    run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "--validate-config",
    ])
    .unwrap();
}

#[cfg(all(feature = "proxy", feature = "cache"))]
#[test]
fn runtime_validation_runs_structural_config_validation() {
    let config: crate::config::Config = toml::from_str(
        r#"
            [cache]
            enabled = true

            [cache.memory]
            enabled = true

            [cache.peer_fill]
            enabled = true

            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.proxy]
            upstreams = ["127.0.0.1:8081"]
            "#,
    )
    .unwrap();

    let error = super::super::validate_runtime_config(&config).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("peer fill requires between 1 and 32 peers")
    );
}

#[cfg(feature = "web")]
#[test]
fn validate_config_rejects_missing_static_root() {
    let dir = TestDir::new("cli-validate-missing-root");
    let missing_root = safe_child_path(&dir.path, "missing-site");
    let config = dir.web_config("fluxheim.toml", "example", "example.test", &missing_root);

    let error = run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "--validate-config",
    ])
    .unwrap_err();

    let error = error.to_string();
    assert!(error.contains("vhost \"example\" web"));
    assert!(error.contains("web root does not exist"));
}

#[cfg(feature = "web")]
#[test]
fn validate_config_rejects_missing_route_static_root_with_context() {
    let dir = TestDir::new("cli-validate-missing-route-root");
    let missing_root = safe_child_path(&dir.path, "missing-route-site");
    let config = dir.route_web_config(
        "fluxheim.toml",
        "example",
        "example.test",
        "assets",
        &missing_root,
    );

    let error = run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "--validate-config",
    ])
    .unwrap_err();

    let error = error.to_string();
    assert!(error.contains("vhost \"example\" route \"assets\" web"));
    assert!(error.contains("web root does not exist"));
}

#[cfg(not(feature = "acme-client"))]
#[test]
fn acme_renew_requires_acme_client_feature() {
    let error = run_from_args(["fluxheim", "acme-renew"]).unwrap_err();

    assert!(error.to_string().contains("acme-client"));
}

#[cfg(not(feature = "acme-client"))]
#[test]
fn acme_init_requires_acme_client_feature() {
    let error = run_from_args(["fluxheim", "acme-init", "actalis"]).unwrap_err();

    assert!(error.to_string().contains("acme-client"));
}

#[cfg(feature = "acme-client")]
#[test]
fn acme_init_actalis_writes_config_and_credential_files() {
    let dir = TestDir::new("cli-acme-init-actalis");
    let kid_input = dir.file("kid-input", 0o600);
    let hmac_input = dir.file("hmac-input", 0o600);
    fs::write(&kid_input, "kid-123\n").unwrap();
    fs::write(&hmac_input, "hmac-456\n").unwrap();
    let conf_dir = dir.dir("conf.d", 0o755);
    let output = conf_dir.join("acme.toml");
    let secrets_dir = dir.path.join("secrets");
    let systemd_dir = dir.path.join("systemd");
    let storage = dir.path.join("acme-storage");

    run_from_args([
        "fluxheim",
        "acme-init",
        "actalis",
        "--email",
        "admin@example.test",
        "--kid-file",
        kid_input.to_str().unwrap(),
        "--hmac-key-file",
        hmac_input.to_str().unwrap(),
        "--terms-of-service-url",
        "https://issuer.example.test/terms/v1",
        "--accept-terms-of-service",
        "--output",
        output.to_str().unwrap(),
        "--secrets-dir",
        secrets_dir.to_str().unwrap(),
        "--systemd-dropin-dir",
        systemd_dir.to_str().unwrap(),
        "--storage",
        storage.to_str().unwrap(),
        "--non-interactive",
    ])
    .unwrap();

    assert_eq!(
        fs::read_to_string(secrets_dir.join("actalis-eab-kid")).unwrap(),
        "kid-123\n"
    );
    assert_eq!(
        fs::read_to_string(secrets_dir.join("actalis-eab-hmac-key")).unwrap(),
        "hmac-456\n"
    );
    assert!(systemd_dir.join("actalis-eab.conf").exists());
    let config = fs::read_to_string(output).unwrap();
    assert!(config.contains("default_issuer = \"actalis\""));
    assert!(config.contains("automation = \"external\""));
    assert!(config.contains("key_id_credential = \"actalis-eab-kid\""));
    assert!(config.contains("hmac_key_credential = \"actalis-eab-hmac-key\""));
    assert!(config.contains("terms_of_service_agreed = true"));
    assert!(config.contains("terms_of_service_url = \"https://issuer.example.test/terms/v1\""));
}

#[cfg(feature = "acme-client")]
#[test]
fn acme_init_requires_explicit_terms_acceptance() {
    let error = run_from_args([
        "fluxheim",
        "acme-init",
        "letsencrypt",
        "--email",
        "admin@example.test",
        "--non-interactive",
    ])
    .unwrap_err();

    assert!(error.to_string().contains("terms-of-service"));
}

#[test]
fn snapshot_command_creates_store_snapshot() {
    let dir = TestDir::new("cli-snapshot-command");
    let config = dir.simple_config("fluxheim.toml", "example", "example.test");

    run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "snapshot",
        "--store",
        dir.path.join("store").to_str().unwrap(),
        "--message",
        "known good",
    ])
    .unwrap();

    let store = fluxheim_snapshot::SnapshotStore::new(dir.path.join("store"));
    assert_eq!(store.list().unwrap().len(), 1);
    assert!(store.current_id().unwrap().is_some());
}

#[test]
fn rollback_command_selects_previous_snapshot() {
    let dir = TestDir::new("cli-rollback-command");
    let store_path = dir.path.join("store");
    let store = fluxheim_snapshot::SnapshotStore::new(&store_path);
    let first = store
        .snapshot_config(&crate::config::Config::default(), Some("first"))
        .unwrap();
    let config = crate::config::Config {
        proxy: crate::config::ProxyConfig {
            upstream: Some("127.0.0.1:4000".to_owned()),
            ..crate::config::ProxyConfig::default()
        },
        ..crate::config::Config::default()
    };
    store.snapshot_config(&config, Some("second")).unwrap();

    run_from_args([
        "fluxheim",
        "rollback",
        "--store",
        store_path.to_str().unwrap(),
    ])
    .unwrap();

    assert_eq!(store.current_id().unwrap(), Some(first.id));
}
