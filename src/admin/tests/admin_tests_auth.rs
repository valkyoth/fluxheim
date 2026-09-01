use super::*;
#[test]
fn rejects_unknown_paths_and_methods() {
    assert_eq!(
        app()
            .handle("GET", "/missing", None, &auth_headers())
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app()
            .handle("POST", "/_fluxheim/status", None, &auth_headers())
            .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[test]
fn bearer_token_comparison_checks_full_string() {
    let token = AdminToken::new("secret-token", false);
    assert!(authorized(Some("Bearer secret-token"), &token));
    assert!(!authorized(Some("Bearer secret"), &token));
    assert!(!authorized(Some("Bearer secret-token-extra"), &token));
    assert!(!constant_time_eq(b"secret", &token));
    assert!(!authorized(
        Some(&format!(
            "Bearer {}",
            "a".repeat(super::super::MAX_ADMIN_TOKEN_BYTES + 1)
        )),
        &token
    ));
}

#[test]
fn certificate_fingerprint_comparison_uses_exact_length_match() {
    let fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let values = vec![fingerprint.to_owned()];

    assert!(admin_fingerprint_list_contains(&values, fingerprint));
    assert!(!admin_fingerprint_list_contains(
        &values,
        &fingerprint[..63]
    ));
    assert!(!admin_fingerprint_list_contains(
        &values,
        &format!("{fingerprint}a")
    ));
}

#[test]
fn admin_client_certificate_policy_requires_trusted_fingerprint_header() {
    let app = app_with_config(Config {
        admin: AdminConfig {
            client_certificate: AdminClientCertificateConfig {
                required: true,
                allow_sha256: vec![
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                ],
                ..AdminClientCertificateConfig::default()
            },
            ..AdminConfig::default()
        },
        ..Config::default()
    });

    assert_eq!(
        app.handle("GET", "/_fluxheim/status", None, &auth_headers())
            .status,
        StatusCode::FORBIDDEN
    );

    let mut headers = auth_headers();
    headers.insert(
        "x-client-cert-sha256",
        HeaderValue::from_static(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    );
    assert_eq!(
        app.handle("GET", "/_fluxheim/status", None, &headers)
            .status,
        StatusCode::OK
    );
}

#[test]
fn admin_client_certificate_policy_denies_blocked_fingerprint() {
    let app = app_with_config(Config {
        admin: AdminConfig {
            client_certificate: AdminClientCertificateConfig {
                deny_sha256: vec![
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
                ],
                ..AdminClientCertificateConfig::default()
            },
            ..AdminConfig::default()
        },
        ..Config::default()
    });

    let mut headers = auth_headers();
    headers.insert(
        "x-client-cert-sha256",
        HeaderValue::from_static(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    );

    assert_eq!(
        app.handle("GET", "/_fluxheim/status", None, &headers)
            .status,
        StatusCode::FORBIDDEN
    );
}

#[test]
fn admin_token_file_must_be_regular_file() {
    let dir = TestDir::new("admin-token-directory");
    let token_dir = dir.path.join("admin-token-dir");
    std::fs::create_dir(&token_dir).unwrap();

    let error = read_secret_file(&token_dir).unwrap_err();

    assert!(
        error.to_string().contains("must be a regular file"),
        "unexpected error: {error}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn admin_token_file_must_not_be_symlink() {
    let dir = TestDir::new("admin-token-symlink");
    let token_file = dir.path.join("admin-token");
    let token_link = dir.path.join("admin-token-link");
    std::fs::write(&token_file, "secret-token\n").unwrap();
    std::os::unix::fs::symlink(&token_file, &token_link).unwrap();

    let error = read_secret_file(&token_link).unwrap_err();

    assert!(error.to_string().contains("without following symlinks"));
}

#[cfg(unix)]
#[test]
fn admin_token_file_must_not_be_below_symlinked_directory() {
    let dir = TestDir::new("admin-token-parent-symlink");
    let real_dir = dir.path.join("real");
    let linked_dir = dir.path.join("linked");
    std::fs::create_dir(&real_dir).unwrap();
    std::fs::write(real_dir.join("admin-token"), "secret-token\n").unwrap();
    std::os::unix::fs::symlink(&real_dir, &linked_dir).unwrap();

    let error = read_secret_file(&linked_dir.join("admin-token")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("must not be below a symlinked directory")
    );
}

#[cfg(unix)]
#[test]
fn admin_token_file_must_not_be_below_world_writable_directory() {
    let token_file =
        unique_world_writable_child("admin-token-world-writable-parent", "admin-token");
    std::fs::write(&token_file, "secret-token\n").unwrap();

    let error = read_secret_file(&token_file).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("must not be below a group- or world-writable directory")
    );
    let _ = std::fs::remove_file(token_file);
}

#[cfg(unix)]
#[test]
fn admin_token_file_must_not_be_below_group_writable_directory() {
    let token_file =
        unique_group_writable_child("admin-token-group-writable-parent", "admin-token");
    std::fs::write(&token_file, "secret-token\n").unwrap();

    let error = read_secret_file(&token_file).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("must not be below a group- or world-writable directory")
    );
    let _ = std::fs::remove_file(token_file);
}

#[test]
fn admin_token_file_has_size_limit() {
    let dir = TestDir::new("admin-token-large");
    let token_file = dir.path.join("admin-token");
    std::fs::write(
        &token_file,
        vec![b'a'; (MAX_ADMIN_TOKEN_FILE_BYTES + 1) as usize],
    )
    .unwrap();

    let error = read_secret_file(&token_file).unwrap_err();

    assert!(error.to_string().contains("is too large"));
}

#[test]
fn admin_token_read_is_bounded() {
    let dir = TestDir::new("admin-token-bounded-read");
    let token_file = dir.path.join("admin-token");
    std::fs::write(&token_file, b"123456789").unwrap();
    let file = std::fs::File::open(&token_file).unwrap();

    let error = read_bounded_secret_file(file, &token_file, 8).unwrap_err();

    assert!(error.to_string().contains("exceeded 8 bytes"));
}
