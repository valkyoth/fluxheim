use std::io;

use fluxheim_config::{PhpConfig, PhpFpmConfig};

use crate::{
    PhpFpmEndpoint, PhpFpmTimeoutKind, PhpRequestBody, create_php_request_body_spool_file,
    managed_php_fpm_instance_name_from_parts, managed_php_fpm_path_env_from,
    managed_php_fpm_restart_backoff_secs, php_fpm_effective_connect_timeout,
    php_fpm_effective_request_timeout, php_fpm_endpoints_from_config, php_fpm_error_outcome,
    php_fpm_retry_attempts, php_fpm_retry_attempts_for_endpoint_count, php_fpm_retryable_error,
    php_fpm_retryable_status, php_fpm_timeout_error, push_php_fpm_stream_chunk,
};

#[test]
fn php_request_body_replays_memory_body() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("test runtime");
    let body = PhpRequestBody::memory(b"body".to_vec());

    let mut reader = runtime.block_on(body.reader()).expect("memory reader");
    let mut replayed = Vec::new();
    runtime
        .block_on(fastcgi_client::io::AsyncReadExt::read_to_end(
            &mut reader,
            &mut replayed,
        ))
        .expect("read memory body");

    assert_eq!(body.len(), 4);
    assert_eq!(replayed, b"body");
}

#[test]
fn php_request_body_spool_replays_and_cleans_up_file() {
    let spool_dir = fluxheim_common::test_support::unique_temp_path("php-fpm-spool");
    std::fs::create_dir_all(&spool_dir).expect("spool dir");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("test runtime");
    let mut file = runtime
        .block_on(create_php_request_body_spool_file(&spool_dir))
        .expect("create spool file");
    runtime.block_on(async {
        use tokio::io::AsyncWriteExt;

        file.write_all(b"spooled-body").await.expect("write spool");
        file.flush().await.expect("flush spool");
    });

    assert_eq!(
        std::fs::read_dir(&spool_dir)
            .expect("read spool dir")
            .count(),
        0,
        "spool file must be unlinked immediately"
    );
    let body = runtime
        .block_on(PhpRequestBody::spooled(file, "spooled-body".len()))
        .expect("retain anonymous spool file");
    let mut reader = runtime.block_on(body.reader()).expect("spool reader");
    let mut replayed = Vec::new();
    runtime
        .block_on(fastcgi_client::io::AsyncReadExt::read_to_end(
            &mut reader,
            &mut replayed,
        ))
        .expect("read spool body");

    assert_eq!(replayed, b"spooled-body");
    drop(reader);
    let mut retry_reader = runtime.block_on(body.reader()).expect("retry spool reader");
    let mut retry = Vec::new();
    runtime
        .block_on(fastcgi_client::io::AsyncReadExt::read_to_end(
            &mut retry_reader,
            &mut retry,
        ))
        .expect("re-read spool body");
    assert_eq!(retry, b"spooled-body");
    drop(retry_reader);
    drop(body);
    std::fs::remove_dir(&spool_dir).expect("remove spool dir");
}

#[test]
fn php_request_body_spool_readers_keep_independent_offsets() {
    let spool_dir = fluxheim_common::test_support::unique_temp_path("php-fpm-spool-offsets");
    std::fs::create_dir_all(&spool_dir).expect("spool dir");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("test runtime");
    let expected = (0..(PHP_TEST_SPOOL_BYTES + 17))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let mut file = runtime
        .block_on(create_php_request_body_spool_file(&spool_dir))
        .expect("create spool file");
    runtime.block_on(async {
        use tokio::io::AsyncWriteExt as _;

        file.write_all(&expected).await.expect("write spool");
        file.flush().await.expect("flush spool");
    });
    let body = runtime
        .block_on(PhpRequestBody::spooled(file, expected.len()))
        .expect("retain anonymous spool file");
    let mut first = runtime.block_on(body.reader()).expect("first reader");
    let mut second = runtime.block_on(body.reader()).expect("second reader");
    let mut first_prefix = vec![0_u8; 1_003];
    let mut second_prefix = vec![0_u8; 70_001];
    let mut first_rest = Vec::new();
    let mut second_rest = Vec::new();

    runtime.block_on(async {
        use fastcgi_client::io::AsyncReadExt as _;

        first
            .read_exact(&mut first_prefix)
            .await
            .expect("first prefix");
        second
            .read_exact(&mut second_prefix)
            .await
            .expect("second prefix");
        first
            .read_to_end(&mut first_rest)
            .await
            .expect("first remainder");
        second
            .read_to_end(&mut second_rest)
            .await
            .expect("second remainder");
    });

    first_prefix.extend(first_rest);
    second_prefix.extend(second_rest);
    assert_eq!(first_prefix, expected);
    assert_eq!(second_prefix, expected);
    drop(first);
    drop(second);
    drop(body);
    std::fs::remove_dir(&spool_dir).expect("remove spool dir");
}

const PHP_TEST_SPOOL_BYTES: usize = 128 * 1024;

#[test]
fn php_fpm_stream_chunk_limit_counts_stdout_and_stderr() {
    let mut total = 0;
    let mut stdout = Vec::new();
    push_php_fpm_stream_chunk(&mut stdout, b"1234", &mut total, 6).unwrap();
    let mut stderr = Vec::new();
    let error = push_php_fpm_stream_chunk(&mut stderr, b"567", &mut total, 6)
        .expect_err("combined FastCGI output should be bounded");

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(stdout, b"1234");
    assert!(stderr.is_empty());
}

#[test]
fn php_fpm_keepalive_pool_labels_are_distinct_for_tcp_upstreams() {
    let php = PhpConfig {
        fpm: PhpFpmConfig {
            tcp_upstreams: vec!["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()],
            keepalive: true,
            ..PhpFpmConfig::default()
        },
        ..PhpConfig::default()
    };

    let pools =
        crate::php_fpm_keepalive_pools_from_config(&php, "vhost", "default", Default::default());

    assert_eq!(pools.len(), 2);
    assert_eq!(pools[0].metric_pool(), "default-0");
    assert_eq!(pools[1].metric_pool(), "default-1");
}

#[cfg(unix)]
#[test]
fn managed_php_fpm_spawn_rejects_symlinked_binary() {
    let root = tempfile::TempDir::new().expect("temp dir");
    let real_binary = root.path().join("php-fpm.real");
    let symlink_binary = root.path().join("php-fpm");
    std::fs::write(&real_binary, b"#!/bin/sh\n").expect("write real binary");
    std::os::unix::fs::symlink(&real_binary, &symlink_binary).expect("create symlink");

    let error = crate::ensure_managed_php_fpm_binary_spawn_safe("test", &symlink_binary)
        .expect_err("symlinked php-fpm binary should be rejected");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("must not be or be below a symlink")
    );
}

#[cfg(unix)]
#[test]
fn managed_php_fpm_spawn_rejects_writable_binary() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::TempDir::new().expect("temp dir");
    let binary = root.path().join("php-fpm");
    std::fs::write(&binary, b"#!/bin/sh\n").expect("write binary");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o777))
        .expect("set writable mode");

    let error = crate::ensure_managed_php_fpm_binary_spawn_safe("test", &binary)
        .expect_err("writable php-fpm binary should be rejected");

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("untrusted owner or mode"));
}

#[cfg(unix)]
#[test]
fn managed_php_fpm_spawn_rejects_writable_ancestor() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::TempDir::new().expect("temp dir");
    let writable = root.path().join("writable");
    let bin_dir = writable.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create binary tree");
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777))
        .expect("set writable ancestor");
    let binary = bin_dir.join("php-fpm");
    std::fs::write(&binary, b"#!/bin/sh\n").expect("write binary");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
        .expect("set executable mode");

    let error = crate::ensure_managed_php_fpm_binary_spawn_safe("test", &binary)
        .expect_err("binary below writable ancestor should be rejected");

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        error
            .to_string()
            .contains("untrusted or group/world-writable ancestor")
    );
}

#[test]
fn php_fpm_error_outcomes_are_bounded() {
    assert_eq!(
        php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Connect)),
        "connect_timeout"
    );
    assert_eq!(
        php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Request)),
        "request_timeout"
    );
    assert_eq!(
        php_fpm_error_outcome(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "connection refused",
        )),
        "connection_error"
    );
    assert_eq!(
        php_fpm_error_outcome(&io::Error::new(io::ErrorKind::InvalidInput, "missing fpm")),
        "configuration_error"
    );
    assert_eq!(
        php_fpm_error_outcome(&io::Error::new(io::ErrorKind::InvalidData, "bad response")),
        "invalid_response"
    );
    assert_eq!(
        php_fpm_error_outcome(&io::Error::other("backend failed")),
        "fpm_error"
    );
}

#[test]
fn managed_php_fpm_path_env_falls_back_for_control_bytes() {
    assert_eq!(
        managed_php_fpm_path_env_from(Some("/usr/bin\n/tmp".to_owned())),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    );
}

#[test]
fn managed_php_fpm_path_env_ignores_inherited_search_path() {
    let expected = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    assert_eq!(
        managed_php_fpm_path_env_from(Some(".:/tmp/bin:/usr/bin".to_owned())),
        expected
    );
    assert_eq!(
        managed_php_fpm_path_env_from(Some(":/relative/bin".to_owned())),
        expected
    );
    assert_eq!(managed_php_fpm_path_env_from(None), expected);
}

#[test]
fn managed_php_fpm_restart_backoff_is_bounded() {
    assert_eq!(managed_php_fpm_restart_backoff_secs(0), 1);
    assert_eq!(managed_php_fpm_restart_backoff_secs(1), 2);
    assert_eq!(managed_php_fpm_restart_backoff_secs(4), 16);
    assert_eq!(managed_php_fpm_restart_backoff_secs(64), 30);
}

#[test]
fn managed_php_fpm_instance_names_are_compact_and_bounded() {
    assert_eq!(
        managed_php_fpm_instance_name_from_parts("pool/main:php", 42, 7, 0xfeed).unwrap(),
        "fh-fpm-2a-7-000000000000feed"
    );
    assert_eq!(
        managed_php_fpm_instance_name_from_parts("", 42, 7, 0xfeed).unwrap(),
        "fh-fpm-2a-7-000000000000feed"
    );

    let long_name =
        managed_php_fpm_instance_name_from_parts(&"a".repeat(96), 42, 7, 0xfeed).unwrap();
    assert!(long_name.len() <= 48);
}

#[test]
fn php_fpm_endpoints_include_tcp_upstreams() {
    let fpm = PhpFpmConfig {
        tcp: Some("127.0.0.1:9000".to_owned()),
        tcp_upstreams: vec!["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()],
        ..PhpFpmConfig::default()
    };

    assert_eq!(
        php_fpm_endpoints_from_config(&fpm),
        vec![
            PhpFpmEndpoint::Tcp("127.0.0.1:9000".to_owned()),
            PhpFpmEndpoint::Tcp("127.0.0.1:9001".to_owned()),
        ]
    );
}

#[test]
fn php_fpm_retry_attempts_respect_method_allowlist_and_failover() {
    let mut fpm = PhpFpmConfig {
        max_retries: 2,
        retry_methods: vec!["GET".to_owned()],
        ..PhpFpmConfig::default()
    };

    assert_eq!(php_fpm_retry_attempts(&fpm, "GET"), 2);
    assert_eq!(php_fpm_retry_attempts(&fpm, "POST"), 0);
    assert_eq!(php_fpm_retry_attempts_for_endpoint_count(&fpm, "GET", 4), 3);

    fpm.retry_methods.clear();
    assert_eq!(php_fpm_retry_attempts_for_endpoint_count(&fpm, "GET", 4), 0);
}

#[test]
fn php_fpm_effective_timeouts_are_capped_by_request_timeout() {
    let request_timeout = std::time::Duration::from_secs(10);
    let mut fpm = PhpFpmConfig {
        connect_timeout_secs: Some(20),
        read_timeout_secs: Some(7),
        write_timeout_secs: Some(4),
        ..PhpFpmConfig::default()
    };

    assert_eq!(
        php_fpm_effective_connect_timeout(&fpm, request_timeout),
        request_timeout
    );
    assert_eq!(
        php_fpm_effective_request_timeout(&fpm, request_timeout),
        std::time::Duration::from_secs(4)
    );

    fpm.connect_timeout_secs = Some(3);
    assert_eq!(
        php_fpm_effective_connect_timeout(&fpm, request_timeout),
        std::time::Duration::from_secs(3)
    );
}

#[test]
fn php_fpm_retryable_statuses_and_errors_are_explicit() {
    let fpm = PhpFpmConfig {
        retry_statuses: vec![502, 503],
        ..PhpFpmConfig::default()
    };

    assert!(php_fpm_retryable_status(&fpm, 502));
    assert!(php_fpm_retryable_status(&fpm, 503));
    assert!(!php_fpm_retryable_status(&fpm, 404));
    assert!(php_fpm_retryable_error(&io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "refused"
    )));
    assert!(!php_fpm_retryable_error(&php_fpm_timeout_error(
        PhpFpmTimeoutKind::Request
    )));
}
