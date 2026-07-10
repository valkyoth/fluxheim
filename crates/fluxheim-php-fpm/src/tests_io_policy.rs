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
    let (path, mut file) = runtime
        .block_on(create_php_request_body_spool_file(&spool_dir))
        .expect("create spool file");
    runtime.block_on(async {
        use tokio::io::AsyncWriteExt;

        file.write_all(b"spooled-body").await.expect("write spool");
        file.flush().await.expect("flush spool");
    });

    let body = PhpRequestBody::spooled(path.clone(), "spooled-body".len());
    let mut reader = runtime.block_on(body.reader()).expect("spool reader");
    let mut replayed = Vec::new();
    runtime
        .block_on(fastcgi_client::io::AsyncReadExt::read_to_end(
            &mut reader,
            &mut replayed,
        ))
        .expect("read spool body");

    assert_eq!(replayed, b"spooled-body");
    assert!(path.exists());
    drop(reader);
    drop(body);
    assert!(!path.exists());
    std::fs::remove_dir(&spool_dir).expect("remove spool dir");
}

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
fn managed_php_fpm_restart_backoff_is_bounded() {
    assert_eq!(managed_php_fpm_restart_backoff_secs(0), 1);
    assert_eq!(managed_php_fpm_restart_backoff_secs(1), 2);
    assert_eq!(managed_php_fpm_restart_backoff_secs(4), 16);
    assert_eq!(managed_php_fpm_restart_backoff_secs(64), 30);
}

#[test]
fn managed_php_fpm_instance_names_are_sanitized_and_bounded() {
    assert_eq!(
        managed_php_fpm_instance_name_from_parts("pool/main:php", 42, 7, 0xfeed).unwrap(),
        "fluxheim-php-fpm-pool-main-php-42-7-000000000000feed"
    );
    assert_eq!(
        managed_php_fpm_instance_name_from_parts("", 42, 7, 0xfeed).unwrap(),
        "fluxheim-php-fpm-php-42-7-000000000000feed"
    );

    let long_name =
        managed_php_fpm_instance_name_from_parts(&"a".repeat(96), 42, 7, 0xfeed).unwrap();
    assert!(long_name.contains(&"a".repeat(48)));
    assert!(!long_name.contains(&"a".repeat(49)));
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
