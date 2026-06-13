#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fluxheim_config::{PhpFpmConfig, PhpFpmProcessManager};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PhpFpmEndpoint {
    Tcp(String),
    #[cfg(unix)]
    Unix(PathBuf),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PhpFpmTimeoutKind {
    Connect,
    Request,
}

impl std::fmt::Display for PhpFpmTimeoutKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => write!(formatter, "php-fpm connect timed out"),
            Self::Request => write!(formatter, "php-fpm request timed out"),
        }
    }
}

impl std::error::Error for PhpFpmTimeoutKind {}

pub fn php_fpm_timeout_error(kind: PhpFpmTimeoutKind) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, kind)
}

pub fn php_fpm_timeout_kind(error: &io::Error) -> Option<PhpFpmTimeoutKind> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<PhpFpmTimeoutKind>())
        .copied()
}

pub fn php_fpm_error_outcome(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::TimedOut => match php_fpm_timeout_kind(error) {
            Some(PhpFpmTimeoutKind::Connect) => "connect_timeout",
            Some(PhpFpmTimeoutKind::Request) | None => "request_timeout",
        },
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotFound
        | io::ErrorKind::UnexpectedEof => "connection_error",
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported => "configuration_error",
        io::ErrorKind::InvalidData => "invalid_response",
        _ => "fpm_error",
    }
}

pub fn php_fpm_endpoints_from_config(config: &PhpFpmConfig) -> Vec<PhpFpmEndpoint> {
    if !config.tcp_upstreams.is_empty() {
        return config
            .tcp_upstreams
            .iter()
            .cloned()
            .map(PhpFpmEndpoint::Tcp)
            .collect();
    }
    if let Some(address) = config.tcp.as_deref() {
        return vec![PhpFpmEndpoint::Tcp(address.to_owned())];
    }
    if let Some(socket) = config.socket.as_deref() {
        #[cfg(unix)]
        {
            return vec![PhpFpmEndpoint::Unix(socket.to_path_buf())];
        }
        #[cfg(not(unix))]
        {
            let _ = socket;
            return Vec::new();
        }
    }
    Vec::new()
}

pub fn php_fpm_effective_connect_timeout(
    fpm: &PhpFpmConfig,
    request_timeout: Duration,
) -> Duration {
    fpm.connect_timeout_secs
        .map(Duration::from_secs)
        .map(|connect_timeout| connect_timeout.min(request_timeout))
        .unwrap_or(request_timeout)
}

pub fn php_fpm_effective_request_timeout(
    fpm: &PhpFpmConfig,
    request_timeout: Duration,
) -> Duration {
    [fpm.read_timeout_secs, fpm.write_timeout_secs]
        .into_iter()
        .flatten()
        .map(Duration::from_secs)
        .fold(request_timeout, Duration::min)
}

fn php_fpm_retry_method_allowed(fpm: &PhpFpmConfig, method: &str) -> bool {
    fpm.retry_methods
        .iter()
        .any(|retry_method| retry_method.eq_ignore_ascii_case(method))
}

pub fn php_fpm_retry_attempts(fpm: &PhpFpmConfig, method: &str) -> u8 {
    php_fpm_retry_attempts_for_endpoint_count(fpm, method, 1)
}

pub fn php_fpm_retry_attempts_for_endpoint_count(
    fpm: &PhpFpmConfig,
    method: &str,
    endpoint_count: usize,
) -> u8 {
    if !php_fpm_retry_method_allowed(fpm, method) {
        return 0;
    }
    let failover_retries = endpoint_count.saturating_sub(1).min(usize::from(u8::MAX)) as u8;
    fpm.max_retries.max(failover_retries)
}

pub fn php_fpm_retry_deadline(retry_timeout_secs: Option<u64>) -> Option<Instant> {
    retry_timeout_secs.and_then(|secs| Instant::now().checked_add(Duration::from_secs(secs)))
}

pub fn php_fpm_retry_deadline_allows(deadline: Option<Instant>) -> bool {
    match deadline {
        Some(deadline) => Instant::now() < deadline,
        None => true,
    }
}

pub fn php_fpm_retryable_status(fpm: &PhpFpmConfig, status: u16) -> bool {
    fpm.retry_statuses.contains(&status)
}

pub fn php_fpm_retryable_error(error: &io::Error) -> bool {
    match error.kind() {
        io::ErrorKind::TimedOut => php_fpm_timeout_kind(error) == Some(PhpFpmTimeoutKind::Connect),
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotFound
        | io::ErrorKind::UnexpectedEof => true,
        _ => false,
    }
}

pub fn managed_php_fpm_restart_backoff_secs(restart_failures: usize) -> u64 {
    2_u64.saturating_pow(restart_failures.min(5) as u32).min(30)
}

pub fn managed_php_fpm_path_env_from(value: Option<String>) -> String {
    const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    value
        .filter(|value| {
            !value.is_empty() && value.bytes().all(|byte| !matches!(byte, 0..=31 | 127))
        })
        .unwrap_or_else(|| DEFAULT_PATH.to_owned())
}

pub fn managed_php_fpm_config(
    socket: &Path,
    pid_path: &Path,
    error_log: &Path,
    slow_log: Option<&Path>,
    fpm: &PhpFpmConfig,
) -> io::Result<String> {
    let socket = php_fpm_config_path_value(socket)?;
    let pid_path = php_fpm_config_path_value(pid_path)?;
    let error_log = php_fpm_config_path_value(error_log)?;
    let slow_log = slow_log.map(php_fpm_config_path_value).transpose()?;
    let session_save_path = fpm
        .session_save_path
        .as_deref()
        .map(php_fpm_config_path_value)
        .transpose()?;
    let upload_tmp_dir = fpm
        .upload_tmp_dir
        .as_deref()
        .map(php_fpm_config_path_value)
        .transpose()?;

    let mut config = String::new();
    config.push_str("[global]\n");
    config.push_str("daemonize = no\n");
    config.push_str(&format!("pid = {pid_path}\n"));
    config.push_str(&format!("error_log = {error_log}\n"));
    config.push('\n');
    config.push_str("[fluxheim]\n");
    config.push_str(&format!("listen = {socket}\n"));
    let listen_mode = match fpm.listen_mode.as_deref() {
        Some(value) => php_fpm_config_listen_mode_value(value)?,
        None => "0600",
    };
    config.push_str(&format!("listen.mode = {listen_mode}\n"));
    if let (Some(listen_owner), Some(listen_group)) = (&fpm.listen_owner, &fpm.listen_group) {
        let listen_owner = php_fpm_config_identity_value(listen_owner)?;
        let listen_group = php_fpm_config_identity_value(listen_group)?;
        config.push_str(&format!("listen.owner = {listen_owner}\n"));
        config.push_str(&format!("listen.group = {listen_group}\n"));
    }
    if let Some(listen_backlog) = fpm.listen_backlog {
        config.push_str(&format!("listen.backlog = {listen_backlog}\n"));
    }
    config.push_str(&managed_php_fpm_identity_config(
        fpm.user.as_deref(),
        fpm.group.as_deref(),
    )?);
    config.push_str(&managed_php_fpm_pool_config(fpm));
    if let Some(request_terminate_timeout_secs) = fpm.request_terminate_timeout_secs {
        config.push_str(&format!(
            "request_terminate_timeout = {request_terminate_timeout_secs}s\n"
        ));
    }
    if fpm.request_terminate_timeout_track_finished {
        config.push_str("request_terminate_timeout_track_finished = yes\n");
    }
    if let Some(request_slowlog_timeout_secs) = fpm.request_slowlog_timeout_secs {
        if let Some(slow_log) = slow_log {
            config.push_str(&format!("slowlog = {slow_log}\n"));
        }
        config.push_str(&format!(
            "request_slowlog_timeout = {request_slowlog_timeout_secs}s\n"
        ));
        config.push_str(&format!(
            "request_slowlog_trace_depth = {}\n",
            fpm.request_slowlog_trace_depth
        ));
    }
    config.push_str(&format!(
        "clear_env = {}\n",
        managed_php_fpm_bool(fpm.clear_env)
    ));
    config.push_str(&format!(
        "catch_workers_output = {}\n",
        managed_php_fpm_bool(fpm.catch_workers_output)
    ));
    config.push_str(&format!(
        "decorate_workers_output = {}\n",
        managed_php_fpm_bool(fpm.decorate_workers_output)
    ));
    config.push_str("chdir = /\n");
    config.push_str("security.limit_extensions = .php\n");
    if let Some(session_save_path) = session_save_path {
        config.push_str(&format!(
            "php_value[session.save_path] = {session_save_path}\n"
        ));
    }
    if let Some(upload_tmp_dir) = upload_tmp_dir {
        config.push_str(&format!(
            "php_admin_value[upload_tmp_dir] = {upload_tmp_dir}\n"
        ));
    }
    Ok(config)
}

fn managed_php_fpm_pool_config(fpm: &PhpFpmConfig) -> String {
    let mut config = String::new();
    match fpm.process_manager {
        PhpFpmProcessManager::Static => {
            config.push_str("pm = static\n");
            config.push_str(&format!("pm.max_children = {}\n", fpm.workers));
        }
        PhpFpmProcessManager::Dynamic => {
            let min_spare = fpm.min_spare_servers.unwrap_or(1);
            let max_spare = fpm.max_spare_servers.unwrap_or(fpm.workers.max(min_spare));
            let start_servers = fpm
                .start_servers
                .unwrap_or_else(|| (min_spare.saturating_add(max_spare) / 2).max(1));
            config.push_str("pm = dynamic\n");
            config.push_str(&format!("pm.max_children = {}\n", fpm.workers));
            config.push_str(&format!("pm.start_servers = {start_servers}\n"));
            config.push_str(&format!("pm.min_spare_servers = {min_spare}\n"));
            config.push_str(&format!("pm.max_spare_servers = {max_spare}\n"));
            if let Some(max_spawn_rate) = fpm.max_spawn_rate {
                config.push_str(&format!("pm.max_spawn_rate = {max_spawn_rate}\n"));
            }
        }
        PhpFpmProcessManager::Ondemand => {
            config.push_str("pm = ondemand\n");
            config.push_str(&format!("pm.max_children = {}\n", fpm.workers));
            if let Some(process_idle_timeout_secs) = fpm.process_idle_timeout_secs {
                config.push_str(&format!(
                    "pm.process_idle_timeout = {process_idle_timeout_secs}s\n"
                ));
            }
        }
    }
    config.push_str(&format!(
        "pm.max_requests = {}\n",
        fpm.max_requests_per_worker
    ));
    config
}

fn managed_php_fpm_bool(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn managed_php_fpm_identity_config(user: Option<&str>, group: Option<&str>) -> io::Result<String> {
    match (user, group) {
        (Some(user), Some(group)) => {
            let user = php_fpm_config_identity_value(user)?;
            let group = php_fpm_config_identity_value(group)?;
            Ok(format!("user = {user}\ngroup = {group}\n"))
        }
        _ => Ok(String::new()),
    }
}

fn php_fpm_config_identity_value(value: &str) -> io::Result<&str> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || !value.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' | b'-'),
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm identity contains bytes unsafe for php-fpm config",
        ));
    }
    Ok(value)
}

fn php_fpm_config_listen_mode_value(value: &str) -> io::Result<&str> {
    match value {
        "0600" | "0660" => Ok(value),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm listen mode must be 0600 or 0660",
        )),
    }
}

fn php_fpm_config_path_value(path: &Path) -> io::Result<&str> {
    let value = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm path is not valid UTF-8",
        )
    })?;
    if value
        .bytes()
        .any(|byte| matches!(byte, 0..=31 | 127 | b'\'' | b'"'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm path contains bytes unsafe for php-fpm config",
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;

    use super::{
        PhpFpmEndpoint, PhpFpmTimeoutKind, managed_php_fpm_config, managed_php_fpm_path_env_from,
        managed_php_fpm_restart_backoff_secs, php_fpm_effective_connect_timeout,
        php_fpm_effective_request_timeout, php_fpm_endpoints_from_config, php_fpm_error_outcome,
        php_fpm_retry_attempts, php_fpm_retry_attempts_for_endpoint_count, php_fpm_retryable_error,
        php_fpm_retryable_status, php_fpm_timeout_error,
    };
    use fluxheim_config::{PhpFpmConfig, PhpFpmProcessManager};

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

    #[test]
    fn managed_php_fpm_config_contains_private_pool_settings() {
        let fpm = PhpFpmConfig {
            process_manager: PhpFpmProcessManager::Dynamic,
            workers: 8,
            min_spare_servers: Some(2),
            max_spare_servers: Some(6),
            start_servers: Some(4),
            max_spawn_rate: Some(16),
            listen_backlog: Some(128),
            listen_owner: Some("fluxheim".to_owned()),
            listen_group: Some("www-data".to_owned()),
            listen_mode: Some("0660".to_owned()),
            user: Some("fluxheim".to_owned()),
            group: Some("www-data".to_owned()),
            request_terminate_timeout_secs: Some(30),
            request_terminate_timeout_track_finished: true,
            request_slowlog_timeout_secs: Some(5),
            session_save_path: Some(Path::new("/run/fluxheim/php/session").to_path_buf()),
            upload_tmp_dir: Some(Path::new("/run/fluxheim/php/upload").to_path_buf()),
            clear_env: false,
            ..PhpFpmConfig::default()
        };

        let config = managed_php_fpm_config(
            Path::new("/run/fluxheim/php/php-fpm.sock"),
            Path::new("/run/fluxheim/php/php-fpm.pid"),
            Path::new("/run/fluxheim/php/php-fpm.log"),
            Some(Path::new("/run/fluxheim/php/php-fpm.slow.log")),
            &fpm,
        )
        .expect("managed php-fpm config should render");

        assert!(config.contains("listen.mode = 0660\n"));
        assert!(config.contains("listen.owner = fluxheim\n"));
        assert!(config.contains("listen.group = www-data\n"));
        assert!(config.contains("listen.backlog = 128\n"));
        assert!(config.contains("user = fluxheim\n"));
        assert!(config.contains("group = www-data\n"));
        assert!(config.contains("pm = dynamic\n"));
        assert!(config.contains("pm.max_children = 8\n"));
        assert!(config.contains("pm.start_servers = 4\n"));
        assert!(config.contains("pm.min_spare_servers = 2\n"));
        assert!(config.contains("pm.max_spare_servers = 6\n"));
        assert!(config.contains("pm.max_spawn_rate = 16\n"));
        assert!(config.contains("request_terminate_timeout = 30s\n"));
        assert!(config.contains("request_terminate_timeout_track_finished = yes\n"));
        assert!(config.contains("request_slowlog_timeout = 5s\n"));
        assert!(config.contains("slowlog = /run/fluxheim/php/php-fpm.slow.log\n"));
        assert!(config.contains("clear_env = no\n"));
        assert!(config.contains("catch_workers_output = yes\n"));
        assert!(config.contains("decorate_workers_output = yes\n"));
        assert!(config.contains("security.limit_extensions = .php\n"));
        assert!(config.contains("php_value[session.save_path] = /run/fluxheim/php/session\n"));
        assert!(config.contains("php_admin_value[upload_tmp_dir] = /run/fluxheim/php/upload\n"));
    }

    #[test]
    fn managed_php_fpm_config_rejects_unsafe_path_bytes() {
        let error = managed_php_fpm_config(
            Path::new("/run/fluxheim/php/php-fpm.sock"),
            Path::new("/run/fluxheim/php/php-fpm.pid"),
            Path::new("/run/fluxheim/php/php-fpm\".log"),
            None,
            &PhpFpmConfig::default(),
        )
        .expect_err("unsafe config paths should be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
