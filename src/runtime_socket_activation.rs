use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::net::TcpListener;

const MAX_SYSTEMD_LISTENERS: usize = 128;

#[derive(Debug)]
pub(super) enum SocketActivationError {
    InvalidValue {
        variable: &'static str,
        value: String,
    },
    ListenerCount {
        expected: usize,
        actual: usize,
    },
    MissingVariable {
        variable: &'static str,
    },
    NonUnicodeValue {
        variable: &'static str,
    },
    ProcessMismatch {
        expected: u32,
        actual: u32,
    },
    TakeListener {
        index: usize,
        source: std::io::Error,
    },
}

impl fmt::Display for SocketActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue { variable, value } => {
                write!(formatter, "invalid systemd socket activation {variable}={value:?}")
            }
            Self::ListenerCount { expected, actual } => write!(
                formatter,
                "systemd socket activation declared {expected} listener(s), but {actual} valid TCP listener(s) were available"
            ),
            Self::MissingVariable { variable } => write!(
                formatter,
                "systemd socket activation requires {variable} when any LISTEN_* variable is present"
            ),
            Self::NonUnicodeValue { variable } => write!(
                formatter,
                "systemd socket activation {variable} is not valid Unicode"
            ),
            Self::ProcessMismatch { expected, actual } => write!(
                formatter,
                "systemd socket activation LISTEN_PID targets process {actual}, not current process {expected}"
            ),
            Self::TakeListener { index, source } => write!(
                formatter,
                "failed to adopt systemd TCP listener at descriptor index {index}: {source}"
            ),
        }
    }
}

impl Error for SocketActivationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TakeListener { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(super) fn take_systemd_tcp_listeners(
) -> Result<Option<Vec<TcpListener>>, SocketActivationError> {
    let listen_fds = environment_value("LISTEN_FDS")?;
    let listen_pid = environment_value("LISTEN_PID")?;
    let listen_fdnames = environment_value("LISTEN_FDNAMES")?;
    let first_fd = environment_value("LISTEN_FDS_FIRST_FD")?;
    let Some(count) = validate_activation_metadata(
        listen_fds.as_deref(),
        listen_pid.as_deref(),
        listen_fdnames.as_deref(),
        first_fd.as_deref(),
        std::process::id(),
    )? else {
        return Ok(None);
    };

    take_validated_listeners(count).map(Some)
}

fn environment_value(variable: &'static str) -> Result<Option<String>, SocketActivationError> {
    std::env::var_os(variable)
        .map(|value| os_string_to_string(variable, value))
        .transpose()
}

fn os_string_to_string(
    variable: &'static str,
    value: OsString,
) -> Result<String, SocketActivationError> {
    value
        .into_string()
        .map_err(|_| SocketActivationError::NonUnicodeValue { variable })
}

fn validate_activation_metadata(
    listen_fds: Option<&str>,
    listen_pid: Option<&str>,
    listen_fdnames: Option<&str>,
    first_fd: Option<&str>,
    current_pid: u32,
) -> Result<Option<usize>, SocketActivationError> {
    let Some(listen_fds) = listen_fds else {
        if listen_pid.is_some() || listen_fdnames.is_some() || first_fd.is_some() {
            return Err(SocketActivationError::MissingVariable {
                variable: "LISTEN_FDS",
            });
        }
        return Ok(None);
    };
    let count = parse_bounded_usize("LISTEN_FDS", listen_fds)?;
    if count == 0 || count > MAX_SYSTEMD_LISTENERS {
        return Err(SocketActivationError::InvalidValue {
            variable: "LISTEN_FDS",
            value: listen_fds.to_owned(),
        });
    }
    let listen_pid = listen_pid.ok_or(SocketActivationError::MissingVariable {
        variable: "LISTEN_PID",
    })?;
    let actual_pid = listen_pid.parse::<u32>().map_err(|_| {
        SocketActivationError::InvalidValue {
            variable: "LISTEN_PID",
            value: listen_pid.to_owned(),
        }
    })?;
    if actual_pid != current_pid {
        return Err(SocketActivationError::ProcessMismatch {
            expected: current_pid,
            actual: actual_pid,
        });
    }
    if let Some(names) = listen_fdnames {
        let actual = names.split(':').count();
        if actual != count {
            return Err(SocketActivationError::ListenerCount {
                expected: count,
                actual,
            });
        }
    }
    if let Some(value) = first_fd {
        return Err(SocketActivationError::InvalidValue {
            variable: "LISTEN_FDS_FIRST_FD",
            value: value.to_owned(),
        });
    }
    Ok(Some(count))
}

fn parse_bounded_usize(
    variable: &'static str,
    value: &str,
) -> Result<usize, SocketActivationError> {
    value
        .parse::<usize>()
        .map_err(|_| SocketActivationError::InvalidValue {
            variable,
            value: value.to_owned(),
        })
}

#[cfg(unix)]
fn take_validated_listeners(count: usize) -> Result<Vec<TcpListener>, SocketActivationError> {
    let mut listen_fd = listenfd::ListenFd::from_env();
    if listen_fd.len() != count {
        return Err(SocketActivationError::ListenerCount {
            expected: count,
            actual: listen_fd.len(),
        });
    }
    let mut listeners = Vec::with_capacity(count);
    for index in 0..count {
        let listener = listen_fd
            .take_tcp_listener(index)
            .map_err(|source| SocketActivationError::TakeListener { index, source })?
            .ok_or(SocketActivationError::ListenerCount {
                expected: count,
                actual: listeners.len(),
            })?;
        listeners.push(listener);
    }
    Ok(listeners)
}

#[cfg(not(unix))]
fn take_validated_listeners(_count: usize) -> Result<Vec<TcpListener>, SocketActivationError> {
    Err(SocketActivationError::InvalidValue {
        variable: "LISTEN_FDS",
        value: "socket activation is only supported on Unix".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{SocketActivationError, validate_activation_metadata};

    #[test]
    fn absent_activation_environment_selects_normal_binding() {
        assert_eq!(
            validate_activation_metadata(None, None, None, None, 42).unwrap(),
            None
        );
    }

    #[test]
    fn activation_requires_matching_process_and_names_count() {
        assert_eq!(
            validate_activation_metadata(Some("2"), Some("42"), Some("http:https"), None, 42)
                .unwrap(),
            Some(2)
        );
        assert!(matches!(
            validate_activation_metadata(Some("2"), Some("41"), None, None, 42),
            Err(SocketActivationError::ProcessMismatch { .. })
        ));
        assert!(matches!(
            validate_activation_metadata(Some("2"), Some("42"), Some("http"), None, 42),
            Err(SocketActivationError::ListenerCount { .. })
        ));
    }

    #[test]
    fn partial_or_unbounded_activation_metadata_is_rejected() {
        assert!(matches!(
            validate_activation_metadata(None, Some("42"), None, None, 42),
            Err(SocketActivationError::MissingVariable { .. })
        ));
        assert!(matches!(
            validate_activation_metadata(Some("0"), Some("42"), None, None, 42),
            Err(SocketActivationError::InvalidValue { .. })
        ));
        assert!(matches!(
            validate_activation_metadata(Some("129"), Some("42"), None, None, 42),
            Err(SocketActivationError::InvalidValue { .. })
        ));
        assert!(matches!(
            validate_activation_metadata(Some("1"), Some("42"), None, Some("4"), 42),
            Err(SocketActivationError::InvalidValue { .. })
        ));
    }
}
