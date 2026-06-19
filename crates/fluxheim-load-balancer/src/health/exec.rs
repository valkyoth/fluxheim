use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::ProxyConfig;

use crate::backend::{FluxHealthCheck, RuntimeBackend as Backend};

pub(super) struct FluxExecHealthCheck {
    pub(super) consecutive_success: usize,
    pub(super) consecutive_failure: usize,
    pub(super) command: String,
    pub(super) args: Arc<[String]>,
    pub(super) timeout: Duration,
}

#[async_trait]
impl FluxHealthCheck for FluxExecHealthCheck {
    async fn check(&self, target: &Backend) -> FluxResult<()> {
        let mut command = tokio::process::Command::new(&self.command);
        let backend_addr = target.addr.to_string();
        let backend_inet = target.addr;
        command
            .args(self.args.iter().map(String::as_str))
            .env_clear()
            .env("FLUXHEIM_HEALTH_BACKEND_ADDR", backend_addr)
            .env(
                "FLUXHEIM_HEALTH_BACKEND_HOST",
                backend_inet.ip().to_string(),
            )
            .env(
                "FLUXHEIM_HEALTH_BACKEND_PORT",
                backend_inet.port().to_string(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|error| FluxError::io("spawn exec health check command", error))?;
        match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(status)) => Err(FluxError::io(
                "exec health check failed",
                io::Error::other(match status.code() {
                    Some(code) => format!("command exited with status {code}"),
                    None => "command terminated by signal".to_owned(),
                }),
            )),
            Ok(Err(error)) => Err(FluxError::io("wait for exec health check command", error)),
            Err(_) => {
                let _ = child.kill().await;
                Err(FluxError::timeout(
                    "exec health check timed out",
                    format!("timeout after {}s", self.timeout.as_secs()),
                ))
            }
        }
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        format!("{} via exec", target.addr)
    }
}

pub(super) fn configured_exec_health_check(
    config: &ProxyConfig,
) -> FluxResult<Box<FluxExecHealthCheck>> {
    let Some(command) = config.load_balance.health_check.exec_command.clone() else {
        return Err(FluxError::InvalidInput(
            "exec health check command is required",
        ));
    };
    if config
        .load_balance
        .health_check
        .exec_allowed_commands
        .is_empty()
        || !config
            .load_balance
            .health_check
            .exec_allowed_commands
            .contains(&command)
    {
        return Err(FluxError::InvalidInput(
            "exec health check command is not in exec_allowed_commands",
        ));
    }
    Ok(Box::new(FluxExecHealthCheck {
        consecutive_success: config.load_balance.health_check.consecutive_success,
        consecutive_failure: config.load_balance.health_check.consecutive_failure,
        command,
        args: config.load_balance.health_check.exec_args.clone().into(),
        timeout: Duration::from_secs(
            config
                .load_balance
                .health_check
                .exec_timeout_secs
                .unwrap_or(1),
        ),
    }))
}
