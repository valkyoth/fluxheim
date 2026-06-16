use std::path::{Path, PathBuf};
use std::time::Duration;

use fluxheim_config::Config;

use crate::ProcessSpec;

const CERTIFICATE_RELOAD_CONTROL_MAX_CONCURRENT_REQUESTS: usize = 4;
const CERTIFICATE_RELOAD_CONTROL_READ_TIMEOUT_SECS: u64 = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateReloadControlPlan {
    socket_path: PathBuf,
    max_concurrent_requests: usize,
    read_timeout: Duration,
}

impl CertificateReloadControlPlan {
    pub(crate) fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            max_concurrent_requests: CERTIFICATE_RELOAD_CONTROL_MAX_CONCURRENT_REQUESTS,
            read_timeout: Duration::from_secs(CERTIFICATE_RELOAD_CONTROL_READ_TIMEOUT_SECS),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub const fn max_concurrent_requests(&self) -> usize {
        self.max_concurrent_requests
    }

    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }
}

pub(crate) fn certificate_reload_control_plan_from_config(
    config: &Config,
    process: &ProcessSpec,
) -> Option<CertificateReloadControlPlan> {
    if config.tls.acme.enabled && config.tls.acme.renewal.reload_after_renewal {
        return Some(CertificateReloadControlPlan::new(
            process.certificate_reload_sock().to_path_buf(),
        ));
    }
    None
}
