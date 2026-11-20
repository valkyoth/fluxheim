use super::{Config, Error};
use std::io::{ErrorKind, Write};

pub(super) fn write_inventory(
    config: &Config,
    vhost: Option<&str>,
    now: i64,
    mut out: impl Write,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut targets = fluxheim_acme::managed_acme_targets(config);
    if let Some(name) = vhost {
        targets.retain(|target| target.vhost_name == name);
        if targets.is_empty() {
            return Err(format!("unknown ACME vhost target {name:?}").into());
        }
    }
    writeln!(out, "acme status targets: {}", targets.len())?;
    writeln!(out, "acme renewal: off (forced renewal is also disabled)")?;
    let mut problems = 0usize;
    for target in targets {
        let (status, expiry) = match fluxheim_acme::inspect_managed_leaf_validity(&target) {
            Ok(Some((start, end))) => {
                let status = if end <= now {
                    "expired"
                } else if start > now {
                    "not-yet-valid"
                } else if end <= now.saturating_add(7 * 86400) {
                    "expiring"
                } else {
                    "valid"
                };
                (status, end.to_string())
            }
            Ok(None) => ("missing", "missing".into()),
            Err(e) if e.kind() == ErrorKind::InvalidData => ("invalid", "unknown".into()),
            Err(_) => ("unreadable", "unknown".into()),
        };
        writeln!(
            out,
            "target: {} status={status} renewal=off not_after={expiry}",
            target.vhost_name
        )?;
        problems += usize::from(status != "valid");
    }
    if problems != 0 {
        return Err(
            format!("{problems} managed certificate(s) need attention; renewal is off").into(),
        );
    }
    Ok(())
}
