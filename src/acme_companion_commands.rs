use std::error::Error;

#[cfg(feature = "acme")]
use super::config_loader::load_validated_config;
#[cfg(feature = "acme-client")]
use super::reload::request_certificate_reload;
#[cfg(feature = "acme")]
use crate::config::Config;

#[cfg(feature = "acme-client")]
pub(super) fn run_renew(
    config_path: Option<&std::path::Path>,
    force_renew: bool,
    vhost: Option<&str>,
    reload_after_renewal: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "tls-rustls-backend")]
    crate::tls::install_rustls_crypto_provider()?;

    let config = load_validated_config(config_path)?;
    if let Some(vhost) = vhost {
        ensure_acme_target_exists(&config, vhost)?;
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let now = std::time::SystemTime::now();
    let run = if let Some(vhost) = vhost {
        runtime.block_on(fluxheim_acme::renew_selected_instant_acme_targets(
            &config,
            now,
            vhost,
            force_renew,
        ))?
    } else if force_renew {
        runtime.block_on(fluxheim_acme::renew_all_instant_acme_targets(&config, now))?
    } else {
        runtime.block_on(fluxheim_acme::renew_due_instant_acme_targets(&config, now))?
    };

    println!("acme attempted: {}", run.attempted);
    if !force_renew && run.attempted == 0 {
        println!("acme status: no certificates are missing or due for renewal");
    }

    let renewed_count = run.renewed.len();
    for outcome in &run.renewed {
        println!(
            "renewed: {} issuer={} cert={} key={} challenges={}",
            outcome.vhost_name,
            outcome.issuer,
            outcome.certificate.cert_path.display(),
            outcome.certificate.key_path.display(),
            outcome.published_challenges
        );
    }
    for failure in &run.failed {
        println!(
            "failed: {} issuer={} domains={} error={}",
            failure.vhost_name,
            failure.issuer,
            failure.domains.join(","),
            failure.error.replace('\n', " ")
        );
    }

    if renewed_count > 0 && reload_after_renewal && config.tls.acme.renewal.reload_after_renewal {
        request_certificate_reload(&config)?;
    }

    if !run.failed.is_empty() {
        return Err(format!("ACME renewal failed for {} target(s)", run.failed.len()).into());
    }
    Ok(())
}

#[cfg(not(feature = "acme-client"))]
pub(super) fn run_renew(
    _config_path: Option<&std::path::Path>,
    _force_renew: bool,
    _vhost: Option<&str>,
    _reload_after_renewal: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("fluxheim-acme renew requires the `acme-client` feature".into())
}

#[cfg(feature = "acme")]
pub(super) fn print_targets(
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = load_validated_config(config_path)?;
    let targets = fluxheim_acme::renewal_targets(&config);
    println!("acme targets: {}", targets.len());
    for target in targets {
        println!(
            "target: {} issuer={} challenge={:?} domains={} cert={} key={}",
            target.vhost_name,
            target.issuer,
            target.challenge,
            target.domains.join(","),
            target.certificate.cert_path.display(),
            target.certificate.key_path.display()
        );
    }
    Ok(())
}

#[cfg(feature = "acme")]
pub(super) fn print_status(
    config_path: Option<&std::path::Path>,
    vhost: Option<&str>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = load_validated_config(config_path)?;
    if let Some(vhost) = vhost {
        ensure_acme_target_exists(&config, vhost)?;
    }

    let now = std::time::SystemTime::now();
    let observations = fluxheim_acme::observe_configured_certificates(&config);
    let queue = fluxheim_acme::plan_renewal_queue(&config, &observations, now);
    let items: Vec<_> = queue
        .into_iter()
        .filter(|item| vhost.is_none_or(|name| item.target.vhost_name == name))
        .collect();
    println!("acme status targets: {}", items.len());
    for item in items {
        let status = if item.not_after.is_none() {
            "missing"
        } else if item.due_now {
            "due"
        } else {
            "valid"
        };
        let not_after = item
            .not_after
            .map(system_time_epoch_secs)
            .unwrap_or_else(|| "missing".to_owned());
        println!(
            "target: {} status={} due_now={} due_at={} not_after={} issuer={} domains={} cert={} key={}",
            item.target.vhost_name,
            status,
            item.due_now,
            system_time_epoch_secs(item.due_at),
            not_after,
            item.target.issuer,
            item.target.domains.join(","),
            item.target.certificate.cert_path.display(),
            item.target.certificate.key_path.display()
        );
    }
    Ok(())
}

#[cfg(feature = "acme")]
fn ensure_acme_target_exists(
    config: &Config,
    vhost: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if fluxheim_acme::renewal_targets(config)
        .into_iter()
        .any(|target| target.vhost_name == vhost)
    {
        return Ok(());
    }
    Err(format!("unknown ACME vhost target {vhost:?}").into())
}

#[cfg(feature = "acme")]
fn system_time_epoch_secs(time: std::time::SystemTime) -> String {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().to_string(),
        Err(_) => "before-unix-epoch".to_owned(),
    }
}

#[cfg(not(feature = "acme"))]
pub(super) fn print_targets(
    _config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("fluxheim-acme requires the `acme` or `acme-client` feature".into())
}

#[cfg(not(feature = "acme"))]
pub(super) fn print_status(
    _config_path: Option<&std::path::Path>,
    _vhost: Option<&str>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("fluxheim-acme requires the `acme` or `acme-client` feature".into())
}
