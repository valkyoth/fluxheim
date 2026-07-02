use std::error::Error;

#[cfg(feature = "acme-client")]
use crate::cli::validate_compiled_module_config;
#[cfg(feature = "acme-client")]
use crate::config::Config;

#[cfg(feature = "acme-client")]
pub(super) fn run_acme_renew_command(
    config_path: Option<&std::path::Path>,
    force_renew: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "tls-rustls-backend")]
    crate::tls::install_rustls_crypto_provider()?;

    let config = Config::load(config_path)?;
    config.validate()?;
    validate_compiled_module_config(&config)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let now = std::time::SystemTime::now();
    let queue = if force_renew {
        crate::acme::plan_renewal_queue(&config, &[], now)
    } else {
        let observations = crate::acme::observe_configured_certificates(&config);
        crate::acme::plan_renewal_queue(&config, &observations, now)
    };
    println!("acme targets: {}", queue.len());
    for item in &queue {
        let target = &item.target;
        let status = if force_renew {
            "forced"
        } else if item.due_now {
            "due"
        } else {
            "skipped"
        };
        println!(
            "target: {} status={} issuer={} domains={} cert={} key={}",
            target.vhost_name,
            status,
            target.issuer,
            target.domains.join(","),
            target.certificate.cert_path.display(),
            target.certificate.key_path.display()
        );
    }
    if queue.is_empty() {
        println!(
            "acme state: tls_enabled={} acme_enabled={} renewal_enabled={} storage={} vhosts={}",
            config.tls.enabled,
            config.tls.acme.enabled,
            config.tls.acme.renewal.enabled,
            config
                .tls
                .acme
                .storage
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_owned()),
            config.vhosts.len()
        );
        for vhost in &config.vhosts {
            println!(
                "vhost-acme-state: {} tls_enabled={} acme_enabled={} hosts={}",
                vhost.name,
                vhost.tls.enabled,
                vhost.tls.acme.enabled,
                vhost.hosts.join(",")
            );
        }
    }

    let run = if force_renew {
        runtime.block_on(crate::acme::renew_all_instant_acme_targets(&config, now))?
    } else {
        runtime.block_on(crate::acme::renew_due_instant_acme_targets(&config, now))?
    };

    println!("acme attempted: {}", run.attempted);
    if force_renew && !queue.is_empty() && run.attempted == 0 {
        return Err(
            "ACME renewal planner produced targets, but --force-renew attempted none".into(),
        );
    }
    if !force_renew && run.attempted == 0 {
        println!("acme status: no certificates are missing or due for renewal");
    }
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
    if !run.failed.is_empty() {
        return Err(format!("ACME renewal failed for {} target(s)", run.failed.len()).into());
    }
    Ok(())
}

#[cfg(not(feature = "acme-client"))]
pub(super) fn run_acme_renew_command(
    _config_path: Option<&std::path::Path>,
    _all: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("acme-renew requires the acme-client feature".into())
}
