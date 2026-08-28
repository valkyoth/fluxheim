use std::error::Error;

#[cfg(feature = "acme")]
use super::config_loader::load_validated_config;
#[cfg(feature = "acme-client")]
use super::reload::request_certificate_reload;
#[cfg(feature = "acme")]
use crate::config::Config;

#[cfg(feature = "acme-client")]
pub(super) fn run_account_operation(
    config_path: Option<&std::path::Path>,
    issuer: &str,
    operation: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "tls-rustls-backend")]
    crate::tls::install_rustls_crypto_provider()?;
    let config = load_validated_config(config_path)?;
    if !config
        .tls
        .acme
        .issuers
        .iter()
        .any(|item| item.name == issuer)
    {
        return Err(format!("unknown ACME issuer {issuer:?}").into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match operation {
        "rollover" => runtime.block_on(fluxheim_acme::rollover_instant_acme_account_key(
            &config, issuer,
        ))?,
        "deactivate" => runtime.block_on(fluxheim_acme::deactivate_instant_acme_account(
            &config, issuer,
        ))?,
        _ => return Err("unknown ACME account operation".into()),
    }
    println!("acme account {operation}: issuer={issuer} status=ok");
    Ok(())
}

#[cfg(feature = "acme-client")]
pub(super) fn run_revoke(
    config_path: Option<&std::path::Path>,
    vhost: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "tls-rustls-backend")]
    crate::tls::install_rustls_crypto_provider()?;
    let config = load_validated_config(config_path)?;
    ensure_acme_target_exists(&config, vhost)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let outcome = runtime.block_on(fluxheim_acme::revoke_instant_acme_certificate(
        &config, vhost,
    ))?;
    request_certificate_reload(&config)?;
    println!(
        "acme certificate revoke: vhost={vhost} status=quarantined replacement_required={}",
        outcome.replacement_required
    );
    Ok(())
}

#[cfg(feature = "acme-client")]
pub(super) fn run_doctor(
    config_path: Option<&std::path::Path>,
    online: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "tls-rustls-backend")]
    crate::tls::install_rustls_crypto_provider()?;
    let config = load_validated_config(config_path)?;
    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or("ACME doctor: tls.acme.storage is not configured")?;
    let targets = fluxheim_acme::renewal_targets(&config);
    if targets.is_empty() {
        return Err("ACME doctor: no enabled ACME vhost targets are configured".into());
    }
    std::fs::create_dir_all(storage)?;
    let metadata = std::fs::symlink_metadata(storage)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("ACME doctor: storage is not a real directory".into());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "ACME doctor: system clock is before the Unix epoch")?;
    if !(1_577_836_800..=7_258_118_400).contains(&now.as_secs()) {
        return Err("ACME doctor: system clock is outside the accepted 2020-2200 range".into());
    }

    for target in &targets {
        fluxheim_acme::recover_managed_certificate_transaction(storage, &target.vhost_name)?;
        let cert_exists = target.certificate.cert_path.is_file();
        let key_exists = target.certificate.key_path.is_file();
        if cert_exists != key_exists {
            return Err(format!(
                "ACME doctor: vhost {:?} has an incomplete certificate/key pair",
                target.vhost_name
            )
            .into());
        }
        if online {
            for domain in &target.domains {
                match target.challenge {
                    fluxheim_config::AcmeChallenge::Http01 => {
                        doctor_http_01_reachability(storage, &target.vhost_name, domain)?;
                    }
                    fluxheim_config::AcmeChallenge::TlsAlpn01 => {
                        doctor_tcp_reachability(domain, 443, "TLS-ALPN-01")?;
                    }
                }
            }
        }
    }

    let runtime = online
        .then(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        })
        .transpose()?;
    let used_issuers = targets
        .iter()
        .map(|target| target.issuer.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for issuer in config
        .tls
        .acme
        .issuers
        .iter()
        .filter(|issuer| used_issuers.contains(issuer.name.as_str()))
    {
        let credentials = fluxheim_acme::load_account_credentials(storage, &issuer.name)?;
        if credentials.is_none()
            && (!issuer.terms_of_service_agreed || issuer.terms_of_service_url.is_none())
        {
            return Err(format!(
                "ACME doctor: issuer {:?} requires explicit terms_of_service_agreed and terms_of_service_url before account creation",
                issuer.name
            )
            .into());
        }
        if let Some(runtime) = runtime.as_ref() {
            runtime.block_on(fluxheim_acme::probe_instant_acme_issuer(
                &config,
                &issuer.name,
            ))?;
        }
        println!(
            "acme issuer: {} account={} connectivity={}",
            issuer.name,
            if credentials.is_some() {
                "stored"
            } else {
                "new"
            },
            if online { "ok" } else { "not-checked" }
        );
    }
    println!("{}", account_rollover_capability_status());
    println!("acme doctor: ok targets={} online={online}", targets.len());
    Ok(())
}

#[cfg(feature = "acme-client")]
pub(super) fn account_rollover_capability_status() -> &'static str {
    "acme capability: account-rollover=unavailable reason=client-cannot-prejournal-replacement-key"
}

#[cfg(feature = "acme-client")]
fn doctor_http_01_reachability(
    storage: &std::path::Path,
    vhost: &str,
    domain: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    use std::io::{Read as _, Write as _};
    use std::net::ToSocketAddrs as _;

    static PROBE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = PROBE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let token = format!("fluxheim-doctor-{}-{sequence}", std::process::id());
    let key_authorization = format!("{token}.local-preflight");
    let store = fluxheim_acme::AcmeHttp01ChallengeStore::new(storage, vhost);
    store.install_key_authorization(&token, &key_authorization)?;
    let result = (|| {
        let addresses = (domain, 80).to_socket_addrs()?.collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(format!("ACME doctor: DNS returned no addresses for {domain}").into());
        }
        let mut last_error = None;
        for address in addresses {
            let mut stream = match std::net::TcpStream::connect_timeout(
                &address,
                std::time::Duration::from_secs(5),
            ) {
                Ok(stream) => stream,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            write!(
                stream,
                "GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
            )?;
            let mut response = Vec::new();
            stream.take(65_537).read_to_end(&mut response)?;
            if response.len() > 65_536 {
                return Err("ACME doctor: HTTP-01 probe response exceeded 64 KiB".into());
            }
            if response
                .windows(key_authorization.len())
                .any(|window| window == key_authorization.as_bytes())
            {
                return Ok(());
            }
            last_error = Some(std::io::Error::other(
                "HTTP-01 response did not contain the probe authorization",
            ));
        }
        Err(format!(
            "ACME doctor: HTTP-01 local-vantage probe failed for {domain}: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "no reachable address".to_owned())
        )
        .into())
    })();
    let cleanup = store.remove_key_authorization(&token);
    match (result, cleanup) {
        (result, Ok(_)) => result,
        (Ok(()), Err(error)) => Err(error.into()),
        (Err(primary), Err(cleanup_error)) => {
            log::error!(
                target: "fluxheim::security",
                "ACME doctor HTTP-01 cleanup failed after probe failure: {cleanup_error}"
            );
            Err(primary)
        }
    }
}

#[cfg(feature = "acme-client")]
pub(super) fn doctor_tcp_reachability(
    domain: &str,
    port: u16,
    challenge: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    use std::net::ToSocketAddrs as _;

    let addresses = (domain, port).to_socket_addrs()?.collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(format!("ACME doctor: DNS returned no addresses for {domain}").into());
    }
    if addresses.iter().any(|address| {
        std::net::TcpStream::connect_timeout(address, std::time::Duration::from_secs(5)).is_ok()
    }) {
        return Ok(());
    }
    Err(format!(
        "ACME doctor: {challenge} local-vantage TCP reachability failed for {domain}:{port}"
    )
    .into())
}

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
            "renewed: {} issuer={} certificate=installed challenges={}",
            outcome.vhost_name, outcome.issuer, outcome.published_challenges
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
            "target: {} issuer={} challenge={:?} domains={} certificate=managed",
            target.vhost_name,
            target.issuer,
            target.challenge,
            target.domains.join(",")
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
            "target: {} status={} due_now={} due_at={} not_after={} issuer={} domains={} certificate=managed",
            item.target.vhost_name,
            status,
            item.due_now,
            system_time_epoch_secs(item.due_at),
            not_after,
            item.target.issuer,
            item.target.domains.join(",")
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
