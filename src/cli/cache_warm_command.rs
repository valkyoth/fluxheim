use std::error::Error;

#[cfg(feature = "cache")]
use crate::config::Config;

use super::command_options::CacheWarmOptions;
#[cfg(feature = "cache")]
use super::{cache_common::parse_cache_cli_headers, cache_warm_support::*};

#[cfg(feature = "cache")]
pub(super) fn run_cache_warm_command(
    options: CacheWarmOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = Config::load(options.config_path)?;
    config.validate()?;

    if options.timeout_secs == 0 {
        return Err("cache-warm --timeout-secs must be greater than zero".into());
    }
    if options.max_targets == 0 || options.max_targets > 4096 {
        return Err("cache-warm --max-targets must be between 1 and 4096".into());
    }
    if options.repeat == 0 || options.repeat > 16 {
        return Err("cache-warm --repeat must be between 1 and 16".into());
    }
    validate_cache_warm_allow_statuses(&options.allow_statuses)?;
    validate_cache_warm_header_name(&options.cache_status_header)?;
    validate_cache_warm_expected_statuses(&options.expect_cache_statuses)?;
    validate_cache_warm_expected_sequence(
        &options.expect_cache_statuses,
        &options.expect_cache_status_sequence,
        options.repeat,
    )?;
    let request_headers = parse_cache_cli_headers("cache-warm", &options.headers)?;

    let listen = cache_warm_listen_addr(&config, options.listen.as_deref())?;
    let default_host = match options.host {
        Some(host) => {
            validate_cache_warm_host(&host)?;
            Some(host)
        }
        None => cache_warm_default_host(&config),
    };
    let targets = cache_warm_targets(
        default_host.as_deref(),
        &options.paths,
        options.input.as_deref(),
        options.max_targets,
    )?;
    let total_requests = targets
        .len()
        .checked_mul(options.repeat)
        .ok_or("cache-warm request count overflow")?;
    if total_requests > 4096 {
        return Err("cache-warm total request count must be at most 4096".into());
    }

    println!("cache warm targets: {}", targets.len());
    println!("cache warm requests: {total_requests}");
    println!("cache warm listener: {listen}");
    if !request_headers.is_empty() {
        println!("cache warm headers: {}", request_headers.len());
    }
    if options.dry_run {
        for target in targets {
            println!(
                "would warm: host={} path={} repeat={}",
                target.host, target.path, options.repeat
            );
        }
        println!("cache warm dry run completed");
        return Ok(());
    }

    let timeout = std::time::Duration::from_secs(options.timeout_secs);
    let mut warmed = 0_usize;
    let mut failed = 0_usize;
    let mut response_statuses = std::collections::BTreeMap::new();
    let mut cache_statuses = std::collections::BTreeMap::new();
    let mut failure_reasons = std::collections::BTreeMap::new();
    'targets: for target in targets {
        for attempt in 1..=options.repeat {
            match cache_warm_request(
                &listen,
                &target,
                timeout,
                &options.cache_status_header,
                &request_headers,
            ) {
                Ok(result) => {
                    fluxheim_cache::cache_warm_increment_count(
                        &mut response_statuses,
                        result.status,
                    );
                    let cache_status =
                        fluxheim_cache::cache_warm_safe_label(result.cache_status.as_deref());
                    fluxheim_cache::cache_warm_increment_count(
                        &mut cache_statuses,
                        cache_status.clone(),
                    );
                    if cache_warm_status_is_success(result.status, &options.allow_statuses) {
                        let expected = cache_warm_expected_statuses_for_attempt(
                            &options.expect_cache_statuses,
                            &options.expect_cache_status_sequence,
                            attempt,
                        );
                        match cache_warm_expected_status_matches(
                            result.cache_status.as_deref(),
                            expected,
                        ) {
                            Ok(()) => {
                                warmed = warmed.saturating_add(1);
                                println!(
                                    "warmed: host={} path={} attempt={}/{} status={} bytes={} cache_status={}",
                                    target.host,
                                    target.path,
                                    attempt,
                                    options.repeat,
                                    result.status,
                                    result.bytes_read,
                                    cache_status
                                );
                            }
                            Err(error) => {
                                failed = failed.saturating_add(1);
                                fluxheim_cache::cache_warm_increment_count(
                                    &mut failure_reasons,
                                    "unexpected_cache_status",
                                );
                                eprintln!(
                                    "failed: host={} path={} attempt={}/{} status={} bytes={} cache_status={} error={}",
                                    target.host,
                                    target.path,
                                    attempt,
                                    options.repeat,
                                    result.status,
                                    result.bytes_read,
                                    cache_status,
                                    error
                                );
                                if options.fail_fast {
                                    break 'targets;
                                }
                            }
                        }
                    } else {
                        failed = failed.saturating_add(1);
                        fluxheim_cache::cache_warm_increment_count(
                            &mut failure_reasons,
                            "unexpected_status",
                        );
                        eprintln!(
                            "failed: host={} path={} attempt={}/{} status={} bytes={} cache_status={} error=unexpected warm response status",
                            target.host,
                            target.path,
                            attempt,
                            options.repeat,
                            result.status,
                            result.bytes_read,
                            cache_status
                        );
                        if options.fail_fast {
                            break 'targets;
                        }
                    }
                }
                Err(error) => {
                    failed = failed.saturating_add(1);
                    fluxheim_cache::cache_warm_increment_count(
                        &mut failure_reasons,
                        "request_error",
                    );
                    eprintln!(
                        "failed: host={} path={} attempt={}/{} error={}",
                        target.host,
                        target.path,
                        attempt,
                        options.repeat,
                        error.to_string().replace('\n', " ")
                    );
                    if options.fail_fast {
                        break 'targets;
                    }
                }
            }
        }
    }

    print_cache_warm_counts("cache warm response statuses", &response_statuses);
    print_cache_warm_counts("cache warm cache statuses", &cache_statuses);
    print_cache_warm_counts("cache warm failure reasons", &failure_reasons);
    println!("cache warm completed: warmed={warmed} failed={failed}");
    if failed > 0 {
        return Err(format!("cache warm failed for {failed} target(s)").into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
pub(super) fn print_cache_warm_counts<K: std::fmt::Display>(
    label: &str,
    counts: &std::collections::BTreeMap<K, usize>,
) {
    if let Some(summary) = fluxheim_cache::cache_warm_counts_summary(counts) {
        println!("{label}: {summary}");
    }
}

#[cfg(not(feature = "cache"))]
pub(super) fn run_cache_warm_command(
    options: CacheWarmOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let CacheWarmOptions {
        config_path,
        listen,
        host,
        headers,
        paths,
        input,
        timeout_secs,
        max_targets,
        fail_fast,
        dry_run,
        repeat,
        allow_statuses,
        cache_status_header,
        expect_cache_statuses,
        expect_cache_status_sequence,
    } = options;
    let _ = (
        config_path,
        listen,
        host,
        headers,
        paths,
        input,
        timeout_secs,
        max_targets,
        fail_fast,
        dry_run,
        repeat,
        allow_statuses,
        cache_status_header,
        expect_cache_statuses,
        expect_cache_status_sequence,
    );
    Err("cache-warm requires the cache feature".into())
}
