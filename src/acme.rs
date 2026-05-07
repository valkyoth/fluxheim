use std::cmp::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use toml::value::{Datetime, Offset};

use crate::config::{AcmeChallenge, Config};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeRenewalTarget {
    pub vhost_name: String,
    pub issuer: String,
    pub domains: Vec<String>,
    pub challenge: AcmeChallenge,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CertificateObservation {
    pub vhost_name: String,
    pub not_after: SystemTime,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeRenewalItem {
    pub target: AcmeRenewalTarget,
    pub not_after: Option<SystemTime>,
    pub due_at: SystemTime,
    pub due_now: bool,
}

pub fn renewal_targets(config: &Config) -> Vec<AcmeRenewalTarget> {
    if !config.tls.enabled || !config.tls.acme.enabled || !config.tls.acme.renewal.enabled {
        return Vec::new();
    }

    config
        .vhosts
        .iter()
        .filter(|vhost| vhost.tls.enabled && vhost.tls.acme.enabled)
        .map(|vhost| {
            let issuer = vhost
                .tls
                .acme
                .issuer
                .clone()
                .unwrap_or_else(|| config.tls.acme.default_issuer.clone());
            let domains = if vhost.tls.acme.domains.is_empty() {
                vhost
                    .hosts
                    .iter()
                    .filter(|host| !host.starts_with("*."))
                    .map(|host| normalized_domain(host))
                    .collect()
            } else {
                vhost
                    .tls
                    .acme
                    .domains
                    .iter()
                    .map(|domain| normalized_domain(domain))
                    .collect()
            };

            AcmeRenewalTarget {
                vhost_name: vhost.name.clone(),
                issuer,
                domains,
                challenge: config.tls.acme.challenge,
            }
        })
        .collect()
}

pub fn plan_renewal_queue(
    config: &Config,
    observations: &[CertificateObservation],
    now: SystemTime,
) -> Vec<AcmeRenewalItem> {
    let renewal = &config.tls.acme.renewal;
    let renew_after = renewal
        .renew_after
        .as_ref()
        .and_then(toml_offset_datetime_to_system_time);
    let renew_before = Duration::from_secs(renewal.renew_before_secs);

    let mut items: Vec<AcmeRenewalItem> = renewal_targets(config)
        .into_iter()
        .map(|target| {
            let not_after = observations
                .iter()
                .find(|observation| observation.vhost_name == target.vhost_name)
                .map(|observation| observation.not_after);
            let certificate_due_at = not_after
                .map(|time| time.checked_sub(renew_before).unwrap_or(UNIX_EPOCH))
                .unwrap_or(now);
            let due_at = renew_after
                .map(|time| max_system_time(certificate_due_at, time))
                .unwrap_or(certificate_due_at);

            AcmeRenewalItem {
                target,
                not_after,
                due_at,
                due_now: due_at <= now,
            }
        })
        .collect();

    items.sort_by(compare_queue_items);
    items
}

pub fn next_retry_at(
    now: SystemTime,
    failures: u32,
    initial_secs: u64,
    max_secs: u64,
) -> SystemTime {
    let capped_shift = failures.min(63);
    let multiplier = 1_u64.checked_shl(capped_shift).unwrap_or(u64::MAX);
    let delay_secs = initial_secs.saturating_mul(multiplier).min(max_secs);
    now + Duration::from_secs(delay_secs)
}

pub fn toml_offset_datetime_to_system_time(datetime: &Datetime) -> Option<SystemTime> {
    let date = datetime.date?;
    let time = datetime.time?;
    let offset = datetime.offset?;
    let second = u64::from(time.second.unwrap_or(0));
    if second > 59 {
        return None;
    }

    let local_seconds = days_from_civil(date.year.into(), date.month.into(), date.day.into())?
        .checked_mul(86_400)?
        .checked_add(i64::from(time.hour) * 3_600)?
        .checked_add(i64::from(time.minute) * 60)?
        .checked_add(i64::try_from(second).ok()?)?;

    let offset_seconds = match offset {
        Offset::Z => 0,
        Offset::Custom { minutes } => i64::from(minutes) * 60,
    };
    let unix_seconds = local_seconds.checked_sub(offset_seconds)?;
    let nanos = time.nanosecond.unwrap_or(0);

    Some(system_time_from_unix(unix_seconds, nanos))
}

fn normalized_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn compare_queue_items(left: &AcmeRenewalItem, right: &AcmeRenewalItem) -> Ordering {
    left.due_at
        .cmp(&right.due_at)
        .then_with(|| left.target.vhost_name.cmp(&right.target.vhost_name))
}

fn max_system_time(left: SystemTime, right: SystemTime) -> SystemTime {
    if left >= right { left } else { right }
}

fn system_time_from_unix(seconds: i64, nanos: u32) -> SystemTime {
    if seconds >= 0 {
        UNIX_EPOCH + Duration::new(seconds as u64, nanos)
    } else {
        UNIX_EPOCH - Duration::new(seconds.unsigned_abs(), nanos)
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    Some(era * 146_097 + day_of_era - 719_468)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    use crate::config::{
        AcmeConfig, CacheConfig, Config, ProxyConfig, TlsConfig, VhostAcmeConfig, VhostConfig,
        VhostTlsConfig, WebConfig,
    };

    use super::{
        CertificateObservation, next_retry_at, plan_renewal_queue, renewal_targets,
        toml_offset_datetime_to_system_time,
    };

    #[test]
    fn skips_targets_when_global_acme_is_disabled() {
        let config = Config::default();

        assert!(renewal_targets(&config).is_empty());
    }

    #[test]
    fn builds_targets_from_enabled_vhosts() {
        let config = acme_config_with_vhosts(vec![VhostConfig {
            name: "example".to_owned(),
            hosts: vec!["Example.TEST".to_owned(), "*.example.test".to_owned()],
            max_request_body_bytes: None,
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: VhostTlsConfig {
                enabled: true,
                acme: VhostAcmeConfig {
                    enabled: true,
                    issuer: None,
                    domains: Vec::new(),
                },
                certificate: None,
            },
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }]);

        let targets = renewal_targets(&config);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].issuer, "letsencrypt");
        assert_eq!(targets[0].domains, vec!["example.test"]);
    }

    #[test]
    fn plans_initial_issue_for_missing_certificate() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let config = acme_config_with_vhosts(vec![managed_vhost("example")]);

        let queue = plan_renewal_queue(&config, &[], now);

        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].due_at, now);
        assert!(queue[0].due_now);
        assert_eq!(queue[0].not_after, None);
    }

    #[test]
    fn uses_later_of_renew_window_and_operator_date() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut config = acme_config_with_vhosts(vec![managed_vhost("example")]);
        config.tls.acme.renewal.renew_before_secs = 100;
        config.tls.acme.renewal.renew_after =
            Some("1970-01-01T00:18:20Z".parse().expect("valid TOML datetime"));
        let observations = vec![CertificateObservation {
            vhost_name: "example".to_owned(),
            not_after: UNIX_EPOCH + Duration::from_secs(1_150),
        }];

        let queue = plan_renewal_queue(&config, &observations, now);

        assert_eq!(queue[0].due_at, UNIX_EPOCH + Duration::from_secs(1_100));
        assert!(!queue[0].due_now);
    }

    #[test]
    fn sorts_queue_by_due_time() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut config =
            acme_config_with_vhosts(vec![managed_vhost("later"), managed_vhost("earlier")]);
        config.tls.acme.renewal.renew_before_secs = 100;
        let observations = vec![
            CertificateObservation {
                vhost_name: "later".to_owned(),
                not_after: UNIX_EPOCH + Duration::from_secs(1_400),
            },
            CertificateObservation {
                vhost_name: "earlier".to_owned(),
                not_after: UNIX_EPOCH + Duration::from_secs(1_200),
            },
        ];

        let queue = plan_renewal_queue(&config, &observations, now);

        assert_eq!(queue[0].target.vhost_name, "earlier");
        assert_eq!(queue[1].target.vhost_name, "later");
    }

    #[test]
    fn retry_backoff_is_capped() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);

        assert_eq!(
            next_retry_at(now, 0, 300, 86_400),
            UNIX_EPOCH + Duration::from_secs(1_300)
        );
        assert_eq!(
            next_retry_at(now, 20, 300, 86_400),
            UNIX_EPOCH + Duration::from_secs(87_400)
        );
    }

    #[test]
    fn converts_offset_datetime_to_utc_system_time() {
        let datetime = "1970-01-01T01:00:00+01:00"
            .parse()
            .expect("valid TOML datetime");

        assert_eq!(
            toml_offset_datetime_to_system_time(&datetime),
            Some(UNIX_EPOCH)
        );
    }

    fn acme_config_with_vhosts(vhosts: Vec<VhostConfig>) -> Config {
        Config {
            tls: TlsConfig {
                enabled: true,
                acme: AcmeConfig {
                    enabled: true,
                    storage: Some(PathBuf::from("/var/lib/fluxheim/acme")),
                    ..AcmeConfig::default()
                },
                ..TlsConfig::default()
            },
            vhosts,
            ..Config::default()
        }
    }

    fn managed_vhost(name: &str) -> VhostConfig {
        VhostConfig {
            name: name.to_owned(),
            hosts: vec![format!("{name}.test")],
            max_request_body_bytes: None,
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: VhostTlsConfig {
                enabled: true,
                acme: VhostAcmeConfig {
                    enabled: true,
                    issuer: None,
                    domains: Vec::new(),
                },
                certificate: None,
            },
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }
    }
}
