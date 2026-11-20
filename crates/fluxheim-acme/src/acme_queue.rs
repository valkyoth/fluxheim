use std::cmp::Ordering;

use toml::value::{Datetime, Offset};

use super::*;

pub(super) const EMERGENCY_RENEWAL_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

pub(super) fn emergency_at(not_after: Option<SystemTime>, now: SystemTime) -> SystemTime {
    not_after.map_or(now, |time| {
        time.checked_sub(EMERGENCY_RENEWAL_WINDOW).unwrap_or(now)
    })
}

pub(super) fn renewal_deadline(config: &Config) -> Option<SystemTime> {
    config
        .tls
        .acme
        .renewal
        .renew_after
        .as_ref()
        .and_then(toml_offset_datetime_to_system_time)
}

pub fn renewal_held(config: &Config, now: SystemTime) -> bool {
    renewal_deadline(config).is_some_and(|deadline| now < deadline)
}

pub fn plan_renewal_queue(
    config: &Config,
    observations: &[CertificateObservation],
    now: SystemTime,
) -> Vec<AcmeRenewalItem> {
    let renewal = &config.tls.acme.renewal;
    let renew_after = renewal_deadline(config);
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
            let emergency = emergency_at(not_after, now);
            let due_at = match (renew_after, renewal.hold_mode) {
                (None, _) => certificate_due_at.min(emergency),
                (Some(hold), fluxheim_config::AcmeHoldMode::Absolute) => {
                    certificate_due_at.min(emergency).max(hold)
                }
                (Some(hold), fluxheim_config::AcmeHoldMode::Elective) => {
                    certificate_due_at.max(hold).min(emergency)
                }
            };

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

    if unix_seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(unix_seconds as u64, nanos))
    } else {
        UNIX_EPOCH.checked_sub(
            Duration::from_secs(unix_seconds.unsigned_abs())
                .checked_sub(Duration::from_nanos(u64::from(nanos)))?,
        )
    }
}
fn compare_queue_items(left: &AcmeRenewalItem, right: &AcmeRenewalItem) -> Ordering {
    left.due_at
        .cmp(&right.due_at)
        .then_with(|| left.target.vhost_name.cmp(&right.target.vhost_name))
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
