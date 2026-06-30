use crate::api::{CacheObjectLookup, CacheObjectMetadata};

pub fn cache_storage_tiers(memory: bool, disk: bool) -> u8 {
    u8::from(memory).saturating_add(u8::from(disk))
}

pub fn cache_ratio_per_mille(numerator: u64, denominator: u64) -> u64 {
    numerator
        .saturating_mul(1000)
        .checked_div(denominator)
        .unwrap_or(0)
}

pub fn cache_ratio_per_mille_usize(numerator: usize, denominator: usize) -> u64 {
    cache_ratio_per_mille(
        u64::try_from(numerator).unwrap_or(u64::MAX),
        u64::try_from(denominator).unwrap_or(u64::MAX),
    )
}

pub fn cache_average_bytes(total_bytes: u64, entries: u64) -> u64 {
    total_bytes.checked_div(entries).unwrap_or(0)
}

pub fn cache_stale_would_purge(dry_run: bool, stale: usize) -> usize {
    if dry_run { stale } else { 0 }
}

pub fn cache_warm_increment_count<K: Ord>(
    counts: &mut std::collections::BTreeMap<K, usize>,
    key: K,
) {
    let count = counts.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

pub fn cache_warm_counts_summary<K: std::fmt::Display>(
    counts: &std::collections::BTreeMap<K, usize>,
) -> Option<String> {
    if counts.is_empty() {
        return None;
    }

    Some(
        counts
            .iter()
            .map(|(key, count)| format!("{key}={count}"))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

pub fn cache_warm_safe_label(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "-".to_owned();
    };
    if value.is_empty() || value.len() > 64 {
        return "other".to_owned();
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'=')
    {
        return "other".to_owned();
    }
    value.to_owned()
}

pub fn cache_object_lookup_bool_summary(
    lookup: &CacheObjectLookup,
    value: impl Fn(&CacheObjectMetadata) -> bool,
) -> String {
    let mut values = lookup
        .objects
        .iter()
        .map(|object| value(object).to_string())
        .collect::<Vec<_>>();
    if values.is_empty() {
        return "none".to_owned();
    }
    values.sort_unstable();
    values.dedup();
    values.join(",")
}

pub fn cache_object_lookup_fresh_ttl_summary(lookup: &CacheObjectLookup) -> String {
    let mut ttls = lookup
        .objects
        .iter()
        .map(|object| object.fresh_ttl_secs.to_string())
        .collect::<Vec<_>>();
    if ttls.is_empty() {
        return "none".to_owned();
    }
    ttls.sort_unstable();
    ttls.dedup();
    ttls.join(",")
}

pub fn cache_object_lookup_body_bytes_summary(lookup: &CacheObjectLookup) -> String {
    let mut sizes = lookup
        .objects
        .iter()
        .map(|object| object.body_bytes.to_string())
        .collect::<Vec<_>>();
    if sizes.is_empty() {
        return "none".to_owned();
    }
    sizes.sort_unstable();
    sizes.dedup();
    sizes.join(",")
}

pub fn cache_object_lookup_header_names_summary(lookup: &CacheObjectLookup) -> String {
    let mut names = lookup
        .objects
        .iter()
        .flat_map(|object| object.header_names.iter().map(String::as_str))
        .collect::<Vec<_>>();
    if names.is_empty() {
        return "none".to_owned();
    }
    names.sort_unstable();
    names.dedup();
    names.join(",")
}

pub fn cache_object_lookup_header_values_summary(
    lookup: &CacheObjectLookup,
    expected_name: &str,
) -> String {
    let mut values = lookup
        .objects
        .iter()
        .flat_map(|object| {
            object
                .header_values
                .iter()
                .filter(move |header| header.name.eq_ignore_ascii_case(expected_name))
                .map(|header| header.value.as_str())
        })
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    if values.is_empty() {
        return "<none>".to_owned();
    }
    values
        .into_iter()
        .take(8)
        .map(|value| format!("{expected_name}: {value}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn cache_object_lookup_cache_tags_summary(lookup: &CacheObjectLookup) -> String {
    let mut tags = lookup
        .objects
        .iter()
        .flat_map(|object| object.cache_tags.iter().map(String::as_str))
        .collect::<Vec<_>>();
    if tags.is_empty() {
        return "none".to_owned();
    }
    tags.sort_unstable();
    tags.dedup();
    tags.join(",")
}
