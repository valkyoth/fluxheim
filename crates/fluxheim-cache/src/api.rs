use fluxheim_config::ByteSize;

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachePurgeRequest<'a> {
    pub vhost: Option<&'a str>,
    pub route: Option<&'a str>,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheBulkPurgeRequest<'a> {
    pub vhost: Option<&'a str>,
    pub route: Option<&'a str>,
    pub host: &'a str,
    pub method: &'a str,
    pub paths: Vec<&'a str>,
    pub query: Option<&'a str>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub limit: usize,
    pub soft: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPathPrefixPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub path_prefix: &'a str,
    pub limit: usize,
    pub soft: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedTagPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub cache_tag: &'a str,
    pub limit: usize,
    pub soft: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheStalePurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub limit: usize,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPathPatternPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub path_pattern: &'a str,
    pub limit: usize,
    pub soft: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheKeyPreview {
    pub vhost: String,
    pub route: Option<String>,
    pub scope: CacheKeyPreviewScope,
    pub eligible: bool,
    pub cache_lock_enabled: bool,
    pub cache_lock_wait_timeout_secs: u64,
    pub cache_predictor_enabled: bool,
    pub origin_protection_enabled: bool,
    pub origin_protection_max_concurrent_fills: usize,
    pub peer_fill_enabled: bool,
    pub peer_fill_peer_count: usize,
    pub peer_fill_max_concurrent_requests: usize,
    pub peer_fill_fail_open: bool,
    pub memory_tier_enabled: bool,
    pub disk_tier_enabled: bool,
    pub storage_tiers: u8,
    pub reason: Option<String>,
    pub namespace: Option<String>,
    pub key_namespace: Option<String>,
    pub primary_key: Option<String>,
    pub primary_hash: Option<String>,
    pub variance_hash: Option<String>,
    pub combined_hash: Option<String>,
    pub user_tag: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CacheKeyPreviewScope {
    Vhost,
    Route,
}

impl CacheKeyPreviewScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vhost => "vhost",
            Self::Route => "route",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachePurgeResult {
    pub vhost: String,
    pub route: Option<String>,
    pub host: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub cache_key: String,
    pub memory_purged: bool,
    pub disk_purged: bool,
}

impl CachePurgeResult {
    pub fn purged(&self) -> bool {
        self.memory_purged || self.disk_purged
    }

    pub fn not_purged(&self) -> bool {
        !self.purged()
    }

    pub fn memory_not_purged(&self) -> bool {
        !self.memory_purged
    }

    pub fn disk_not_purged(&self) -> bool {
        !self.disk_purged
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheBulkPurgeResult {
    pub vhost: String,
    pub results: Vec<CachePurgeResult>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPurgeResult {
    pub vhost: String,
    pub route: Option<String>,
    pub memory_matched: usize,
    pub memory_purged: usize,
    pub memory_truncated: bool,
    pub disk_matched: usize,
    pub disk_purged: usize,
    pub disk_truncated: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheStalePurgeResult {
    pub vhost: String,
    pub route: Option<String>,
    pub memory_scanned: usize,
    pub memory_stale: usize,
    pub memory_purged: usize,
    pub memory_truncated: bool,
    pub disk_scanned: usize,
    pub disk_stale: usize,
    pub disk_purged: usize,
    pub disk_truncated: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CacheBackgroundPurgeResult {
    pub targets: usize,
    pub scanned: usize,
    pub stale: usize,
    pub purged: usize,
    pub truncated: bool,
}

impl CacheStalePurgeResult {
    pub fn scanned(&self) -> usize {
        self.memory_scanned.saturating_add(self.disk_scanned)
    }

    pub fn stale(&self) -> usize {
        self.memory_stale.saturating_add(self.disk_stale)
    }

    pub fn purged(&self) -> usize {
        self.memory_purged.saturating_add(self.disk_purged)
    }

    pub fn not_purged(&self) -> usize {
        self.stale().saturating_sub(self.purged())
    }

    pub fn truncated(&self) -> bool {
        self.memory_truncated || self.disk_truncated
    }

    pub fn route(&self) -> Option<&str> {
        self.route.as_deref()
    }
}

impl CacheIndexedPurgeResult {
    pub fn matched(&self) -> usize {
        self.memory_matched.saturating_add(self.disk_matched)
    }

    pub fn purged(&self) -> usize {
        self.memory_purged.saturating_add(self.disk_purged)
    }

    pub fn not_purged(&self) -> usize {
        self.matched().saturating_sub(self.purged())
    }

    pub fn memory_not_purged(&self) -> usize {
        self.memory_matched.saturating_sub(self.memory_purged)
    }

    pub fn disk_not_purged(&self) -> usize {
        self.disk_matched.saturating_sub(self.disk_purged)
    }

    pub fn truncated(&self) -> bool {
        self.memory_truncated || self.disk_truncated
    }
}

impl CacheBulkPurgeResult {
    pub fn route(&self) -> Option<&str> {
        self.results
            .first()
            .and_then(|result| result.route.as_deref())
    }

    pub fn requested(&self) -> usize {
        self.results.len()
    }

    pub fn purged(&self) -> usize {
        self.results.iter().filter(|result| result.purged()).count()
    }

    pub fn not_purged(&self) -> usize {
        self.requested().saturating_sub(self.purged())
    }

    pub fn memory_purged(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.memory_purged)
            .count()
    }

    pub fn memory_not_purged(&self) -> usize {
        self.requested().saturating_sub(self.memory_purged())
    }

    pub fn disk_purged(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.disk_purged)
            .count()
    }

    pub fn disk_not_purged(&self) -> usize {
        self.requested().saturating_sub(self.disk_purged())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CacheActivityStats {
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub store_refusals: u64,
    pub evictions: u64,
    pub purges: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MemoryCacheStats {
    pub entries: u64,
    pub weighted_size_bytes: u64,
    pub max_size_bytes: ByteSize,
    pub max_object_bytes: ByteSize,
    pub purge_index_entries: u64,
    pub purge_index_max_entries: u64,
    pub activity: CacheActivityStats,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DiskCacheStats {
    pub backend: &'static str,
    pub entries: u64,
    pub size_bytes: u64,
    pub allocated_size_bytes: u64,
    pub free_size_bytes: u64,
    pub free_range_count: u64,
    pub largest_free_range_bytes: u64,
    pub bin_files: u64,
    pub max_size_bytes: ByteSize,
    pub max_object_bytes: ByteSize,
    pub purge_index_entries: u64,
    pub purge_index_max_entries: u64,
    pub activity: CacheActivityStats,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TieredCacheStats {
    pub memory: MemoryCacheStats,
    pub disk: DiskCacheStats,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheObjectHeaderValue {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheObjectMetadata {
    pub tier: CacheObjectTier,
    pub purge_indexed: bool,
    pub status: u16,
    pub fresh: bool,
    pub freshness_state: CacheObjectFreshnessState,
    pub serve_stale_while_revalidate: bool,
    pub serve_stale_if_error: bool,
    pub body_bytes: u64,
    pub weight_bytes: u64,
    pub created_unix_secs: Option<u64>,
    pub updated_unix_secs: Option<u64>,
    pub fresh_until_unix_secs: Option<u64>,
    pub age_secs: u64,
    pub fresh_ttl_secs: u64,
    pub stale_while_revalidate_secs: u32,
    pub stale_if_error_secs: u32,
    pub cache_tags: Vec<String>,
    pub header_names: Vec<String>,
    pub header_values: Vec<CacheObjectHeaderValue>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CacheObjectFreshnessState {
    Fresh,
    Stale,
    Expired,
}

impl CacheObjectFreshnessState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CacheObjectTier {
    Memory,
    Disk,
}

impl CacheObjectTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Disk => "disk",
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CacheRuntimeTotals {
    pub vhosts: u64,
    pub enabled_vhosts: u64,
    pub tiered_vhosts: u64,
    pub configured_routes: u64,
    pub routes_total: u64,
    pub enabled_routes: u64,
    pub tiered_routes: u64,
    pub lock_enabled_policies: u64,
    pub origin_protection_enabled_policies: u64,
    pub origin_protection_max_concurrent_fills: u64,
    pub peer_fill_enabled_policies: u64,
    pub peer_fill_peers: u64,
    pub peer_fill_max_concurrent_requests: u64,
    pub memory_tiers: u64,
    pub memory_entries: u64,
    pub memory_weighted_size_bytes: u64,
    pub memory_max_size_bytes: u64,
    pub memory_purge_index_entries: u64,
    pub memory_purge_index_max_entries: u64,
    pub disk_tiers: u64,
    pub disk_entries: u64,
    pub disk_size_bytes: u64,
    pub disk_allocated_size_bytes: u64,
    pub disk_free_size_bytes: u64,
    pub disk_free_range_count: u64,
    pub disk_largest_free_range_bytes: u64,
    pub disk_bin_files: u64,
    pub disk_max_size_bytes: u64,
    pub disk_purge_index_entries: u64,
    pub disk_purge_index_max_entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub store_refusals: u64,
    pub evictions: u64,
    pub purges: u64,
}

impl CacheRuntimeTotals {
    pub fn enabled_cache_policies(&self) -> u64 {
        self.enabled_vhosts.saturating_add(self.enabled_routes)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CacheActivityResetResult {
    pub vhosts: u64,
    pub enabled_vhosts: u64,
    pub configured_routes: u64,
    pub routes_total: u64,
    pub enabled_routes: u64,
    pub memory_tiers: u64,
    pub disk_tiers: u64,
    pub tiered_vhosts: u64,
    pub tiered_routes: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheObjectLookup {
    pub preview: CacheKeyPreview,
    pub objects: Vec<CacheObjectMetadata>,
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheRuntimeStats {
    pub totals: CacheRuntimeTotals,
    pub vhosts: Vec<CacheVhostStats>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheVhostStats {
    pub name: String,
    pub enabled: bool,
    pub tiered: bool,
    pub lock_enabled: bool,
    pub lock_wait_timeout_secs: u64,
    pub origin_protection_enabled: bool,
    pub origin_protection_max_concurrent_fills: usize,
    pub peer_fill_enabled: bool,
    pub peer_fill_peers: usize,
    pub peer_fill_max_concurrent_requests: usize,
    pub peer_fill_fail_open: bool,
    pub configured_routes: u64,
    pub routes_total: u64,
    pub enabled_routes: u64,
    pub tiered_routes: u64,
    pub memory: Option<MemoryCacheStats>,
    pub disk: Option<DiskCacheStats>,
    pub routes: Vec<CacheRouteStats>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheRouteStats {
    pub name: String,
    pub enabled: bool,
    pub tiered: bool,
    pub lock_enabled: bool,
    pub lock_wait_timeout_secs: u64,
    pub origin_protection_enabled: bool,
    pub origin_protection_max_concurrent_fills: usize,
    pub peer_fill_enabled: bool,
    pub peer_fill_peers: usize,
    pub peer_fill_max_concurrent_requests: usize,
    pub peer_fill_fail_open: bool,
    pub memory: Option<MemoryCacheStats>,
    pub disk: Option<DiskCacheStats>,
}

#[cfg(test)]
mod tests {
    use super::{
        CacheKeyPreview, CacheKeyPreviewScope, CacheObjectFreshnessState, CacheObjectHeaderValue,
        CacheObjectLookup, CacheObjectMetadata, CacheObjectTier, cache_average_bytes,
        cache_object_lookup_body_bytes_summary, cache_object_lookup_bool_summary,
        cache_object_lookup_cache_tags_summary, cache_object_lookup_fresh_ttl_summary,
        cache_object_lookup_header_names_summary, cache_object_lookup_header_values_summary,
        cache_ratio_per_mille, cache_ratio_per_mille_usize, cache_stale_would_purge,
        cache_storage_tiers, cache_warm_counts_summary, cache_warm_increment_count,
        cache_warm_safe_label,
    };

    #[test]
    fn cache_admin_math_handles_zero_denominators_and_saturation() {
        assert_eq!(cache_ratio_per_mille(5, 10), 500);
        assert_eq!(cache_ratio_per_mille(5, 0), 0);
        assert_eq!(cache_ratio_per_mille(u64::MAX, 1), u64::MAX);
        assert_eq!(cache_ratio_per_mille_usize(1, 4), 250);
        assert_eq!(cache_average_bytes(100, 4), 25);
        assert_eq!(cache_average_bytes(100, 0), 0);
    }

    #[test]
    fn cache_admin_policy_helpers_report_tiers_and_dry_run_counts() {
        assert_eq!(cache_storage_tiers(false, false), 0);
        assert_eq!(cache_storage_tiers(true, false), 1);
        assert_eq!(cache_storage_tiers(false, true), 1);
        assert_eq!(cache_storage_tiers(true, true), 2);
        assert_eq!(cache_stale_would_purge(true, 7), 7);
        assert_eq!(cache_stale_would_purge(false, 7), 0);
    }

    #[test]
    fn cache_warm_summaries_are_stable_and_bounded() {
        let empty = std::collections::BTreeMap::<String, usize>::new();
        assert_eq!(cache_warm_counts_summary(&empty), None);

        let mut counts = std::collections::BTreeMap::new();
        cache_warm_increment_count(&mut counts, "unexpected_status".to_owned());
        cache_warm_increment_count(&mut counts, "unexpected_status".to_owned());
        cache_warm_increment_count(&mut counts, "request_error".to_owned());
        cache_warm_increment_count(&mut counts, "unexpected_cache_status".to_owned());
        cache_warm_increment_count(&mut counts, "unexpected_cache_status".to_owned());
        cache_warm_increment_count(&mut counts, "unexpected_cache_status".to_owned());

        assert_eq!(
            cache_warm_counts_summary(&counts).as_deref(),
            Some("request_error=1 unexpected_cache_status=3 unexpected_status=2")
        );
        assert_eq!(cache_warm_safe_label(Some("HIT")), "HIT");
        assert_eq!(cache_warm_safe_label(None), "-");
        assert_eq!(cache_warm_safe_label(Some("bad value")), "other");
        assert_eq!(cache_warm_safe_label(Some("bad=value")), "other");
    }

    #[test]
    fn cache_object_lookup_summaries_are_stable_and_bounded() {
        let lookup = CacheObjectLookup {
            preview: CacheKeyPreview {
                vhost: "cache.test".to_owned(),
                route: None,
                scope: CacheKeyPreviewScope::Vhost,
                eligible: true,
                cache_lock_enabled: true,
                cache_lock_wait_timeout_secs: 30,
                cache_predictor_enabled: true,
                origin_protection_enabled: false,
                origin_protection_max_concurrent_fills: 32,
                peer_fill_enabled: false,
                peer_fill_peer_count: 0,
                peer_fill_max_concurrent_requests: 64,
                peer_fill_fail_open: true,
                memory_tier_enabled: true,
                disk_tier_enabled: true,
                storage_tiers: 2,
                reason: None,
                namespace: None,
                key_namespace: None,
                primary_key: None,
                primary_hash: None,
                variance_hash: None,
                combined_hash: None,
                user_tag: None,
            },
            objects: vec![
                CacheObjectMetadata {
                    tier: CacheObjectTier::Memory,
                    purge_indexed: true,
                    status: 200,
                    fresh: true,
                    freshness_state: CacheObjectFreshnessState::Fresh,
                    serve_stale_while_revalidate: false,
                    serve_stale_if_error: true,
                    body_bytes: 42,
                    weight_bytes: 64,
                    created_unix_secs: None,
                    updated_unix_secs: None,
                    fresh_until_unix_secs: None,
                    age_secs: 0,
                    fresh_ttl_secs: 120,
                    stale_while_revalidate_secs: 0,
                    stale_if_error_secs: 60,
                    cache_tags: vec!["asset".to_owned(), "shared".to_owned()],
                    header_names: vec!["cache-control".to_owned(), "etag".to_owned()],
                    header_values: vec![
                        CacheObjectHeaderValue {
                            name: "etag".to_owned(),
                            value: "\"a\"".to_owned(),
                        },
                        CacheObjectHeaderValue {
                            name: "x-other".to_owned(),
                            value: "ignored".to_owned(),
                        },
                    ],
                },
                CacheObjectMetadata {
                    tier: CacheObjectTier::Disk,
                    purge_indexed: false,
                    status: 200,
                    fresh: true,
                    freshness_state: CacheObjectFreshnessState::Fresh,
                    serve_stale_while_revalidate: false,
                    serve_stale_if_error: false,
                    body_bytes: 42,
                    weight_bytes: 64,
                    created_unix_secs: None,
                    updated_unix_secs: None,
                    fresh_until_unix_secs: None,
                    age_secs: 0,
                    fresh_ttl_secs: 60,
                    stale_while_revalidate_secs: 0,
                    stale_if_error_secs: 60,
                    cache_tags: vec!["asset".to_owned()],
                    header_names: vec!["etag".to_owned()],
                    header_values: vec![CacheObjectHeaderValue {
                        name: "ETag".to_owned(),
                        value: "\"b\"".to_owned(),
                    }],
                },
            ],
        };

        assert_eq!(
            cache_object_lookup_bool_summary(&lookup, |object| object.serve_stale_if_error),
            "false,true"
        );
        assert_eq!(cache_object_lookup_fresh_ttl_summary(&lookup), "120,60");
        assert_eq!(cache_object_lookup_body_bytes_summary(&lookup), "42");
        assert_eq!(
            cache_object_lookup_header_names_summary(&lookup),
            "cache-control,etag"
        );
        assert_eq!(
            cache_object_lookup_header_values_summary(&lookup, "etag"),
            "etag: \"a\",etag: \"b\""
        );
        assert_eq!(
            cache_object_lookup_cache_tags_summary(&lookup),
            "asset,shared"
        );
    }
}
