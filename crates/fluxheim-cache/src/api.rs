use fluxheim_config::ByteSize;

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
    pub peer_fill_enabled: bool,
    pub peer_fill_peers: usize,
    pub peer_fill_max_concurrent_requests: usize,
    pub peer_fill_fail_open: bool,
    pub memory: Option<MemoryCacheStats>,
    pub disk: Option<DiskCacheStats>,
}
