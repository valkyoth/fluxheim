pub use fluxheim_cache::{
    CacheActivityResetResult, CacheBackgroundPurgeResult, CacheBulkPurgeRequest,
    CacheBulkPurgeResult, CacheIndexedPathPatternPurgeRequest, CacheIndexedPathPrefixPurgeRequest,
    CacheIndexedPurgeRequest, CacheIndexedPurgeResult, CacheIndexedTagPurgeRequest,
    CacheKeyPreview, CacheKeyPreviewScope, CachePurgeRequest, CachePurgeResult, CacheRuntimeTotals,
    CacheStalePurgeRequest, CacheStalePurgeResult,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheObjectLookup {
    pub preview: CacheKeyPreview,
    pub objects: Vec<crate::cache::CacheObjectMetadata>,
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
    pub memory: Option<crate::cache::MemoryCacheStats>,
    pub disk: Option<crate::cache::DiskCacheStats>,
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
    pub memory: Option<crate::cache::MemoryCacheStats>,
    pub disk: Option<crate::cache::DiskCacheStats>,
}
