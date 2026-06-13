#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod api;
pub mod headers;
pub mod object;
pub mod plan;
pub mod purge_index;
pub mod request;

pub use api::{
    CacheActivityResetResult, CacheActivityStats, CacheBackgroundPurgeResult,
    CacheBulkPurgeRequest, CacheBulkPurgeResult, CacheIndexedPathPatternPurgeRequest,
    CacheIndexedPathPrefixPurgeRequest, CacheIndexedPurgeRequest, CacheIndexedPurgeResult,
    CacheIndexedTagPurgeRequest, CacheKeyPreview, CacheKeyPreviewScope, CacheObjectFreshnessState,
    CacheObjectHeaderValue, CacheObjectLookup, CacheObjectMetadata, CacheObjectTier,
    CachePurgeRequest, CachePurgeResult, CacheRouteStats, CacheRuntimeStats, CacheRuntimeTotals,
    CacheStalePurgeRequest, CacheStalePurgeResult, CacheVhostStats, DiskCacheStats,
    MemoryCacheStats, TieredCacheStats,
};
pub use object::{CacheStoreError, CachedHeader, CachedImageObject};
pub use plan::{CacheStoragePlan, DiskTierPlan, MemoryTierPlan};
pub use purge_index::{CachePurgeIndex, CachePurgeIndexEntry};
pub use request::{
    CacheClientRange, CacheKey, CacheRangeRequest, CacheRequest, CacheSliceBounds,
    CacheSliceRangeRequest, StaticCacheRequest, parse_bounded_single_range,
    parse_cache_client_ranges, required_slice_bounds, resolve_client_slice_ranges,
};
