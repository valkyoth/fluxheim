#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod api;
pub mod headers;
pub mod metrics;
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
pub use headers::{
    CacheStaleEvent, MAX_VARY_FIELDS, VaryCachePolicy, VaryRequestHashField,
    cache_control_freshness_value, cache_control_with_directive, cache_should_serve_stale,
    cache_stale_status_allows, cache_vary_policy, cookie_headers_match_cache_bypass,
    query_matches_cache_bypass, remaining_fresh_ttl_secs, response_age_secs,
    response_cache_control_max_age, response_content_type_is_cacheable, vary_cache_policy,
    vary_request_hash_material,
};
pub use metrics::{
    cache_event_label, cache_operation_label, cache_phase_label, cache_purge_mode_label,
    cache_purge_operation_label, cache_purger_entry_result_label, cache_purger_outcome_label,
    cache_scope_label, cache_tier_label,
};
pub use object::{CacheStoreError, CachedHeader, CachedImageObject};
pub use plan::{CacheStoragePlan, DiskTierPlan, MemoryTierPlan};
pub use purge_index::{CachePurgeIndex, CachePurgeIndexEntry};
pub use request::{
    CacheClientRange, CacheContentRange, CacheKey, CacheRangeRequest, CacheRequest,
    CacheSliceBounds, CacheSliceRangeRequest, StaticCacheRequest, append_cache_key_component,
    cache_method_temporarily_bypassed, parse_bounded_single_range, parse_cache_client_ranges,
    parse_cache_content_range, required_slice_bounds, resolve_client_slice_ranges,
    response_content_length_matches_range, response_content_range_matches,
    slice_request_within_policy,
};
