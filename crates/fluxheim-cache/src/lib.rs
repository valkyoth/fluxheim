#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod api;
mod api_summary;
pub mod headers;
mod headers_directives;
mod headers_request;
mod headers_response;
mod headers_vary;
pub mod metrics;
pub mod object;
pub mod plan;
pub mod purge_index;
pub mod request;
pub mod storage;
pub mod storage_bin;
mod storage_bin_alloc;
mod storage_bin_fs;
mod storage_bin_manifest;
pub mod tags;

#[cfg(test)]
mod api_tests;
#[cfg(test)]
mod object_tests;
#[cfg(test)]
mod request_tests;
#[cfg(test)]
mod storage_bin_tests;

pub fn cache_user_tag(vhost: &str, route: Option<&str>) -> String {
    route
        .map(|route| format!("{vhost}:route:{route}"))
        .unwrap_or_else(|| vhost.to_owned())
}

pub use api::{
    CacheActivityResetResult, CacheActivityStats, CacheBackgroundPurgeResult,
    CacheBulkPurgeRequest, CacheBulkPurgeResult, CacheIndexedPathPatternPurgeRequest,
    CacheIndexedPathPrefixPurgeRequest, CacheIndexedPurgeRequest, CacheIndexedPurgeResult,
    CacheIndexedTagPurgeRequest, CacheKeyPreview, CacheKeyPreviewScope, CacheObjectFreshnessState,
    CacheObjectHeaderValue, CacheObjectLookup, CacheObjectMetadata, CacheObjectTier,
    CachePurgeRequest, CachePurgeResult, CacheRouteStats, CacheRuntimeStats, CacheRuntimeTotals,
    CacheStalePurgeRequest, CacheStalePurgeResult, CacheVhostStats, DiskCacheStats,
    MemoryCacheStats, TieredCacheStats, cache_average_bytes,
    cache_object_lookup_body_bytes_summary, cache_object_lookup_bool_summary,
    cache_object_lookup_cache_tags_summary, cache_object_lookup_fresh_ttl_summary,
    cache_object_lookup_header_names_summary, cache_object_lookup_header_values_summary,
    cache_ratio_per_mille, cache_ratio_per_mille_usize, cache_stale_would_purge,
    cache_storage_tiers, cache_warm_counts_summary, cache_warm_increment_count,
    cache_warm_safe_label,
};
pub use headers::{
    CacheRequestView, CacheStaleEvent, MAX_VARY_FIELDS, VaryCachePolicy, VaryRequestHashField,
    cache_control_freshness_value, cache_control_with_directive, cache_should_serve_stale,
    cache_stale_status_allows, cache_vary_policy, cookie_headers_match_cache_bypass,
    first_header_value, query_matches_cache_bypass, range_response_cache_admission_rejection,
    remaining_fresh_ttl_secs, request_cache_bypass_reason, request_cache_revalidation_requested,
    response_age_secs, response_cache_admission_rejection, response_cache_control_max_age,
    response_cache_header_policy_rejection, response_content_type_is_cacheable,
    response_range_cache_admission_rejection, sanitize_multipart_content_type,
    selected_cache_range_request, selected_cache_slice_range_request, vary_cache_policy,
    vary_request_hash_material,
};
pub use metrics::{
    cache_event_label, cache_operation_label, cache_phase_label, cache_purge_mode_label,
    cache_purge_operation_label, cache_purger_entry_result_label, cache_purger_outcome_label,
    cache_scope_label, cache_tier_label,
};
pub use object::{
    CacheStoreError, CachedHeader, CachedImageObject, DISK_CACHE_MAGIC_V1, DISK_CACHE_MAGIC_V2,
    DISK_CACHE_MAGIC_V3, DISK_CACHE_MAGIC_V4, DISK_CACHE_MAGIC_V5, DiskCacheEntry,
    DiskCacheObjectKey, DiskObjectIndex, DiskObjectLruKey, FluxCacheMissFinish, FluxCachePurgeType,
    SerializedCacheObject, disk_cache_header_overhead, encode_disk_cache_object,
    parse_disk_cache_object, write_disk_cache_object_plaintext_prefix,
};
pub use plan::{CacheStoragePlan, DiskTierPlan, MemoryTierPlan};
pub use purge_index::{CachePurgeIndex, CachePurgeIndexEntry};
pub use request::{
    CacheClientRange, CacheContentRange, CacheKey, CacheRangeRequest, CacheRequest,
    CacheSliceBounds, CacheSliceRangeRequest, FluxCacheKeyParts, StaticCacheRequest,
    append_cache_key_component, cache_key_with_component, cache_method_temporarily_bypassed,
    eligible_image_request, eligible_static_request, image_cache_key, parse_bounded_single_range,
    parse_cache_client_ranges, parse_cache_content_range, required_slice_bounds,
    resolve_client_slice_ranges, response_content_length_matches_range,
    response_content_range_matches, slice_request_within_policy, static_cache_key,
};
pub use storage::{
    FluxCacheHitHandler, FluxCacheMissHandler, FluxCacheStorage, FluxCacheTrace, FluxHandleHit,
    FluxHandleMiss, SerializedCacheMeta,
};
pub use storage_bin::{
    STORAGE_BIN_DATA_DIR, STORAGE_BIN_INDEX_FILENAME, STORAGE_BIN_MANIFEST_FILENAME,
    StorageBinFileSet, StorageBinFreeMap, StorageBinFreeRange, StorageBinIndexEntry,
    StorageBinLayoutPlan, StorageBinManifest, StorageBinObjectLocation, prepare_storage_bin_layout,
    read_storage_bin_index, storage_bin_index_path, write_storage_bin_index,
};
pub use tags::{
    MAX_CACHE_TAG_BYTES_PER_OBJECT, MAX_CACHE_TAG_LEN, MAX_CACHE_TAGS_PER_OBJECT,
    collect_cache_tags, decode_cache_tags, default_cache_tag_headers_for_storage,
    encode_cache_tags, encoded_cache_tags_len, is_valid_cache_tag,
};
