#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod api;
pub mod headers;

pub use api::{
    CacheBackgroundPurgeResult, CacheBulkPurgeRequest, CacheBulkPurgeResult,
    CacheIndexedPathPatternPurgeRequest, CacheIndexedPathPrefixPurgeRequest,
    CacheIndexedPurgeRequest, CacheIndexedPurgeResult, CacheIndexedTagPurgeRequest,
    CacheKeyPreview, CacheKeyPreviewScope, CachePurgeRequest, CachePurgeResult,
    CacheStalePurgeRequest, CacheStalePurgeResult,
};
