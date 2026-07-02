use std::sync::OnceLock;

use prometheus::IntGauge;

static CACHE_VHOSTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ENABLED_VHOSTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_TIERED_VHOSTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_CONFIGURED_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_POLICY_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ENABLED_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_TIERED_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_TIERS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_TIERS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_LOCK_ENABLED_POLICIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_LOCK_WAIT_TIMEOUT_MAX_SECONDS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ORIGIN_PROTECTION_ENABLED_POLICIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ORIGIN_PROTECTION_MAX_CONCURRENT_FILLS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_PEER_FILL_ENABLED_POLICIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_PEER_FILL_PEERS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_ENTRIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_WEIGHTED_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_MAX_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_FILL_RATIO_PER_MILLE: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_PURGE_INDEX_ENTRIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_ENTRIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_ALLOCATED_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_FREE_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_FREE_RANGE_COUNT: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_LARGEST_FREE_RANGE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_BIN_FILES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_MAX_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_FILL_RATIO_PER_MILLE: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_PURGE_INDEX_ENTRIES: OnceLock<IntGauge> = OnceLock::new();
pub(in crate::metrics) fn cache_vhosts() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_VHOSTS,
        "fluxheim_cache_vhosts",
        "Configured Fluxheim virtual hosts visible to cache metrics.",
    )
}

pub(in crate::metrics) fn cache_enabled_vhosts() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ENABLED_VHOSTS,
        "fluxheim_cache_enabled_vhosts",
        "Configured Fluxheim virtual hosts with cache enabled.",
    )
}

pub(in crate::metrics) fn cache_tiered_vhosts() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_TIERED_VHOSTS,
        "fluxheim_cache_tiered_vhosts",
        "Configured Fluxheim virtual hosts using both memory and disk cache tiers.",
    )
}

pub(in crate::metrics) fn cache_configured_routes() -> Result<&'static IntGauge, prometheus::Error>
{
    int_gauge(
        &CACHE_CONFIGURED_ROUTES,
        "fluxheim_cache_configured_routes",
        "Configured Fluxheim routes visible to cache metrics.",
    )
}

pub(in crate::metrics) fn cache_policy_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_POLICY_ROUTES,
        "fluxheim_cache_policy_routes",
        "Configured Fluxheim routes with an explicit cache policy.",
    )
}

pub(in crate::metrics) fn cache_enabled_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ENABLED_ROUTES,
        "fluxheim_cache_enabled_routes",
        "Configured Fluxheim routes with an explicit enabled cache policy.",
    )
}

pub(in crate::metrics) fn cache_tiered_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_TIERED_ROUTES,
        "fluxheim_cache_tiered_routes",
        "Configured Fluxheim routes using both memory and disk cache tiers.",
    )
}

pub(in crate::metrics) fn cache_memory_tiers() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_TIERS,
        "fluxheim_cache_memory_tiers",
        "Configured Fluxheim cache memory tiers across vhosts and routes.",
    )
}

pub(in crate::metrics) fn cache_disk_tiers() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_TIERS,
        "fluxheim_cache_disk_tiers",
        "Configured Fluxheim cache disk tiers across vhosts and routes.",
    )
}

pub(in crate::metrics) fn cache_lock_enabled_policies()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_LOCK_ENABLED_POLICIES,
        "fluxheim_cache_lock_enabled_policies",
        "Configured Fluxheim cache policies with request-collapsing locks enabled and at least one storage tier.",
    )
}

pub(in crate::metrics) fn cache_lock_wait_timeout_max_seconds()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_LOCK_WAIT_TIMEOUT_MAX_SECONDS,
        "fluxheim_cache_lock_wait_timeout_max_seconds",
        "Maximum configured Fluxheim cache request-collapsing wait timeout across lock-enabled cache policies.",
    )
}

pub(in crate::metrics) fn cache_origin_protection_enabled_policies()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ORIGIN_PROTECTION_ENABLED_POLICIES,
        "fluxheim_cache_origin_protection_enabled_policies",
        "Configured Fluxheim cache policies with origin fill protection enabled.",
    )
}

pub(in crate::metrics) fn cache_origin_protection_max_concurrent_fills()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ORIGIN_PROTECTION_MAX_CONCURRENT_FILLS,
        "fluxheim_cache_origin_protection_max_concurrent_fills",
        "Maximum configured Fluxheim cache origin-fill concurrency budget across protected cache policies.",
    )
}

pub(in crate::metrics) fn cache_peer_fill_enabled_policies()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_PEER_FILL_ENABLED_POLICIES,
        "fluxheim_cache_peer_fill_enabled_policies",
        "Configured Fluxheim cache policies with distributed peer fill enabled.",
    )
}

pub(in crate::metrics) fn cache_peer_fill_peers() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_PEER_FILL_PEERS,
        "fluxheim_cache_peer_fill_peers",
        "Configured Fluxheim cache peer-fill peers across enabled cache policies.",
    )
}

pub(in crate::metrics) fn cache_peer_fill_max_concurrent_requests()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS,
        "fluxheim_cache_peer_fill_max_concurrent_requests",
        "Maximum configured Fluxheim cache peer-fill concurrency across enabled cache policies.",
    )
}

pub(in crate::metrics) fn cache_memory_entries() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_ENTRIES,
        "fluxheim_cache_memory_entries",
        "Current aggregate Fluxheim memory-cache object count.",
    )
}

pub(in crate::metrics) fn cache_memory_weighted_size_bytes()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_WEIGHTED_SIZE_BYTES,
        "fluxheim_cache_memory_weighted_size_bytes",
        "Current aggregate Fluxheim memory-cache weighted size in bytes.",
    )
}

pub(in crate::metrics) fn cache_memory_max_size_bytes()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_MAX_SIZE_BYTES,
        "fluxheim_cache_memory_max_size_bytes",
        "Configured aggregate Fluxheim memory-cache size budget in bytes.",
    )
}

pub(in crate::metrics) fn cache_memory_fill_ratio_per_mille()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_FILL_RATIO_PER_MILLE,
        "fluxheim_cache_memory_fill_ratio_per_mille",
        "Current aggregate Fluxheim memory-cache fill ratio in per-mille units.",
    )
}

pub(in crate::metrics) fn cache_memory_purge_index_entries()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_PURGE_INDEX_ENTRIES,
        "fluxheim_cache_memory_purge_index_entries",
        "Current aggregate Fluxheim memory-cache purge-index entry count.",
    )
}

pub(in crate::metrics) fn cache_disk_entries() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_ENTRIES,
        "fluxheim_cache_disk_entries",
        "Current aggregate Fluxheim disk-cache object count.",
    )
}

pub(in crate::metrics) fn cache_disk_size_bytes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_SIZE_BYTES,
        "fluxheim_cache_disk_size_bytes",
        "Current aggregate Fluxheim disk-cache size in bytes.",
    )
}

pub(in crate::metrics) fn cache_disk_allocated_size_bytes()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_ALLOCATED_SIZE_BYTES,
        "fluxheim_cache_disk_allocated_size_bytes",
        "Current aggregate Fluxheim disk-cache allocated storage bytes.",
    )
}

pub(in crate::metrics) fn cache_disk_free_size_bytes()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_FREE_SIZE_BYTES,
        "fluxheim_cache_disk_free_size_bytes",
        "Current aggregate Fluxheim disk-cache free allocated bytes.",
    )
}

pub(in crate::metrics) fn cache_disk_free_range_count()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_FREE_RANGE_COUNT,
        "fluxheim_cache_disk_free_range_count",
        "Current aggregate Fluxheim storage-bin disk-cache free range count.",
    )
}

pub(in crate::metrics) fn cache_disk_largest_free_range_bytes()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_LARGEST_FREE_RANGE_BYTES,
        "fluxheim_cache_disk_largest_free_range_bytes",
        "Largest Fluxheim storage-bin disk-cache free range in bytes across configured tiers.",
    )
}

pub(in crate::metrics) fn cache_disk_bin_files() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_BIN_FILES,
        "fluxheim_cache_disk_bin_files",
        "Current aggregate Fluxheim storage-bin disk-cache bin file count.",
    )
}

pub(in crate::metrics) fn cache_disk_max_size_bytes() -> Result<&'static IntGauge, prometheus::Error>
{
    int_gauge(
        &CACHE_DISK_MAX_SIZE_BYTES,
        "fluxheim_cache_disk_max_size_bytes",
        "Configured aggregate Fluxheim disk-cache size budget in bytes.",
    )
}

pub(in crate::metrics) fn cache_disk_fill_ratio_per_mille()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_FILL_RATIO_PER_MILLE,
        "fluxheim_cache_disk_fill_ratio_per_mille",
        "Current aggregate Fluxheim disk-cache fill ratio in per-mille units.",
    )
}

pub(in crate::metrics) fn cache_disk_purge_index_entries()
-> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_PURGE_INDEX_ENTRIES,
        "fluxheim_cache_disk_purge_index_entries",
        "Current aggregate Fluxheim disk-cache purge-index entry count.",
    )
}
pub(in crate::metrics) fn int_gauge(
    cell: &'static OnceLock<IntGauge>,
    name: &'static str,
    help: &'static str,
) -> Result<&'static IntGauge, prometheus::Error> {
    if let Some(gauge) = cell.get() {
        return Ok(gauge);
    }

    let gauge = IntGauge::new(name, help)?;
    match prometheus::default_registry().register(Box::new(gauge.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = cell.set(gauge);
    cell.get()
        .ok_or_else(|| prometheus::Error::Msg(format!("{name} failed to initialize")))
}
