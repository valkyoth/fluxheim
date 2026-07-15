use fluxheim_config::{CacheConfig, CacheKeyPart, normalize_host};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheRequest<'a> {
    pub method: &'a str,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct StaticCacheRequest<'a> {
    pub method: &'a str,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub file_identity: &'a str,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct CacheKey(String);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FluxCacheKeyParts {
    primary: String,
    combined: String,
    user_tag: String,
}

impl FluxCacheKeyParts {
    pub fn new(
        primary: impl Into<String>,
        combined: impl Into<String>,
        user_tag: impl Into<String>,
    ) -> Self {
        Self {
            primary: primary.into(),
            combined: combined.into(),
            user_tag: user_tag.into(),
        }
    }

    pub fn primary(&self) -> &str {
        &self.primary
    }

    pub fn combined(&self) -> &str {
        &self.combined
    }

    pub fn user_tag(&self) -> &str {
        &self.user_tag
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheRangeRequest {
    pub start: u64,
    pub end: u64,
}

impl CacheRangeRequest {
    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    pub fn is_empty(self) -> bool {
        self.end < self.start
    }

    pub fn component(self) -> String {
        format!("bytes={}-{}", self.start, self.end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheContentRange {
    pub start: u64,
    pub end: u64,
    pub total: Option<u64>,
}

impl CacheContentRange {
    pub fn bounds(self) -> CacheRangeRequest {
        CacheRangeRequest {
            start: self.start,
            end: self.end,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheClientRange {
    Bounded { start: u64, end: u64 },
    OpenEnded { start: u64 },
    Suffix { len: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheSliceRangeRequest {
    pub ranges: Vec<CacheClientRange>,
    pub if_range: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheSliceBounds {
    pub start: u64,
    pub end: u64,
}

impl CacheSliceBounds {
    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    pub fn is_empty(self) -> bool {
        self.end < self.start
    }

    pub fn range_request(self) -> CacheRangeRequest {
        CacheRangeRequest {
            start: self.start,
            end: self.end,
        }
    }
}

const MAX_CACHE_CLIENT_RANGES: usize = 128;
const MULTIPART_SLICE_OVERHEAD_BYTES_PER_RANGE: u64 = 256;
const MULTIPART_SLICE_CLOSING_OVERHEAD_BYTES: u64 = 128;

impl CacheKey {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn append_cache_key_component(key: &mut String, label: &str, value: &str) {
    use std::fmt::Write as _;
    let _ = write!(key, "{label}:{}:{value};", value.len());
}

pub fn cache_key_with_component(primary: &str, label: &str, value: &str) -> String {
    let mut key = primary.to_owned();
    append_cache_key_component(&mut key, label, value);
    key
}

pub fn cache_method_temporarily_bypassed(method: &str) -> bool {
    method == "HEAD"
}

pub fn eligible_image_request(config: &CacheConfig, request: &CacheRequest<'_>) -> bool {
    config.enabled
        && config.has_enabled_tier()
        && method_allowed(config, request.method)
        && image_extension(request.path).is_some_and(|extension| {
            config
                .image_extensions
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(extension))
        })
}

pub fn image_cache_key(config: &CacheConfig, request: &CacheRequest<'_>) -> Option<CacheKey> {
    if !eligible_image_request(config, request) {
        return None;
    }

    let mut key = String::from("fluxheim-image-v1;");
    if let Some(namespace) = config.key_namespace.as_deref() {
        append_cache_key_component(&mut key, "namespace", namespace);
    }
    for part in &config.key_parts {
        match part {
            CacheKeyPart::Method => append_cache_key_component(&mut key, "method", request.method),
            CacheKeyPart::Host => append_cache_key_component(
                &mut key,
                "host",
                &request.host.and_then(normalize_host).unwrap_or_default(),
            ),
            CacheKeyPart::Path => append_cache_key_component(&mut key, "path", request.path),
            CacheKeyPart::Query if config.include_query => {
                append_cache_key_component(&mut key, "query", request.query.unwrap_or_default());
            }
            CacheKeyPart::Query => {}
        }
    }
    Some(CacheKey::new(key))
}

pub fn eligible_static_request(config: &CacheConfig, request: &StaticCacheRequest<'_>) -> bool {
    config.enabled
        && config.local_static
        && config.has_enabled_tier()
        && request.method == "GET"
        && image_extension(request.path).is_some_and(|extension| {
            config
                .image_extensions
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(extension))
        })
}

pub fn static_cache_key(
    config: &CacheConfig,
    request: &StaticCacheRequest<'_>,
) -> Option<CacheKey> {
    if !eligible_static_request(config, request) {
        return None;
    }

    let mut key = String::from("fluxheim-static-v1;");
    if let Some(namespace) = config.key_namespace.as_deref() {
        append_cache_key_component(&mut key, "namespace", namespace);
    }
    for part in &config.key_parts {
        match part {
            CacheKeyPart::Method => append_cache_key_component(&mut key, "method", request.method),
            CacheKeyPart::Host => append_cache_key_component(
                &mut key,
                "host",
                &request.host.and_then(normalize_host).unwrap_or_default(),
            ),
            CacheKeyPart::Path => append_cache_key_component(&mut key, "path", request.path),
            CacheKeyPart::Query if config.include_query => {
                append_cache_key_component(&mut key, "query", request.query.unwrap_or_default());
            }
            CacheKeyPart::Query => {}
        }
    }
    append_cache_key_component(&mut key, "file", request.file_identity);
    Some(CacheKey::new(key))
}

fn method_allowed(config: &CacheConfig, method: &str) -> bool {
    config.methods.iter().any(|candidate| candidate == method)
}

fn image_extension(path: &str) -> Option<&str> {
    let file_name = path.rsplit('/').next()?;
    if file_name.is_empty() || file_name == "." || file_name == ".." {
        return None;
    }

    let (stem, extension) = file_name.rsplit_once('.')?;
    if stem.is_empty() || extension.is_empty() {
        return None;
    }

    Some(extension)
}

pub fn parse_bounded_single_range(range: &str) -> Option<CacheRangeRequest> {
    let range = range.trim();
    let range = range.strip_prefix("bytes=")?;
    if range.contains(',') {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    if start.is_empty() || end.is_empty() {
        return None;
    }
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    Some(CacheRangeRequest { start, end })
}

pub fn parse_cache_content_range(value: &str) -> Option<CacheContentRange> {
    let value = value.trim();
    let rest = value.strip_prefix("bytes ")?;
    if rest.starts_with("*/") {
        return None;
    }
    let (range, complete_len) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    let total = if complete_len == "*" {
        None
    } else {
        Some(complete_len.parse::<u64>().ok()?)
    };
    if total.is_some_and(|total| total <= end) {
        return None;
    }
    Some(CacheContentRange { start, end, total })
}

pub fn parse_cache_client_ranges(value: &str) -> Option<Vec<CacheClientRange>> {
    let value = value.trim();
    let value = value.strip_prefix("bytes=")?;
    let mut ranges = Vec::new();
    for part in value.split(',') {
        if ranges.len() >= MAX_CACHE_CLIENT_RANGES {
            return None;
        }
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (start, end) = part.split_once('-')?;
        if start.is_empty() {
            let len = end.parse::<u64>().ok()?;
            if len == 0 {
                return None;
            }
            ranges.push(CacheClientRange::Suffix { len });
        } else if end.is_empty() {
            ranges.push(CacheClientRange::OpenEnded {
                start: start.parse::<u64>().ok()?,
            });
        } else {
            let start = start.parse::<u64>().ok()?;
            let end = end.parse::<u64>().ok()?;
            if end < start {
                return None;
            }
            ranges.push(CacheClientRange::Bounded { start, end });
        }
    }
    (!ranges.is_empty()).then_some(ranges)
}

pub fn response_content_range_matches(
    headers: &http::HeaderMap,
    expected: CacheRangeRequest,
) -> bool {
    let mut values = headers.get_all("content-range").iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().ok().is_some_and(|value| {
        parse_cache_content_range(value)
            .is_some_and(|range| range.start == expected.start && range.end == expected.end)
    })
}

pub fn response_content_length_matches_range(
    headers: &http::HeaderMap,
    expected: CacheRangeRequest,
) -> bool {
    let mut values = headers.get_all("content-length").iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        == Some(expected.len())
}

pub fn resolve_client_slice_ranges(
    ranges: &[CacheClientRange],
    total: u64,
) -> Option<Vec<CacheSliceBounds>> {
    if total == 0 {
        return Some(Vec::new());
    }
    let last = total.saturating_sub(1);
    let mut resolved = Vec::new();
    for range in ranges {
        match *range {
            CacheClientRange::Bounded { start, end } => {
                if start > last {
                    continue;
                }
                resolved.push(CacheSliceBounds {
                    start,
                    end: end.min(last),
                });
            }
            CacheClientRange::OpenEnded { start } => {
                if start > last {
                    continue;
                }
                resolved.push(CacheSliceBounds { start, end: last });
            }
            CacheClientRange::Suffix { len } => {
                if len == 0 {
                    continue;
                }
                resolved.push(CacheSliceBounds {
                    start: total.saturating_sub(len),
                    end: last,
                });
            }
        }
    }
    Some(resolved)
}

pub fn required_slice_bounds(
    ranges: &[CacheSliceBounds],
    slice_size: u64,
    total: u64,
) -> Vec<CacheSliceBounds> {
    if slice_size == 0 || total == 0 {
        return Vec::new();
    }
    let mut slices = Vec::new();
    let last = total.saturating_sub(1);
    for range in ranges {
        let mut start = (range.start / slice_size).saturating_mul(slice_size);
        while start <= range.end && start <= last {
            let end = start.saturating_add(slice_size.saturating_sub(1)).min(last);
            let slice = CacheSliceBounds { start, end };
            if !slices.contains(&slice) {
                slices.push(slice);
            }
            let Some(next) = start.checked_add(slice_size) else {
                break;
            };
            start = next;
        }
    }
    slices.sort_by_key(|slice| slice.start);
    slices
}

pub fn slice_request_within_policy(
    ranges: &[CacheSliceBounds],
    max_bytes: u64,
    max_slices: usize,
    slice_size: u64,
) -> bool {
    let requested_bytes = ranges
        .iter()
        .try_fold(0_u64, |sum, range| sum.checked_add(range.len()));
    let Some(requested_bytes) = requested_bytes else {
        return false;
    };
    if requested_bytes > max_bytes {
        return false;
    }
    if ranges.len() > 1 {
        let Some(multipart_bytes) = requested_bytes
            .checked_add(
                u64::try_from(ranges.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(MULTIPART_SLICE_OVERHEAD_BYTES_PER_RANGE),
            )
            .and_then(|bytes| bytes.checked_add(MULTIPART_SLICE_CLOSING_OVERHEAD_BYTES))
        else {
            return false;
        };
        if multipart_bytes > max_bytes {
            return false;
        }
    }
    let slices = required_slice_bounds(ranges, slice_size, u64::MAX);
    !slices.is_empty() && slices.len() <= max_slices
}
