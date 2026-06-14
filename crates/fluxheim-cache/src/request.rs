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
    if let Some(total) = rest.strip_prefix("*/") {
        return Some(CacheContentRange {
            start: 0,
            end: 0,
            total: total.parse::<u64>().ok(),
        });
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
    headers
        .get_all("content-range")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            parse_cache_content_range(value)
                .is_some_and(|range| range.start == expected.start && range.end == expected.end)
        })
}

pub fn response_content_length_matches_range(
    headers: &http::HeaderMap,
    expected: CacheRangeRequest,
) -> bool {
    headers
        .get_all("content-length")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.trim().parse::<u64>().ok() == Some(expected.len()))
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

#[cfg(test)]
mod tests {
    use super::{
        CacheClientRange, CacheContentRange, CacheSliceBounds, FluxCacheKeyParts,
        append_cache_key_component, cache_method_temporarily_bypassed, parse_bounded_single_range,
        parse_cache_client_ranges, parse_cache_content_range, required_slice_bounds,
        resolve_client_slice_ranges, response_content_length_matches_range,
        response_content_range_matches, slice_request_within_policy,
    };

    #[test]
    fn appends_length_delimited_cache_key_component() {
        let mut key = String::from("prefix;");
        append_cache_key_component(&mut key, "range", "bytes=10-19");
        assert_eq!(key, "prefix;range:11:bytes=10-19;");
        assert_eq!(
            super::cache_key_with_component("prefix;", "slice", "bytes=10-19"),
            "prefix;slice:11:bytes=10-19;"
        );
    }

    #[test]
    fn detects_temporarily_bypassed_cache_methods() {
        assert!(cache_method_temporarily_bypassed("HEAD"));
        assert!(!cache_method_temporarily_bypassed("GET"));
        assert!(!cache_method_temporarily_bypassed("head"));
    }

    #[test]
    fn parses_bounded_single_range() {
        assert_eq!(
            parse_bounded_single_range("bytes=10-19"),
            Some(super::CacheRangeRequest { start: 10, end: 19 })
        );
        assert_eq!(parse_bounded_single_range("bytes=19-10"), None);
        assert_eq!(parse_bounded_single_range("bytes=10-"), None);
        assert_eq!(parse_bounded_single_range("bytes=10-19,20-29"), None);
    }

    #[test]
    fn parses_content_range() {
        assert_eq!(
            parse_cache_content_range("bytes 10-19/100"),
            Some(CacheContentRange {
                start: 10,
                end: 19,
                total: Some(100),
            })
        );
        assert_eq!(
            parse_cache_content_range("bytes 10-19/*"),
            Some(CacheContentRange {
                start: 10,
                end: 19,
                total: None,
            })
        );
        assert_eq!(
            parse_cache_content_range("bytes */100"),
            Some(CacheContentRange {
                start: 0,
                end: 0,
                total: Some(100),
            })
        );
        assert_eq!(parse_cache_content_range("bytes 19-10/100"), None);
        assert_eq!(parse_cache_content_range("items 10-19/100"), None);
    }

    #[test]
    fn validates_response_range_headers_against_request() {
        let response = http::Response::builder()
            .header("content-range", "bytes 10-19/100")
            .header("content-length", "10")
            .body(())
            .unwrap();
        let expected = super::CacheRangeRequest { start: 10, end: 19 };

        assert!(response_content_range_matches(response.headers(), expected));
        assert!(response_content_length_matches_range(
            response.headers(),
            expected
        ));

        let wrong = super::CacheRangeRequest { start: 20, end: 29 };
        assert!(!response_content_range_matches(response.headers(), wrong));
        assert!(response_content_length_matches_range(
            response.headers(),
            wrong
        ));
    }

    #[test]
    fn parses_client_ranges() {
        assert_eq!(
            parse_cache_client_ranges("bytes=0-9, 20-, -5"),
            Some(vec![
                CacheClientRange::Bounded { start: 0, end: 9 },
                CacheClientRange::OpenEnded { start: 20 },
                CacheClientRange::Suffix { len: 5 },
            ])
        );
        assert_eq!(parse_cache_client_ranges("bytes=-0"), None);
        assert_eq!(parse_cache_client_ranges("items=0-1"), None);
    }

    #[test]
    fn resolves_client_ranges_against_total() {
        let ranges = parse_cache_client_ranges("bytes=0-99, 950-, -25").unwrap();

        assert_eq!(
            resolve_client_slice_ranges(&ranges, 1000).unwrap(),
            vec![
                CacheSliceBounds { start: 0, end: 99 },
                CacheSliceBounds {
                    start: 950,
                    end: 999
                },
                CacheSliceBounds {
                    start: 975,
                    end: 999
                },
            ]
        );
    }

    #[test]
    fn computes_required_slice_bounds() {
        let ranges = [CacheSliceBounds {
            start: 10,
            end: 130,
        }];

        assert_eq!(
            required_slice_bounds(&ranges, 64, 200),
            vec![
                CacheSliceBounds { start: 0, end: 63 },
                CacheSliceBounds {
                    start: 64,
                    end: 127
                },
                CacheSliceBounds {
                    start: 128,
                    end: 191
                },
            ]
        );
    }

    #[test]
    fn slice_policy_bounds_assembled_bytes_and_slice_count() {
        assert!(slice_request_within_policy(
            &[CacheSliceBounds { start: 0, end: 15 }],
            16,
            2,
            8
        ));
        assert!(!slice_request_within_policy(
            &[CacheSliceBounds { start: 0, end: 16 }],
            16,
            2,
            8
        ));
        assert!(!slice_request_within_policy(
            &[CacheSliceBounds { start: 0, end: 23 }],
            16,
            2,
            8
        ));
        assert!(!slice_request_within_policy(
            &[
                CacheSliceBounds { start: 0, end: 0 },
                CacheSliceBounds { start: 0, end: 0 },
            ],
            16,
            2,
            8
        ));
    }

    #[test]
    fn flux_cache_key_parts_preserve_identity_fields() {
        let key = FluxCacheKeyParts::new("primary", "combined", "tag");

        assert_eq!(key.primary(), "primary");
        assert_eq!(key.combined(), "combined");
        assert_eq!(key.user_tag(), "tag");
    }
}
