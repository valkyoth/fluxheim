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

impl CacheKey {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
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

#[cfg(test)]
mod tests {
    use super::{
        CacheClientRange, CacheContentRange, CacheSliceBounds, parse_bounded_single_range,
        parse_cache_client_ranges, parse_cache_content_range, required_slice_bounds,
        resolve_client_slice_ranges,
    };

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
}
