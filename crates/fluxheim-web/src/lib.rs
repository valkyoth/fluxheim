#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::time::SystemTime;

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DirectoryListing {
    pub path: String,
    pub entries: Vec<DirectoryEntry>,
    pub local_time: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ByteRangeParse {
    Single { start: u64, len: u64 },
    Unsatisfiable,
    Ignore,
}

pub fn parse_single_byte_range(range: &str, file_len: u64) -> ByteRangeParse {
    let range = range.trim();
    let Some(range) = range.strip_prefix("bytes=") else {
        return ByteRangeParse::Unsatisfiable;
    };
    if range.contains(',') {
        return ByteRangeParse::Ignore;
    }
    if file_len == 0 {
        return ByteRangeParse::Unsatisfiable;
    }

    let Some((start, end)) = range.split_once('-') else {
        return ByteRangeParse::Unsatisfiable;
    };
    if start.is_empty() {
        let Ok(suffix_len) = end.parse::<u64>() else {
            return ByteRangeParse::Unsatisfiable;
        };
        if suffix_len == 0 {
            return ByteRangeParse::Unsatisfiable;
        }
        let len = suffix_len.min(file_len);
        return ByteRangeParse::Single {
            start: file_len - len,
            len,
        };
    }

    let Ok(start) = start.parse::<u64>() else {
        return ByteRangeParse::Unsatisfiable;
    };
    if start >= file_len {
        return ByteRangeParse::Unsatisfiable;
    }

    let end = if end.is_empty() {
        file_len - 1
    } else {
        match end.parse::<u64>() {
            Ok(end) => end.min(file_len - 1),
            Err(_) => return ByteRangeParse::Unsatisfiable,
        }
    };

    if end < start {
        return ByteRangeParse::Unsatisfiable;
    }

    ByteRangeParse::Single {
        start,
        len: end - start + 1,
    }
}

pub fn render_directory_listing(listing: &DirectoryListing) -> String {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>Index of ");
    html.push_str(&html_escape(&listing.path));
    html.push_str("</title></head><body><h1>Index of ");
    html.push_str(&html_escape(&listing.path));
    html.push_str(
        "</h1><table><thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead><tbody>",
    );
    for entry in &listing.entries {
        let display_name = if entry.is_dir {
            format!("{}/", entry.name)
        } else {
            entry.name.clone()
        };
        let href = format!(
            "{}{}{}",
            listing.path,
            utf8_percent_encode(&entry.name, NON_ALPHANUMERIC),
            if entry.is_dir { "/" } else { "" }
        );
        html.push_str("<tr><td><a href=\"");
        html.push_str(&html_escape(&href));
        html.push_str("\">");
        html.push_str(&html_escape(&display_name));
        html.push_str("</a></td><td>");
        html.push_str(
            &entry
                .size
                .map(|size| size.to_string())
                .unwrap_or_else(|| "-".to_owned()),
        );
        html.push_str("</td><td>");
        if let Some(modified) = entry.modified {
            html.push_str(&html_escape(&format_directory_listing_time(
                modified,
                listing.local_time,
            )));
        } else {
            html.push('-');
        }
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></body></html>");
    html
}

fn format_directory_listing_time(modified: SystemTime, local_time: bool) -> String {
    if local_time {
        let local: chrono::DateTime<chrono::Local> = modified.into();
        return local.format("%Y-%m-%d %H:%M:%S %z").to_string();
    }

    httpdate::fmt_http_date(modified)
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::{
        ByteRangeParse, DirectoryEntry, DirectoryListing, parse_single_byte_range,
        render_directory_listing,
    };

    #[test]
    fn renders_escaped_directory_listing() {
        let listing = DirectoryListing {
            path: "/repo/<root>/".to_owned(),
            entries: vec![DirectoryEntry {
                name: "a&b.txt".to_owned(),
                is_dir: false,
                size: Some(1),
                modified: None,
            }],
            local_time: false,
        };

        let html = render_directory_listing(&listing);

        assert!(html.contains("Index of /repo/&lt;root&gt;/"));
        assert!(html.contains("a&amp;b.txt"));
    }

    #[test]
    fn directory_listing_local_time_uses_local_timestamp_shape() {
        let listing = DirectoryListing {
            path: "/".to_owned(),
            entries: vec![DirectoryEntry {
                name: "asset.txt".to_owned(),
                is_dir: false,
                size: Some(1),
                modified: Some(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)),
            }],
            local_time: true,
        };

        let html = render_directory_listing(&listing);

        assert!(
            html.contains("2023-11-14") || html.contains("2023-11-15"),
            "{html}"
        );
        assert!(!html.contains("GMT"));
    }

    #[test]
    fn parses_single_byte_ranges() {
        assert_eq!(
            parse_single_byte_range("bytes=10-19", 100),
            ByteRangeParse::Single { start: 10, len: 10 }
        );
        assert_eq!(
            parse_single_byte_range("bytes=90-", 100),
            ByteRangeParse::Single { start: 90, len: 10 }
        );
        assert_eq!(
            parse_single_byte_range("bytes=-5", 100),
            ByteRangeParse::Single { start: 95, len: 5 }
        );
        assert_eq!(
            parse_single_byte_range("bytes=0-999", 10),
            ByteRangeParse::Single { start: 0, len: 10 }
        );
    }

    #[test]
    fn rejects_unsatisfiable_or_multi_ranges() {
        assert_eq!(
            parse_single_byte_range("bytes=100-101", 100),
            ByteRangeParse::Unsatisfiable
        );
        assert_eq!(
            parse_single_byte_range("bytes=0-1,2-3", 100),
            ByteRangeParse::Ignore
        );
        assert_eq!(
            parse_single_byte_range("items=0-1", 100),
            ByteRangeParse::Unsatisfiable
        );
    }
}
