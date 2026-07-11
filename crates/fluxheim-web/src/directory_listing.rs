use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
        match entry
            .modified
            .and_then(|modified| format_directory_listing_time(modified, listing.local_time))
        {
            Some(timestamp) => html.push_str(&html_escape(&timestamp)),
            None => html.push('-'),
        }
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></body></html>");
    html
}

pub fn directory_listing_path(relative: &Path) -> String {
    let mut path = String::from("/");
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            continue;
        };
        if path.len() > 1 {
            path.push('/');
        }
        path.push_str(&segment.to_string_lossy());
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

fn format_directory_listing_time(modified: SystemTime, local_time: bool) -> Option<String> {
    const MAX_HTTP_DATE_SECONDS: u64 = 253_402_300_799;

    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    if duration.as_secs() > MAX_HTTP_DATE_SECONDS {
        return None;
    }
    if local_time {
        let seconds = i64::try_from(duration.as_secs()).ok()?;
        let utc =
            chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, duration.subsec_nanos())?;
        return Some(
            utc.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %z")
                .to_string(),
        );
    }

    Some(httpdate::fmt_http_date(modified))
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
