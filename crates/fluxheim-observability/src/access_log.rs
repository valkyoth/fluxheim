use std::fmt::Write as _;

pub fn unix_time_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

pub fn access_log_status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

pub fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

pub fn access_log_request_id_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub fn generate_access_log_request_id() -> Option<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).ok()?;

    let mut id = String::with_capacity(35);
    id.push_str("fh-");
    for byte in random {
        let _ = write!(&mut id, "{byte:02x}");
    }
    Some(id)
}

pub fn count_access_log_response_body_bytes(bytes_seen: &mut u64, bytes: usize) {
    *bytes_seen = bytes_seen.saturating_add(bytes as u64);
}
