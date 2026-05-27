#[cfg(feature = "cache")]
pub(crate) fn safe_forward_path_and_query(path_and_query: &str) -> bool {
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    safe_forward_path(path)
}

pub(crate) fn safe_forward_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.as_bytes().contains(&b'\\')
    {
        return false;
    }

    path.split('/').all(safe_forward_path_segment)
}

fn safe_forward_path_segment(segment: &str) -> bool {
    if segment == ".." {
        return false;
    }

    let mut current = segment.to_owned();
    for _ in 0..3 {
        let Some(decoded) = percent_decode_path_segment(&current) else {
            return false;
        };
        if unsafe_decoded_forward_path_segment(&decoded) {
            return false;
        }
        match std::str::from_utf8(&decoded) {
            Ok(decoded_text) if decoded_text.contains('%') => {
                current.clear();
                current.push_str(decoded_text);
            }
            _ => return true,
        }
    }

    if current.contains('%') {
        return false;
    }

    true
}

fn unsafe_decoded_forward_path_segment(segment: &[u8]) -> bool {
    segment == b".."
        || segment
            .iter()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
}

fn percent_decode_path_segment(segment: &str) -> Option<Vec<u8>> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push((hex_value(high)? << 4) | hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{safe_forward_path, safe_forward_path_and_query};

    #[test]
    fn rejects_multi_encoded_parent_segments() {
        assert!(!safe_forward_path("/%2e%2e/secret"));
        assert!(!safe_forward_path("/%252e%252e/secret"));
        assert!(!safe_forward_path("/%25252e%25252e/secret"));
    }

    #[test]
    fn rejects_remaining_percent_after_decode_budget() {
        assert!(!safe_forward_path("/%2525252e%2525252e/secret"));
    }

    #[test]
    fn accepts_safe_percent_encoded_path_and_query() {
        assert!(safe_forward_path_and_query("/assets/%66ile.css?v=%252e"));
    }
}
