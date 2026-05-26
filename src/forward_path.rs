pub(crate) fn safe_forward_path_and_query(path_and_query: &str) -> bool {
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    safe_forward_path(path)
}

fn safe_forward_path(path: &str) -> bool {
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

    let Some(decoded_once) = percent_decode_path_segment(segment) else {
        return false;
    };
    if unsafe_decoded_forward_path_segment(&decoded_once) {
        return false;
    }
    if let Ok(decoded_once_text) = std::str::from_utf8(&decoded_once)
        && decoded_once_text.contains('%')
    {
        let Some(decoded_twice) = percent_decode_path_segment(decoded_once_text) else {
            return false;
        };
        if unsafe_decoded_forward_path_segment(&decoded_twice) {
            return false;
        }
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
