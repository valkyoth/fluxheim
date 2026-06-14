use std::io;

pub const MAX_CACHE_TAGS_PER_OBJECT: usize = 64;
pub const MAX_CACHE_TAG_LEN: usize = 128;
pub const MAX_CACHE_TAG_BYTES_PER_OBJECT: usize = 4096;

pub fn default_cache_tag_headers_for_storage() -> Vec<String> {
    ["surrogate-key", "cache-tag", "x-cache-tags"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

pub fn collect_cache_tags(value: &str, tags: &mut Vec<String>, total_bytes: &mut usize) {
    for candidate in value.split(|character: char| character == ',' || character.is_whitespace()) {
        if tags.len() >= MAX_CACHE_TAGS_PER_OBJECT || *total_bytes >= MAX_CACHE_TAG_BYTES_PER_OBJECT
        {
            return;
        }
        let candidate = candidate.trim();
        if !is_valid_cache_tag(candidate) || tags.iter().any(|tag| tag == candidate) {
            continue;
        }
        let next_bytes = total_bytes.saturating_add(candidate.len());
        if next_bytes > MAX_CACHE_TAG_BYTES_PER_OBJECT {
            return;
        }
        tags.push(candidate.to_owned());
        *total_bytes = next_bytes;
    }
}

pub fn is_valid_cache_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= MAX_CACHE_TAG_LEN
        && tag.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'=')
        })
}

pub fn encode_cache_tags(tags: &[String]) -> String {
    tags.join("\n")
}

pub fn encoded_cache_tags_len(tags: &[String]) -> usize {
    encode_cache_tags(tags).len()
}

pub fn decode_cache_tags(bytes: &[u8]) -> io::Result<Vec<String>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let tags = String::from_utf8(bytes.to_vec()).map_err(|error| {
        io::Error::new(io::ErrorKind::InvalidData, format!("cache tags: {error}"))
    })?;
    let mut decoded = Vec::new();
    let mut total_bytes = 0_usize;
    collect_cache_tags(&tags, &mut decoded, &mut total_bytes);
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{
        collect_cache_tags, decode_cache_tags, default_cache_tag_headers_for_storage,
        encode_cache_tags, encoded_cache_tags_len, is_valid_cache_tag,
    };

    #[test]
    fn default_tag_headers_are_stable() {
        assert_eq!(
            default_cache_tag_headers_for_storage(),
            ["surrogate-key", "cache-tag", "x-cache-tags"]
        );
    }

    #[test]
    fn tag_collection_deduplicates_and_filters_invalid_values() {
        let mut tags = Vec::new();
        let mut total_bytes = 0;

        collect_cache_tags(
            "article:1 collection/news article:1,tenant/main bad@tag asset/logo",
            &mut tags,
            &mut total_bytes,
        );

        assert_eq!(
            tags,
            ["article:1", "collection/news", "tenant/main", "asset/logo"]
        );
        assert_eq!(total_bytes, tags.iter().map(String::len).sum::<usize>());
    }

    #[test]
    fn tag_encoding_round_trips_through_normalization() {
        let tags = vec!["one".to_owned(), "two/three".to_owned()];
        let encoded = encode_cache_tags(&tags);

        assert_eq!(encoded_cache_tags_len(&tags), encoded.len());
        assert_eq!(decode_cache_tags(encoded.as_bytes()).unwrap(), tags);
    }

    #[test]
    fn tag_grammar_is_bounded() {
        assert!(is_valid_cache_tag("tenant/main=blue"));
        assert!(!is_valid_cache_tag(""));
        assert!(!is_valid_cache_tag("bad@tag"));
        assert!(!is_valid_cache_tag(&"x".repeat(129)));
    }
}
