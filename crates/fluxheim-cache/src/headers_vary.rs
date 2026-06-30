pub const MAX_VARY_FIELDS: usize = 16;
const MAX_VARY_HEADER_BYTES: usize = 2048;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VaryCachePolicy {
    None,
    Fields(Vec<String>),
    Uncacheable(&'static str),
}

pub struct VaryRequestHashField<'a> {
    pub name: &'a str,
    pub values: Vec<&'a [u8]>,
}

pub fn vary_request_hash_material<'a>(
    fields: impl IntoIterator<Item = VaryRequestHashField<'a>>,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(b"fluxheim-vary-v2");

    for field in fields {
        append_vary_hash_component(&mut material, field.name.as_bytes());
        material.extend_from_slice(&(field.values.len() as u32).to_le_bytes());
        for value in field.values {
            append_vary_hash_component(&mut material, value);
        }
    }

    material
}

pub fn cache_vary_policy(
    headers: &http::HeaderMap,
    cache: &fluxheim_config::CacheConfig,
) -> VaryCachePolicy {
    let mut fields = match vary_cache_policy(headers) {
        VaryCachePolicy::None => Vec::new(),
        VaryCachePolicy::Fields(fields) => fields,
        VaryCachePolicy::Uncacheable(reason) => return VaryCachePolicy::Uncacheable(reason),
    };

    for configured in &cache.vary_request_headers {
        let field = configured.to_ascii_lowercase();
        if !fields.contains(&field) {
            fields.push(field);
        }
        if fields.len() > MAX_VARY_FIELDS {
            return VaryCachePolicy::Uncacheable("vary-too-many-fields");
        }
    }

    if fields.is_empty() {
        VaryCachePolicy::None
    } else {
        fields.sort();
        VaryCachePolicy::Fields(fields)
    }
}

pub fn vary_cache_policy(headers: &http::HeaderMap) -> VaryCachePolicy {
    let mut fields = Vec::new();
    let mut total_bytes = 0usize;

    for value in headers.get_all("vary").iter() {
        total_bytes = total_bytes.saturating_add(value.as_bytes().len());
        if total_bytes > MAX_VARY_HEADER_BYTES {
            return VaryCachePolicy::Uncacheable("vary-too-large");
        }

        let Ok(line) = value.to_str() else {
            return VaryCachePolicy::Uncacheable("vary-invalid");
        };

        for raw_field in line.split(',') {
            let field = raw_field.trim();
            if field.is_empty() {
                return VaryCachePolicy::Uncacheable("vary-invalid");
            }
            if field == "*" {
                return VaryCachePolicy::Uncacheable("vary-star");
            }
            if http::header::HeaderName::from_bytes(field.as_bytes()).is_err() {
                return VaryCachePolicy::Uncacheable("vary-invalid");
            }

            let field = field.to_ascii_lowercase();
            if is_sensitive_vary_field(&field) {
                return VaryCachePolicy::Uncacheable("vary-sensitive-field");
            }
            if !fields.contains(&field) {
                fields.push(field);
            }
            if fields.len() > MAX_VARY_FIELDS {
                return VaryCachePolicy::Uncacheable("vary-too-many-fields");
            }
        }
    }

    if fields.is_empty() {
        VaryCachePolicy::None
    } else {
        fields.sort();
        VaryCachePolicy::Fields(fields)
    }
}

fn is_sensitive_vary_field(field: &str) -> bool {
    matches!(field, "authorization" | "cookie" | "proxy-authorization")
}

fn append_vary_hash_component(material: &mut Vec<u8>, bytes: &[u8]) {
    material.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    material.extend_from_slice(bytes);
}
