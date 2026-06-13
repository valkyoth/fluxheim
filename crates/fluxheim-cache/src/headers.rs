pub fn request_forces_cache_refresh(cache_control: Option<&str>, pragma: Option<&str>) -> bool {
    pragma.is_some_and(is_pragma_no_cache)
        || cache_control.is_some_and(cache_control_forces_refresh)
}

pub fn request_values_force_cache_refresh<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
    pragma: impl IntoIterator<Item = &'a str>,
) -> bool {
    pragma.into_iter().any(is_pragma_no_cache)
        || cache_control.into_iter().any(cache_control_forces_refresh)
}

pub fn request_values_force_cache_revalidation<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
    pragma: impl IntoIterator<Item = &'a str>,
) -> bool {
    pragma.into_iter().any(is_pragma_no_cache)
        || cache_control
            .into_iter()
            .any(cache_control_forces_revalidation)
}

pub fn request_values_forbid_cache_store<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
) -> bool {
    cache_control.into_iter().any(cache_control_forbids_store)
}

pub fn response_values_forbid_shared_cache<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
) -> Option<&'static str> {
    cache_control
        .into_iter()
        .find_map(response_cache_control_shared_rejection)
}

pub fn remaining_fresh_ttl_secs(ttl_secs: u32, age_secs: u64) -> Option<u32> {
    let remaining = u64::from(ttl_secs).checked_sub(age_secs)?;
    u32::try_from(remaining).ok().filter(|ttl| *ttl > 0)
}

pub fn cache_control_freshness_value(
    ttl_secs: u32,
    stale_while_revalidate_secs: Option<u32>,
    stale_if_error_secs: Option<u32>,
) -> String {
    let mut value = format!("max-age={ttl_secs}");
    if let Some(stale_while_revalidate_secs) = stale_while_revalidate_secs {
        value.push_str(", stale-while-revalidate=");
        value.push_str(&stale_while_revalidate_secs.to_string());
    }
    if let Some(stale_if_error_secs) = stale_if_error_secs {
        value.push_str(", stale-if-error=");
        value.push_str(&stale_if_error_secs.to_string());
    }
    value
}

pub const MAX_VARY_FIELDS: usize = 16;
const MAX_VARY_HEADER_BYTES: usize = 2048;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VaryCachePolicy {
    None,
    Fields(Vec<String>),
    Uncacheable(&'static str),
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

fn is_pragma_no_cache(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("no-cache")
}

fn cache_control_forces_refresh(value: &str) -> bool {
    value.split(',').any(|directive| {
        let (name, value) = cache_control_directive_parts(directive);
        name.eq_ignore_ascii_case("no-cache")
            || name.eq_ignore_ascii_case("no-store")
            || (name.eq_ignore_ascii_case("max-age") && value == Some("0"))
    })
}

fn cache_control_forces_revalidation(value: &str) -> bool {
    value.split(',').any(|directive| {
        let (name, value) = cache_control_directive_parts(directive);
        name.eq_ignore_ascii_case("no-cache")
            || (name.eq_ignore_ascii_case("max-age") && value == Some("0"))
    })
}

fn cache_control_forbids_store(value: &str) -> bool {
    value.split(',').any(|directive| {
        let (name, _) = cache_control_directive_parts(directive);
        name.eq_ignore_ascii_case("no-store")
    })
}

fn cache_control_directive_parts(directive: &str) -> (&str, Option<&str>) {
    let directive = directive.trim();
    directive
        .split_once('=')
        .map_or((directive, None), |(name, value)| {
            (name.trim(), Some(value.trim()))
        })
}

fn response_cache_control_shared_rejection(value: &str) -> Option<&'static str> {
    value.split(',').find_map(|directive| {
        let directive = directive.trim();
        let (name, value) = directive
            .split_once('=')
            .map_or((directive, None), |(name, value)| {
                (name.trim(), Some(value.trim().trim_matches('"')))
            });

        if name.eq_ignore_ascii_case("no-store") {
            Some("cache-control-no-store")
        } else if name.eq_ignore_ascii_case("private") {
            Some("cache-control-private")
        } else if name.eq_ignore_ascii_case("no-cache") {
            Some("cache-control-no-cache")
        } else if (name.eq_ignore_ascii_case("max-age") || name.eq_ignore_ascii_case("s-maxage"))
            && value == Some("0")
        {
            Some("cache-control-zero-freshness")
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::request_forces_cache_refresh;

    #[test]
    fn detects_request_cache_refresh_directives() {
        for value in [
            "no-cache",
            "No-Cache",
            "no-store",
            "max-age=0",
            "max-age = 0",
            "public, max-age=0",
            "public, no-cache",
        ] {
            assert!(
                request_forces_cache_refresh(Some(value), None),
                "cache-control: {value}"
            );
        }

        assert!(request_forces_cache_refresh(None, Some("no-cache")));
        assert!(request_forces_cache_refresh(
            Some("public, max-age=60"),
            Some("no-cache")
        ));
    }

    #[test]
    fn ignores_normal_request_cache_directives() {
        for value in [
            "public",
            "private",
            "max-age=60",
            "min-fresh=0",
            "only-if-cached",
        ] {
            assert!(
                !request_forces_cache_refresh(Some(value), None),
                "cache-control: {value}"
            );
        }

        assert!(!request_forces_cache_refresh(None, Some("max-age=0")));
        assert!(!request_forces_cache_refresh(None, None));
    }

    #[test]
    fn detects_refresh_across_repeated_header_values() {
        assert!(super::request_values_force_cache_refresh(
            ["public, max-age=60", "no-cache"],
            []
        ));
        assert!(super::request_values_force_cache_refresh(
            ["public, max-age=60"],
            ["ignored", "no-cache"]
        ));
        assert!(!super::request_values_force_cache_refresh(
            ["public, max-age=60"],
            ["ignored"]
        ));
    }

    #[test]
    fn separates_request_revalidation_from_no_store() {
        for value in ["no-cache", "max-age=0", "max-age = 0", "public, no-cache"] {
            assert!(
                super::request_values_force_cache_revalidation([value], []),
                "cache-control: {value}"
            );
            assert!(
                !super::request_values_forbid_cache_store([value]),
                "cache-control: {value}"
            );
        }

        assert!(super::request_values_force_cache_revalidation(
            ["public, max-age=60"],
            ["no-cache"]
        ));
        assert!(super::request_values_forbid_cache_store(["no-store"]));
        assert!(super::request_values_forbid_cache_store([
            "public, no-store"
        ]));
        assert!(!super::request_values_force_cache_revalidation(
            ["no-store"],
            []
        ));
    }

    #[test]
    fn detects_response_shared_cache_rejections() {
        for (value, reason) in [
            ("no-store", "cache-control-no-store"),
            ("private", "cache-control-private"),
            ("public, no-cache", "cache-control-no-cache"),
            ("max-age=0", "cache-control-zero-freshness"),
            ("s-maxage=\"0\"", "cache-control-zero-freshness"),
        ] {
            assert_eq!(
                super::response_values_forbid_shared_cache([value]),
                Some(reason),
                "cache-control: {value}"
            );
        }

        assert_eq!(
            super::response_values_forbid_shared_cache(["public, max-age=60", "immutable"]),
            None
        );
        assert_eq!(
            super::response_values_forbid_shared_cache(["public, max-age=60", "private"]),
            Some("cache-control-private")
        );
    }

    #[test]
    fn computes_remaining_fresh_ttl() {
        assert_eq!(super::remaining_fresh_ttl_secs(120, 0), Some(120));
        assert_eq!(super::remaining_fresh_ttl_secs(120, 119), Some(1));
        assert_eq!(super::remaining_fresh_ttl_secs(120, 120), None);
        assert_eq!(super::remaining_fresh_ttl_secs(120, 121), None);
    }

    #[test]
    fn builds_cache_control_freshness_value() {
        assert_eq!(
            super::cache_control_freshness_value(60, Some(5), Some(10)),
            "max-age=60, stale-while-revalidate=5, stale-if-error=10"
        );
        assert_eq!(
            super::cache_control_freshness_value(60, None, None),
            "max-age=60"
        );
    }

    #[test]
    fn vary_cache_policy_rejects_unsafe_vary_headers() {
        let response = http::Response::builder().body(()).unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::None
        );

        let response = http::Response::builder()
            .header("vary", "*")
            .body(())
            .unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Uncacheable("vary-star")
        );

        let response = http::Response::builder()
            .header("vary", "accept-encoding,,user-agent")
            .body(())
            .unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Uncacheable("vary-invalid")
        );

        let mut vary = String::new();
        for index in 0..super::MAX_VARY_FIELDS {
            vary.push_str(&format!("x-test-{index},"));
        }
        vary.push_str("x-overflow");
        let response = http::Response::builder()
            .header("vary", vary)
            .body(())
            .unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Uncacheable("vary-too-many-fields")
        );

        let response = http::Response::builder()
            .header("vary", "authorization")
            .body(())
            .unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Uncacheable("vary-sensitive-field")
        );
    }

    #[test]
    fn vary_cache_policy_normalizes_repeated_vary_fields() {
        let response = http::Response::builder()
            .header("vary", "Accept-Encoding, User-Agent")
            .header("vary", "accept-encoding")
            .body(())
            .unwrap();

        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Fields(vec![
                "accept-encoding".to_owned(),
                "user-agent".to_owned(),
            ])
        );
    }

    #[test]
    fn cache_vary_policy_merges_configured_request_headers() {
        let mut cache = fluxheim_config::CacheConfig {
            vary_request_headers: vec!["Accept-Encoding".to_owned(), "X-Device".to_owned()],
            ..fluxheim_config::CacheConfig::default()
        };
        let response = http::Response::builder()
            .header("vary", "User-Agent")
            .body(())
            .unwrap();

        assert_eq!(
            super::cache_vary_policy(response.headers(), &cache),
            super::VaryCachePolicy::Fields(vec![
                "accept-encoding".to_owned(),
                "user-agent".to_owned(),
                "x-device".to_owned(),
            ])
        );

        cache.vary_request_headers = (0..super::MAX_VARY_FIELDS)
            .map(|index| format!("x-config-{index}"))
            .collect();
        assert_eq!(
            super::cache_vary_policy(response.headers(), &cache),
            super::VaryCachePolicy::Uncacheable("vary-too-many-fields")
        );
    }
}
