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

#[cfg(feature = "cache")]
pub fn response_values_forbid_shared_cache<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
) -> Option<&'static str> {
    cache_control
        .into_iter()
        .find_map(response_cache_control_shared_rejection)
}

fn is_pragma_no_cache(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("no-cache")
}

fn cache_control_forces_refresh(value: &str) -> bool {
    value.split(',').any(|directive| {
        let directive = directive.trim();
        let (name, value) = directive
            .split_once('=')
            .map_or((directive, None), |(name, value)| {
                (name.trim(), Some(value.trim()))
            });

        name.eq_ignore_ascii_case("no-cache")
            || name.eq_ignore_ascii_case("no-store")
            || (name.eq_ignore_ascii_case("max-age") && value == Some("0"))
    })
}

#[cfg(feature = "cache")]
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

    #[cfg(feature = "cache")]
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
}
