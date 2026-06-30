pub(crate) fn is_pragma_no_cache(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("no-cache")
}

pub(crate) fn cache_control_forces_refresh(value: &str) -> bool {
    value.split(',').any(|directive| {
        let (name, value) = cache_control_directive_parts(directive);
        name.eq_ignore_ascii_case("no-cache")
            || name.eq_ignore_ascii_case("no-store")
            || (name.eq_ignore_ascii_case("max-age") && value == Some("0"))
    })
}

pub(crate) fn cache_control_forces_revalidation(value: &str) -> bool {
    value.split(',').any(|directive| {
        let (name, value) = cache_control_directive_parts(directive);
        name.eq_ignore_ascii_case("no-cache")
            || (name.eq_ignore_ascii_case("max-age") && value == Some("0"))
    })
}

pub(crate) fn cache_control_forbids_store(value: &str) -> bool {
    value.split(',').any(|directive| {
        let (name, _) = cache_control_directive_parts(directive);
        name.eq_ignore_ascii_case("no-store")
    })
}

pub(crate) fn cache_control_directive_parts(directive: &str) -> (&str, Option<&str>) {
    let directive = directive.trim();
    directive
        .split_once('=')
        .map_or((directive, None), |(name, value)| {
            (name.trim(), Some(value.trim()))
        })
}

pub(crate) fn response_cache_control_shared_rejection(value: &str) -> Option<&'static str> {
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
