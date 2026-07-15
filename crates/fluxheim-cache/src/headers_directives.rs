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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResponseCacheControlPolicy {
    pub(crate) freshness_secs: Option<u32>,
    pub(crate) stale_reuse_forbidden: bool,
    pub(crate) shared_rejection: Option<&'static str>,
}

pub(crate) const MAX_RESPONSE_CACHE_CONTROL_BYTES: usize = 16 * 1024;
pub(crate) const MAX_RESPONSE_CACHE_CONTROL_DIRECTIVES: usize = 128;

pub(crate) fn parse_response_cache_control_values<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<ResponseCacheControlPolicy, ()> {
    let mut policy = ResponseCacheControlPolicy::default();
    let mut max_age = None;
    let mut shared_max_age = None;
    let mut seen_no_store = false;
    let mut seen_private = false;
    let mut seen_no_cache = false;
    let mut seen_must_revalidate = false;
    let mut seen_proxy_revalidate = false;
    let mut total_bytes = 0_usize;
    let mut directive_count = 0_usize;

    for value in values {
        total_bytes = total_bytes.checked_add(value.len()).ok_or(())?;
        if total_bytes > MAX_RESPONSE_CACHE_CONTROL_BYTES {
            return Err(());
        }

        visit_cache_control_directives(value, &mut |directive| {
            directive_count = directive_count.checked_add(1).ok_or(())?;
            if directive_count > MAX_RESPONSE_CACHE_CONTROL_DIRECTIVES {
                return Err(());
            }
            let (name, value) = parse_cache_control_directive(directive)?;
            if name.eq_ignore_ascii_case("max-age") {
                if max_age.is_some() {
                    return Err(());
                }
                max_age = Some(parse_cache_control_delta_seconds(value)?);
            } else if name.eq_ignore_ascii_case("s-maxage") {
                if shared_max_age.is_some() {
                    return Err(());
                }
                shared_max_age = Some(parse_cache_control_delta_seconds(value)?);
                policy.stale_reuse_forbidden = true;
            } else if name.eq_ignore_ascii_case("no-store") {
                reject_duplicate_flag(value, &mut seen_no_store)?;
                policy
                    .shared_rejection
                    .get_or_insert("cache-control-no-store");
            } else if name.eq_ignore_ascii_case("private") {
                reject_duplicate_directive(&mut seen_private)?;
                policy
                    .shared_rejection
                    .get_or_insert("cache-control-private");
            } else if name.eq_ignore_ascii_case("no-cache") {
                reject_duplicate_directive(&mut seen_no_cache)?;
                policy
                    .shared_rejection
                    .get_or_insert("cache-control-no-cache");
            } else if name.eq_ignore_ascii_case("must-revalidate") {
                reject_duplicate_flag(value, &mut seen_must_revalidate)?;
                policy.stale_reuse_forbidden = true;
            } else if name.eq_ignore_ascii_case("proxy-revalidate") {
                reject_duplicate_flag(value, &mut seen_proxy_revalidate)?;
                policy.stale_reuse_forbidden = true;
            }
            Ok(())
        })?;
    }

    policy.freshness_secs = shared_max_age.or(max_age);
    if policy.freshness_secs == Some(0) {
        policy
            .shared_rejection
            .get_or_insert("cache-control-zero-freshness");
    }
    Ok(policy)
}

fn reject_duplicate_directive(seen: &mut bool) -> Result<(), ()> {
    if *seen {
        return Err(());
    }
    *seen = true;
    Ok(())
}

fn reject_duplicate_flag(value: Option<&str>, seen: &mut bool) -> Result<(), ()> {
    if value.is_some() || *seen {
        return Err(());
    }
    *seen = true;
    Ok(())
}

fn parse_cache_control_delta_seconds(value: Option<&str>) -> Result<u32, ()> {
    let value = value.ok_or(())?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    value.parse::<u32>().map_err(|_| ())
}

fn visit_cache_control_directives(
    value: &str,
    visitor: &mut impl FnMut(&str) -> Result<(), ()>,
) -> Result<(), ()> {
    let mut start = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == b',' && !quoted {
            let directive = value.get(start..index).ok_or(())?.trim();
            if directive.is_empty() {
                return Err(());
            }
            visitor(directive)?;
            start = index.saturating_add(1);
        }
    }
    if quoted || escaped {
        return Err(());
    }
    let directive = value.get(start..).ok_or(())?.trim();
    if directive.is_empty() {
        return Err(());
    }
    visitor(directive)
}

fn parse_cache_control_directive(directive: &str) -> Result<(&str, Option<&str>), ()> {
    let (name, value) = directive
        .split_once('=')
        .map_or((directive.trim(), None), |(name, value)| {
            (name.trim(), Some(value.trim()))
        });
    if !http_token_valid(name) {
        return Err(());
    }
    if let Some(value) = value
        && (value.is_empty() || !cache_control_value_valid(value))
    {
        return Err(());
    }
    Ok((name, value))
}

fn cache_control_value_valid(value: &str) -> bool {
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        let mut escaped = false;
        for byte in inner.bytes() {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' || byte == b'\r' || byte == b'\n' {
                return false;
            }
        }
        !escaped
    } else {
        http_token_valid(value)
    }
}

fn http_token_valid(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}
