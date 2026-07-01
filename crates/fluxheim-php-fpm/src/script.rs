use std::path::Path;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PhpScriptName {
    pub script_name: String,
    pub path_info: String,
    pub explicit_php: bool,
}

pub fn php_fpm_script_filename(root: &Path, fpm_root: &Path, local_path: &Path) -> Option<String> {
    let relative = local_path.strip_prefix(root).ok()?;
    fpm_root.join(relative).to_str().map(str::to_owned)
}

pub fn php_fpm_path_translated(fpm_root: &Path, path_info: &str) -> Option<String> {
    let mut translated = fpm_root.to_path_buf();
    for segment in path_info.trim_start_matches('/').split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.starts_with('.')
            || segment.contains('\\')
            || segment.chars().any(char::is_control)
        {
            return None;
        }
        translated.push(segment);
    }
    translated.to_str().map(str::to_owned)
}

pub fn php_script_name_for_request(
    request_path: &str,
    index: &str,
    path_info: fluxheim_config::PhpPathInfoMode,
    allowed_extensions: &[String],
) -> Option<PhpScriptName> {
    let decoded = percent_encoding::percent_decode_str(request_path)
        .decode_utf8()
        .ok()?;
    if !decoded.starts_with('/') || decoded.chars().any(char::is_control) {
        return None;
    }

    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." || segment.contains('\\') || segment.starts_with('.') {
            return None;
        }
        segments.push(segment.to_owned());
    }

    if let Some((index, _)) = segments
        .iter()
        .enumerate()
        .find(|(_, segment)| php_segment_has_allowed_extension(segment, allowed_extensions))
    {
        let script_name = format!("/{}", segments[..=index].join("/"));
        let trailing = &segments[index + 1..];
        if !trailing.is_empty() && path_info == fluxheim_config::PhpPathInfoMode::Disabled {
            return None;
        }
        let path_info = if trailing.is_empty() {
            String::new()
        } else {
            format!("/{}", trailing.join("/"))
        };
        return Some(PhpScriptName {
            script_name,
            path_info,
            explicit_php: true,
        });
    }

    Some(PhpScriptName {
        script_name: format!("/{index}"),
        path_info: String::new(),
        explicit_php: false,
    })
}

pub fn php_script_name_denied(deny_path_prefixes: &[String], script_name: &str) -> bool {
    deny_path_prefixes.iter().any(|prefix| {
        script_name == prefix
            || script_name
                .strip_prefix(prefix)
                .is_some_and(|rest| prefix.ends_with('/') || rest.starts_with('/'))
    })
}

pub fn php_should_redirect_directory_index(
    request_path: &str,
    script_name: &str,
    index: &str,
) -> bool {
    if request_path.ends_with('/') || request_path.contains('\\') {
        return false;
    }
    let Some(parent) = script_name.strip_suffix(&format!("/{index}")) else {
        return false;
    };
    !parent.is_empty() && parent == request_path
}

pub fn php_static_file_script_name(
    root: &Path,
    local_path: &Path,
    allowed_extensions: &[String],
) -> Option<String> {
    let relative = local_path.strip_prefix(root).ok()?;
    let mut script_name = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            return None;
        };
        let segment = segment.to_str()?;
        if segment.is_empty() || segment == "." || segment == ".." || segment.starts_with('.') {
            return None;
        }
        script_name.push('/');
        script_name.push_str(segment);
    }
    if script_name.is_empty()
        || !php_segment_has_allowed_extension(&script_name, allowed_extensions)
    {
        return None;
    }
    Some(script_name)
}

pub fn php_segment_has_allowed_extension(segment: &str, allowed_extensions: &[String]) -> bool {
    segment.rsplit_once('.').is_some_and(|(_, extension)| {
        allowed_extensions
            .iter()
            .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    })
}
