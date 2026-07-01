const MAX_ROUTE_REGEX_CAPTURE_VALUES: usize = 16;
const MAX_ROUTE_REGEX_CAPTURE_VALUE_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NativeHttp1RouteMatcher {
    Exact(String),
    Prefix(String),
    Regex(NativeRegexRouteMatcher),
    Fallback,
}

#[derive(Clone)]
pub(crate) struct NativeRegexRouteMatcher {
    pattern: String,
    regex: regex::Regex,
}

impl std::fmt::Debug for NativeRegexRouteMatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRegexRouteMatcher")
            .field("pattern", &self.pattern)
            .finish_non_exhaustive()
    }
}

impl PartialEq for NativeRegexRouteMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for NativeRegexRouteMatcher {}

impl NativeRegexRouteMatcher {
    pub(crate) fn from_pattern(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            pattern: pattern.to_owned(),
            regex: regex::RegexBuilder::new(pattern)
                .size_limit(fluxheim_config::MAX_ROUTE_REGEX_PROGRAM_BYTES)
                .dfa_size_limit(fluxheim_config::MAX_ROUTE_REGEX_PROGRAM_BYTES)
                .build()?,
        })
    }

    fn is_match(&self, path: &str) -> bool {
        self.regex.is_match(path)
    }

    fn capture_value<'a>(&'a self, path: &'a str, variable: &str) -> Option<&'a str> {
        let key = variable.strip_prefix("route.regex.")?;
        let captures = self.regex.captures(path)?;
        let value = if key.bytes().all(|byte| byte.is_ascii_digit()) {
            let index = key.parse::<usize>().ok()?;
            if index >= MAX_ROUTE_REGEX_CAPTURE_VALUES {
                return None;
            }
            captures.get(index)?.as_str()
        } else {
            let index = self
                .regex
                .capture_names()
                .enumerate()
                .take(MAX_ROUTE_REGEX_CAPTURE_VALUES)
                .find_map(|(index, name)| (name == Some(key)).then_some(index))?;
            captures.get(index)?.as_str()
        };
        (value.len() <= MAX_ROUTE_REGEX_CAPTURE_VALUE_BYTES).then_some(value)
    }
}

impl NativeHttp1RouteMatcher {
    pub(crate) fn is_match(&self, path: &str) -> bool {
        match self {
            Self::Regex(regex) => regex.is_match(path),
            Self::Exact(exact) => path == exact,
            Self::Prefix(prefix) => fluxheim_protocol::route_prefix_matches_path(prefix, path),
            Self::Fallback => true,
        }
    }

    pub(crate) fn prefix_len(&self) -> usize {
        match self {
            Self::Prefix(prefix) => prefix.len(),
            _ => 0,
        }
    }

    pub(crate) fn capture_value<'a>(&'a self, path: &'a str, capture: &str) -> Option<&'a str> {
        match self {
            Self::Regex(regex) => regex.capture_value(path, capture),
            _ => None,
        }
    }

    pub(crate) fn header_captures(&self, path: &str) -> Vec<(String, String)> {
        let Self::Regex(regex) = self else {
            return Vec::new();
        };
        let Some(captures) = regex.regex.captures(path) else {
            return Vec::new();
        };
        let mut values = Vec::new();
        for index in 1..captures.len() {
            if let Some(value) = captures.get(index) {
                values.push((format!("route.regex.{index}"), value.as_str().to_owned()));
            }
        }
        for name in regex.regex.capture_names().flatten() {
            if let Some(value) = captures.name(name) {
                values.push((format!("route.regex.{name}"), value.as_str().to_owned()));
            }
        }
        values
    }
}
