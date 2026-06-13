use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct CachePurgeIndex {
    inner: Arc<RwLock<CachePurgeIndexInner>>,
}

#[derive(Debug, Default)]
struct CachePurgeIndexInner {
    entries: HashMap<String, CachePurgeIndexEntry>,
    order: VecDeque<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachePurgeIndexEntry {
    pub combined_key: String,
    pub primary_key: String,
    pub user_tag: String,
    pub path: Option<String>,
    pub cache_tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CacheIndexedPurgeResult {
    pub matched: usize,
    pub purged: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CacheStalePurgeResult {
    pub scanned: usize,
    pub stale: usize,
    pub purged: usize,
    pub truncated: bool,
}

impl CachePurgeIndex {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CachePurgeIndexInner::default())),
        }
    }

    pub fn insert(&self, combined_key: String, primary_key: String, user_tag: String) {
        let path = cache_primary_component(&primary_key, "path");
        self.insert_with_path_and_tags(combined_key, primary_key, user_tag, path, Vec::new());
    }

    pub fn insert_with_path(
        &self,
        combined_key: String,
        primary_key: String,
        user_tag: String,
        path: Option<String>,
    ) {
        self.insert_with_path_and_tags(combined_key, primary_key, user_tag, path, Vec::new());
    }

    pub fn insert_with_path_and_tags(
        &self,
        combined_key: String,
        primary_key: String,
        user_tag: String,
        path: Option<String>,
        cache_tags: Vec<String>,
    ) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };

        if inner.entries.contains_key(&combined_key) {
            inner.entries.insert(
                combined_key.clone(),
                CachePurgeIndexEntry {
                    combined_key,
                    primary_key,
                    user_tag,
                    path,
                    cache_tags,
                },
            );
            return;
        }

        inner.order.push_back(combined_key.clone());
        inner.entries.insert(
            combined_key.clone(),
            CachePurgeIndexEntry {
                combined_key,
                primary_key,
                user_tag,
                path,
                cache_tags,
            },
        );
    }

    pub fn remove_combined(&self, combined_key: &str) -> bool {
        let Ok(mut inner) = self.inner.write() else {
            return false;
        };
        let removed = inner.entries.remove(combined_key).is_some();
        if removed {
            inner.order.retain(|candidate| candidate != combined_key);
        }
        removed
    }

    pub fn contains_combined(&self, combined_key: &str) -> bool {
        let Ok(inner) = self.inner.read() else {
            return false;
        };
        inner.entries.contains_key(combined_key)
    }

    #[doc(hidden)]
    pub fn move_combined_keys_to_back(&self, combined_keys: &[String]) {
        if combined_keys.is_empty() {
            return;
        }
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        let candidates = combined_keys
            .iter()
            .filter(|key| inner.entries.contains_key(key.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return;
        }
        let candidate_set = candidates.iter().cloned().collect::<HashSet<_>>();
        inner.order.retain(|key| !candidate_set.contains(key));
        inner.order.extend(candidates);
    }

    pub fn combined_keys_for_primary(&self, primary_key: &str) -> Vec<String> {
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .entries
            .values()
            .filter(|entry| entry.primary_key == primary_key)
            .map(|entry| entry.combined_key.clone())
            .collect()
    }

    pub fn entries_with_prefix(&self, prefix: &str, limit: usize) -> Vec<CachePurgeIndexEntry> {
        if prefix.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| entry.combined_key.starts_with(prefix))
    }

    pub fn entries_for_user_tag(&self, user_tag: &str, limit: usize) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| entry.user_tag == user_tag)
    }

    pub fn entries_for_user_tag_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || path_prefix.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| {
            entry.user_tag == user_tag
                && entry
                    .path
                    .as_deref()
                    .is_some_and(|path| path.starts_with(path_prefix))
        })
    }

    pub fn entries_for_user_tag_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || path_exact.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| {
            entry.user_tag == user_tag
                && entry.path.as_deref().is_some_and(|path| path == path_exact)
        })
    }

    pub fn entries_for_user_tag_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || path_pattern.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| {
            entry.user_tag == user_tag
                && entry
                    .path
                    .as_deref()
                    .is_some_and(|path| cache_path_wildcard_matches(path_pattern, path))
        })
    }

    pub fn entries_for_user_tag_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || cache_tag.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| {
            entry.user_tag == user_tag && entry.cache_tags.iter().any(|tag| tag == cache_tag)
        })
    }

    fn entries_matching(
        &self,
        limit: usize,
        matches: impl Fn(&CachePurgeIndexEntry) -> bool,
    ) -> Vec<CachePurgeIndexEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .order
            .iter()
            .filter_map(|key| inner.entries.get(key))
            .filter(|entry| matches(entry))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        let Ok(inner) = self.inner.read() else {
            return 0;
        };
        inner.entries.len()
    }

    pub fn max_entries(&self) -> usize {
        usize::MAX
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CachePurgeIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[doc(hidden)]
pub fn cache_path_wildcard_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut rest = path;
    let mut first_part = true;

    for part in pattern.split('*').filter(|part| !part.is_empty()) {
        if first_part && anchored_start {
            let Some(after_prefix) = rest.strip_prefix(part) else {
                return false;
            };
            rest = after_prefix;
        } else {
            let Some(index) = rest.find(part) else {
                return false;
            };
            rest = &rest[index + part.len()..];
        }
        first_part = false;
    }

    !anchored_end || pattern.ends_with('*') || rest.is_empty()
}

#[doc(hidden)]
pub fn cache_primary_component(primary_key: &str, name: &str) -> Option<String> {
    let mut rest = primary_key
        .strip_prefix("fluxheim-image-v1;")
        .unwrap_or(primary_key);
    while !rest.is_empty() {
        let (component, after_component) = rest.split_once(':')?;
        let (len, after_len) = after_component.split_once(':')?;
        let len = len.parse::<usize>().ok()?;
        let bytes = after_len.as_bytes();
        if bytes.len() < len {
            return None;
        }
        let value = std::str::from_utf8(&bytes[..len]).ok()?;
        let after_value = &after_len[len..];
        rest = after_value.strip_prefix(';')?;
        if component == name {
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{CachePurgeIndex, cache_path_wildcard_matches, cache_primary_component};

    #[test]
    fn wildcard_matches_absolute_path_patterns() {
        assert!(cache_path_wildcard_matches(
            "/media/*/thumb.png",
            "/media/a/thumb.png"
        ));
        assert!(cache_path_wildcard_matches(
            "/media/*",
            "/media/a/thumb.png"
        ));
        assert!(!cache_path_wildcard_matches(
            "/media/*/thumb.png",
            "/asset/thumb.png"
        ));
        assert!(!cache_path_wildcard_matches(
            "/media/*/thumb.png",
            "/media/a/full.png"
        ));
    }

    #[test]
    fn primary_component_reads_length_delimited_path() {
        let primary = "fluxheim-image-v1;namespace:14:cache-vhost-v1;method:3:GET;host:10:cache.test;path:10:/a:b;c.png;query:0:;";
        assert_eq!(
            cache_primary_component(primary, "path").as_deref(),
            Some("/a:b;c.png")
        );
        assert_eq!(
            cache_primary_component(primary, "method").as_deref(),
            Some("GET")
        );
        assert_eq!(cache_primary_component(primary, "missing"), None);
    }

    #[test]
    fn purge_index_preserves_insertion_order() {
        let index = CachePurgeIndex::new();
        index.insert_with_path(
            "combined-a".to_owned(),
            "primary-a".to_owned(),
            "tag".to_owned(),
            Some("/a".to_owned()),
        );
        index.insert_with_path(
            "combined-b".to_owned(),
            "primary-b".to_owned(),
            "tag".to_owned(),
            Some("/b".to_owned()),
        );

        let entries = index.entries_for_user_tag("tag", 10);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.combined_key.as_str())
                .collect::<Vec<_>>(),
            ["combined-a", "combined-b"]
        );
    }
}
