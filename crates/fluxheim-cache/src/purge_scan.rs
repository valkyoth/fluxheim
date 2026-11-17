use std::collections::VecDeque;
use std::ops::Bound::{Excluded, Included};

use super::{CachePurgeIndex, CachePurgeIndexEntry, cache_path_wildcard_matches};

const MAX_SCANS: usize = 64;
const MAX_SELECTOR_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachePurgeMode {
    Hard,
    Soft,
    Stale,
    DryRun,
}

#[derive(Clone, Copy, Debug)]
pub enum CachePurgeSelector<'a> {
    Scope(&'a str),
    Prefix(&'a str, &'a str),
    Exact(&'a str, &'a str),
    Pattern(&'a str, &'a str),
    Tag(&'a str, &'a str),
}

impl<'a> CachePurgeSelector<'a> {
    fn parts(self) -> (u8, &'a str, &'a str) {
        match self {
            Self::Scope(scope) => (0, scope, ""),
            Self::Prefix(scope, value) => (1, scope, value),
            Self::Exact(scope, value) => (2, scope, value),
            Self::Pattern(scope, value) => (3, scope, value),
            Self::Tag(scope, value) => (4, scope, value),
        }
    }

    fn matches(self, entry: &CachePurgeIndexEntry) -> bool {
        let (_, scope, _) = self.parts();
        if entry.user_tag != scope {
            return false;
        }
        match self {
            Self::Scope(_) => true,
            Self::Prefix(_, value) => entry.path.as_deref().is_some_and(|p| p.starts_with(value)),
            Self::Exact(_, value) => entry.path.as_deref() == Some(value),
            Self::Pattern(_, value) => entry
                .path
                .as_deref()
                .is_some_and(|p| cache_path_wildcard_matches(value, p)),
            Self::Tag(_, value) => entry.cache_tags.iter().any(|tag| tag == value),
        }
    }
}

#[derive(Default)]
pub struct CachePurgeVisit {
    pub purged: bool,
    pub stale: bool,
    pub retry: bool,
}

#[derive(Default, Debug)]
pub struct CachePurgeScanResult {
    pub examined: usize,
    pub matched: usize,
    pub purged: usize,
    pub stale: usize,
    pub truncated: bool,
}

#[derive(Debug)]
struct Progress {
    kind: u8,
    scope: String,
    value: String,
    mode: CachePurgeMode,
    after: u64,
    through: u64,
    failed: bool,
}

#[derive(Default, Debug)]
pub(super) struct Scans(VecDeque<Progress>);

impl CachePurgeIndex {
    /// Inspect at most `limit` index entries, including nonmatches. Continuation
    /// is shared per selector/mode and bounded to 64 active scans. Completion is
    /// a completed traversal, not a fence against subsequent cache fills.
    pub fn scan(
        &self,
        selector: CachePurgeSelector<'_>,
        mode: CachePurgeMode,
        limit: usize,
        mut visit: impl FnMut(&CachePurgeIndexEntry) -> CachePurgeVisit,
    ) -> CachePurgeScanResult {
        self.scan_batch(selector, mode, limit, |entries| {
            let mut result = CachePurgeScanResult::default();
            for (_, entry) in entries {
                let outcome = visit(entry);
                result.purged += usize::from(outcome.purged);
                result.stale += usize::from(outcome.stale);
                result.truncated |= outcome.retry;
            }
            result
        })
    }

    pub fn is_current_generation(&self, key: &str, sequence: u64) -> bool {
        self.inner
            .read()
            .is_ok_and(|inner| inner.positions.get(key) == Some(&sequence))
    }

    /// Complete the visit before advancing this selector's cursor. A grouped
    /// mutation signals retry via truncated; its counts include only commits.
    pub fn scan_batch(
        &self,
        selector: CachePurgeSelector<'_>,
        mode: CachePurgeMode,
        limit: usize,
        visit: impl FnOnce(
            &mut dyn Iterator<Item = (u64, &CachePurgeIndexEntry)>,
        ) -> CachePurgeScanResult,
    ) -> CachePurgeScanResult {
        let incomplete = || CachePurgeScanResult {
            truncated: true,
            ..Default::default()
        };
        let (kind, scope, value) = selector.parts();
        if limit == 0
            || scope.is_empty()
            || scope.len().saturating_add(value.len()) > MAX_SELECTOR_BYTES
            || (kind != 0 && value.is_empty())
        {
            return incomplete();
        }
        // Serialize traversal and visits, without holding the index lock during
        // a visit. Concurrent callers fail visibly instead of waiting on I/O.
        let Ok(mut scans) = self.scans.try_lock() else {
            return incomplete();
        };
        let Ok(inner) = self.inner.read() else {
            return incomplete();
        };
        if inner.exhausted {
            return incomplete();
        }
        let position = scans
            .0
            .iter()
            .position(|p| p.kind == kind && p.scope == scope && p.value == value && p.mode == mode);
        let mut progress = position
            .and_then(|p| scans.0.remove(p))
            .unwrap_or_else(|| Progress {
                kind,
                scope: scope.to_owned(),
                value: value.to_owned(),
                mode,
                after: 0,
                through: inner.sequence,
                failed: false,
            });
        let mut candidates = inner
            .order
            .range((Excluded(progress.after), Included(progress.through)));
        let selected = candidates
            .by_ref()
            .take(limit)
            .filter_map(|(sequence, key)| {
                inner
                    .entries
                    .get(key)
                    .map(|entry| (*sequence, entry.clone()))
            })
            .collect::<Vec<_>>();
        let more = candidates.next().is_some();
        drop(inner);
        let mut matched = 0;
        let mut examined = 0;
        let mut result = visit(&mut selected.iter().filter_map(|(sequence, entry)| {
            examined += 1;
            progress.after = *sequence;
            if selector.matches(entry) && self.is_current_generation(&entry.combined_key, *sequence)
            {
                matched += 1;
                Some((*sequence, entry))
            } else {
                None
            }
        }));
        let more = more || examined < selected.len();
        result.examined = examined;
        result.matched = matched;
        progress.failed |= result.truncated;
        let Ok(inner) = self.inner.read() else {
            return incomplete();
        };
        result.truncated =
            more || progress.failed || inner.sequence > progress.through || inner.exhausted;
        if result.truncated {
            if !more {
                progress.after = 0;
                progress.through = inner.sequence;
                progress.failed = false;
            }
            if scans.0.len() == MAX_SCANS {
                scans.0.pop_front();
            }
            scans.0.push_back(progress);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(count: usize) -> CachePurgeIndex {
        let index = CachePurgeIndex::new();
        for n in 0..count {
            index.insert_with_path_and_tags(
                n.to_string(),
                n.to_string(),
                "scope".into(),
                Some(format!("/{n}")),
                vec!["tag".into()],
            );
        }
        index
    }

    #[test]
    fn sparse_selectors_bound_examined_entries_and_finish() {
        for selector in [
            CachePurgeSelector::Prefix("scope", "/9"),
            CachePurgeSelector::Exact("scope", "/9"),
            CachePurgeSelector::Pattern("scope", "/*9"),
            CachePurgeSelector::Tag("scope", "absent"),
        ] {
            let index = index(10);
            let mut matched = 0;
            for n in 0..5 {
                let result = index.scan(selector, CachePurgeMode::Hard, 2, |_| {
                    CachePurgeVisit::default()
                });
                assert_eq!(result.examined, 2);
                assert_eq!(result.truncated, n != 4);
                matched += result.matched;
            }
            assert_eq!(
                matched,
                usize::from(!matches!(selector, CachePurgeSelector::Tag(..)))
            );
        }
    }

    #[test]
    fn partially_consumed_batch_resumes_at_first_unexamined_entry() {
        let index = index(4);
        let selector = CachePurgeSelector::Scope("scope");
        let mut visited = Vec::new();
        for (count, more) in [(1, true), (3, false)] {
            let result = index.scan_batch(selector, CachePurgeMode::Soft, 4, |entries| {
                visited.extend(entries.take(count).map(|(_, e)| e.combined_key.clone()));
                CachePurgeScanResult::default()
            });
            assert_eq!((result.examined, result.matched), (count, count));
            assert_eq!(result.truncated, more);
        }
        assert_eq!(visited, ["0", "1", "2", "3"]);
    }

    #[test]
    fn failures_are_remembered_until_a_complete_successful_pass() {
        let index = index(3);
        let selector = CachePurgeSelector::Scope("scope");
        let first = index.scan(selector, CachePurgeMode::Hard, 1, |_| CachePurgeVisit {
            retry: true,
            ..Default::default()
        });
        assert!(first.truncated);
        let rest = index.scan(selector, CachePurgeMode::Hard, 2, |_| {
            CachePurgeVisit::default()
        });
        assert!(rest.truncated);
        let retry = index.scan(selector, CachePurgeMode::Hard, 3, |_| {
            CachePurgeVisit::default()
        });
        assert_eq!(retry.examined, 3);
        assert!(!retry.truncated);
    }

    #[test]
    fn replacements_and_new_fills_require_another_pass() {
        let index = index(2);
        let selector = CachePurgeSelector::Scope("scope");
        assert!(
            index
                .scan(selector, CachePurgeMode::Soft, 1, |_| {
                    CachePurgeVisit::default()
                })
                .truncated
        );
        index.insert("0".into(), "0".into(), "scope".into());
        let mut visited = Vec::new();
        let result = index.scan(selector, CachePurgeMode::Soft, 2, |entry| {
            visited.push(entry.combined_key.clone());
            CachePurgeVisit::default()
        });
        assert_eq!(visited, ["1"]);
        assert!(result.truncated);
        assert!(
            !index
                .scan(selector, CachePurgeMode::Soft, 2, |_| {
                    CachePurgeVisit::default()
                })
                .truncated
        );
    }

    #[test]
    fn modes_and_scopes_have_independent_progress() {
        let index = index(3);
        for mode in [
            CachePurgeMode::Hard,
            CachePurgeMode::Soft,
            CachePurgeMode::Stale,
            CachePurgeMode::DryRun,
        ] {
            let mut visited = Vec::new();
            assert!(
                index
                    .scan(CachePurgeSelector::Scope("scope"), mode, 1, |entry| {
                        visited.push(entry.combined_key.clone());
                        CachePurgeVisit::default()
                    })
                    .truncated
            );
            assert_eq!(visited, ["0"]);
        }
    }

    #[test]
    fn cursor_capacity_eviction_restarts_without_claiming_completion() {
        let index = index(3);
        for n in 0..100 {
            assert!(
                index
                    .scan(
                        CachePurgeSelector::Exact("scope", &format!("/{n}")),
                        CachePurgeMode::Hard,
                        1,
                        |_| CachePurgeVisit::default()
                    )
                    .truncated
            );
        }
        assert_eq!(index.scans.lock().unwrap().0.len(), MAX_SCANS);
        let mut visited = Vec::new();
        let result = index.scan(
            CachePurgeSelector::Exact("scope", "/0"),
            CachePurgeMode::Hard,
            1,
            |entry| {
                visited.push(entry.combined_key.clone());
                CachePurgeVisit::default()
            },
        );
        assert!(result.truncated);
        assert_eq!(visited, ["0"]);
    }

    #[test]
    fn concurrent_scans_and_invalid_bounds_fail_closed() {
        let index = index(1);
        let selector = CachePurgeSelector::Scope("scope");
        assert!(
            index
                .scan(selector, CachePurgeMode::Hard, 0, |_| unreachable!())
                .truncated
        );
        assert!(
            index
                .scan(
                    CachePurgeSelector::Scope(&"x".repeat(MAX_SELECTOR_BYTES + 1)),
                    CachePurgeMode::Hard,
                    1,
                    |_| unreachable!()
                )
                .truncated
        );
        let result = index.scan(selector, CachePurgeMode::Hard, 1, |_| {
            assert!(
                index
                    .scan(selector, CachePurgeMode::Hard, 1, |_| unreachable!())
                    .truncated
            );
            CachePurgeVisit::default()
        });
        assert!(!result.truncated);
    }
}
