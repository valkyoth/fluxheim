use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::config_stream::StreamRouteConfig;

#[derive(Debug)]
pub struct StreamUpstreamSelector {
    upstreams: Arc<[RuntimeStreamUpstream]>,
    primary_indices: Arc<[usize]>,
    backup_indices: Arc<[usize]>,
    primary_weight_total: usize,
    next_upstream: AtomicUsize,
}

impl StreamUpstreamSelector {
    pub fn from_route(route: &StreamRouteConfig) -> FluxResult<Self> {
        let upstreams = runtime_stream_upstreams(route);
        if upstreams.is_empty() {
            return Err(FluxError::InvalidInput(
                "stream route requires at least one upstream",
            ));
        }
        let primary_indices = upstreams
            .iter()
            .enumerate()
            .filter_map(|(index, upstream)| {
                (!upstream.backup && !upstream.drained).then_some(index)
            })
            .collect::<Vec<_>>();
        if primary_indices.is_empty() {
            return Err(FluxError::InvalidInput(
                "stream route requires at least one selectable primary upstream",
            ));
        }
        let backup_indices = upstreams
            .iter()
            .enumerate()
            .filter_map(|(index, upstream)| (upstream.backup && !upstream.drained).then_some(index))
            .collect::<Vec<_>>();
        let primary_weight_total = primary_indices
            .iter()
            .map(|index| upstreams[*index].weight)
            .sum::<usize>()
            .max(1);

        Ok(Self {
            upstreams: upstreams.into(),
            primary_indices: primary_indices.into(),
            backup_indices: backup_indices.into(),
            primary_weight_total,
            next_upstream: AtomicUsize::new(0),
        })
    }

    pub fn select_candidates(&self) -> Vec<StreamSelectedUpstream> {
        let weighted_index =
            self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.primary_weight_total;
        let first = self
            .primary_indices
            .iter()
            .copied()
            .scan(0usize, |seen, index| {
                *seen = seen.saturating_add(self.upstreams[index].weight);
                Some((index, *seen))
            })
            .find_map(|(index, seen)| (weighted_index < seen).then_some(index))
            .unwrap_or(self.primary_indices[0]);

        self.primary_indices
            .iter()
            .copied()
            .filter(move |index| *index == first)
            .chain(
                self.primary_indices
                    .iter()
                    .copied()
                    .filter(move |index| *index != first),
            )
            .chain(self.backup_indices.iter().copied())
            .map(|index| StreamSelectedUpstream {
                authority: self.upstreams[index].authority.clone(),
                alias: self.upstreams[index].alias.clone(),
                backup: self.upstreams[index].backup,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RuntimeStreamUpstream {
    authority: Arc<str>,
    alias: Option<Arc<str>>,
    weight: usize,
    backup: bool,
    drained: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StreamSelectedUpstream {
    pub authority: Arc<str>,
    pub alias: Option<Arc<str>>,
    pub backup: bool,
}

impl StreamSelectedUpstream {
    pub fn label(&self) -> &str {
        self.alias.as_deref().unwrap_or(self.authority.as_ref())
    }
}

fn runtime_stream_upstreams(route: &StreamRouteConfig) -> Vec<RuntimeStreamUpstream> {
    let backup = route
        .backup_upstreams
        .iter()
        .map(|upstream| upstream.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let drain = route
        .drain_upstreams
        .iter()
        .map(|upstream| upstream.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    route
        .upstreams()
        .enumerate()
        .map(|(index, authority)| {
            let normalized = authority.to_ascii_lowercase();
            RuntimeStreamUpstream {
                authority: Arc::from(authority),
                alias: route
                    .upstream_aliases
                    .get(index)
                    .map(|alias| Arc::<str>::from(alias.as_str())),
                weight: route.upstream_weights.get(index).copied().unwrap_or(1),
                backup: backup.contains(&normalized),
                drained: drain.contains(&normalized),
            }
        })
        .collect()
}
