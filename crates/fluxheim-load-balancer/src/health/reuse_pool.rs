use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use fluxheim_common::FluxResult;
use tokio::sync::watch;

use super::reuse_connection::{AbortTask, Connection, failure};
use crate::backend::{MAX_RUNTIME_BACKEND_COUNT, RuntimeBackend};

const IDLE_LIMIT: Duration = Duration::from_secs(30);
const AGE_LIMIT: Duration = Duration::from_secs(300);

#[cfg(test)]
#[path = "tests_reuse_pool.rs"]
mod tests;

struct Entry {
    // The identity also cancels a checked-out connection when membership changes.
    identity: Arc<watch::Sender<bool>>,
    // None reserves the slot for exactly one in-flight probe; there is no waiter queue.
    idle: Option<(Connection, Instant)>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.identity.send_replace(true);
    }
}

#[derive(Default)]
struct State {
    entries: BTreeMap<SocketAddr, Entry>,
    members: Option<BTreeSet<SocketAddr>>,
    closed: bool,
}

#[derive(Default)]
pub(super) struct Pool {
    state: Arc<Mutex<State>>,
    reaper: OnceLock<AbortTask>,
}

impl Pool {
    pub(super) fn reserve(&self, address: SocketAddr) -> FluxResult<Lease<'_>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| failure("health pool unavailable"))?;
        if state.closed {
            return Err(failure("health pool closed"));
        }
        self.reaper.get_or_init(|| {
            let weak = Arc::downgrade(&self.state);
            AbortTask(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let Some(state) = weak.upgrade() else {
                        return;
                    };
                    let Ok(mut state) = state.lock() else {
                        return;
                    };
                    expire(&mut state, Instant::now());
                }
            }))
        });
        expire(&mut state, Instant::now());
        if state
            .members
            .as_ref()
            .is_some_and(|members| !members.contains(&address))
        {
            return Err(failure("health backend no longer configured"));
        }
        if let Some(entry) = state.entries.get_mut(&address) {
            let Some((connection, _)) = entry.idle.take() else {
                return Err(failure("health probe already in progress"));
            };
            return Ok(Lease {
                pool: self,
                address,
                identity: Arc::clone(&entry.identity),
                connection: (!connection.closed()).then_some(connection),
                returned: false,
            });
        }
        if state.entries.len() >= MAX_RUNTIME_BACKEND_COUNT {
            return Err(failure("health connection limit reached"));
        }
        let identity = Arc::new(watch::channel(false).0);
        state.entries.insert(
            address,
            Entry {
                identity: Arc::clone(&identity),
                idle: None,
            },
        );
        Ok(Lease {
            pool: self,
            address,
            identity,
            connection: None,
            returned: false,
        })
    }

    pub(super) fn members(&self, backends: &BTreeSet<RuntimeBackend>) {
        if let Ok(mut state) = self.state.lock() {
            let members: BTreeSet<_> = backends.iter().map(|backend| backend.addr).collect();
            state.entries.retain(|address, _| members.contains(address));
            state.members = Some(members);
        }
    }

    pub(super) fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.entries.clear();
        }
        if let Some(reaper) = self.reaper.get() {
            reaper.0.abort();
        }
    }
}

fn expire(state: &mut State, now: Instant) {
    state.entries.retain(|_, entry| {
        entry.idle.as_ref().is_none_or(|(connection, idle)| {
            now.saturating_duration_since(*idle) < IDLE_LIMIT
                && now.saturating_duration_since(connection.created) < AGE_LIMIT
                && !connection.closed()
        })
    });
}

pub(super) struct Lease<'a> {
    pool: &'a Pool,
    address: SocketAddr,
    identity: Arc<watch::Sender<bool>>,
    pub(super) connection: Option<Connection>,
    returned: bool,
}

impl Lease<'_> {
    pub(super) fn cancellation(&self) -> watch::Receiver<bool> {
        self.identity.subscribe()
    }

    pub(super) fn release(mut self) {
        if let Some(connection) = self.connection.take()
            && !connection.closed()
            && let Ok(mut state) = self.pool.state.lock()
            && let Some(entry) = state.entries.get_mut(&self.address)
            && Arc::ptr_eq(&entry.identity, &self.identity)
        {
            entry.idle = Some((connection, Instant::now()));
            self.returned = true;
        }
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        // An old cancelled probe must not remove a newly added member's slot.
        if !self.returned
            && let Ok(mut state) = self.pool.state.lock()
            && state
                .entries
                .get(&self.address)
                .is_some_and(|entry| Arc::ptr_eq(&entry.identity, &self.identity))
        {
            state.entries.remove(&self.address);
        }
    }
}
