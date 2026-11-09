use super::*;
use crate::health::tests_reuse_fixture::Fixture;

#[tokio::test]
async fn reuse_pool_shutdown_stops_cleanup_and_never_restarts_it() {
    let address = SocketAddr::from(([127, 0, 0, 1], 12345));
    let unused = Pool::default();
    unused.clear();
    assert!(unused.reserve(address).is_err());
    assert!(unused.reaper.get().is_none());
    let pool = Pool::default();
    let lease = pool.reserve(address).unwrap();
    let cancellation = lease.cancellation();
    pool.clear();
    assert!(*cancellation.borrow());
    assert!(pool.reserve(address).is_err());
    tokio::time::timeout(Duration::from_secs(1), async {
        while !pool.reaper.get().unwrap().0.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reuse_pool_capacity_and_busy_admission_are_bounded() {
    let pool = Pool::default();
    let mut leases = Vec::new();
    for port in 1..=MAX_RUNTIME_BACKEND_COUNT {
        let address = SocketAddr::from(([127, 0, 0, 1], port as u16));
        leases.push(pool.reserve(address).unwrap());
        assert!(pool.reserve(address).is_err());
    }
    assert!(
        pool.reserve(SocketAddr::from(([127, 0, 0, 1], 9999)))
            .is_err()
    );
    drop(leases);
    assert!(
        pool.reserve(SocketAddr::from(([127, 0, 0, 1], 9999)))
            .is_ok()
    );
}

#[tokio::test]
async fn reuse_pool_idle_and_max_age_expire_without_another_probe() {
    for age in [false, true] {
        let fixture = Fixture::start(false).await;
        let pool = Pool::default();
        let mut lease = pool.reserve(fixture.backend.addr).unwrap();
        let stream = tokio::net::TcpStream::connect(fixture.backend.addr)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while fixture.count() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        lease.connection = Some(Connection::new(Box::new(stream), false).await.unwrap());
        lease.release();
        {
            let mut state = pool.state.lock().unwrap();
            let (connection, idle) = state
                .entries
                .get_mut(&fixture.backend.addr)
                .unwrap()
                .idle
                .as_mut()
                .unwrap();
            if age {
                connection.created = Instant::now() - AGE_LIMIT;
            } else {
                *idle = Instant::now() - IDLE_LIMIT;
            }
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if pool.state.lock().unwrap().entries.is_empty()
                    && fixture.active.load(std::sync::atomic::Ordering::SeqCst) == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn reuse_pool_removed_lease_cannot_replace_new_membership_connection() {
    let pool = Pool::default();
    let backend = RuntimeBackend {
        addr: SocketAddr::from(([127, 0, 0, 1], 12345)),
        weight: 1,
    };
    let old = pool.reserve(backend.addr).unwrap();
    let mut cancellation = old.cancellation();
    pool.members(&BTreeSet::new());
    assert!(*cancellation.borrow_and_update());
    pool.members(&BTreeSet::from([backend.clone()]));
    let new = pool.reserve(backend.addr).unwrap();
    drop(old);
    assert!(pool.reserve(backend.addr).is_err());
    drop(new);
    assert!(pool.reserve(backend.addr).is_ok());
}
