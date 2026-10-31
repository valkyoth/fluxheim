use super::*;
use fluxheim_config::ConcurrencyLimitConfig;
use std::future::Future;
use std::task::{Context, Poll, Waker};

#[tokio::test]
async fn queue_zero_derives_capacity_and_cancellation_returns_slots() {
    let limiter = NativeConcurrencyLimit::from_config(&ConcurrencyLimitConfig {
        enabled: true,
        max_in_flight: 1,
        queue_timeout_ms: 1000,
        ..Default::default()
    });
    assert_eq!(limiter.max_queue, 4);
    let active = limiter.acquire().await.unwrap().unwrap();
    let mut waiting = Box::pin(limiter.acquire());
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(limiter.queued.load(Ordering::Acquire), 1);
    drop(waiting);
    assert_eq!(limiter.queued.load(Ordering::Acquire), 0);
    drop(active);
    assert_eq!(limiter.semaphore.available_permits(), 1);
    assert!(limiter.clone().acquire().await.unwrap().is_some());
}

#[tokio::test]
async fn full_queue_rejects_and_timeout_returns_queue_slot() {
    let limiter = NativeConcurrencyLimit::from_config(&ConcurrencyLimitConfig {
        enabled: true,
        max_in_flight: 1,
        max_queue: 1,
        queue_timeout_ms: 10,
        ..Default::default()
    });
    let active = limiter.acquire().await.unwrap();
    let mut waiting = Box::pin(limiter.acquire());
    assert!(
        waiting
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(limiter.acquire().await.unwrap_err(), 503);
    assert_eq!(waiting.await.unwrap_err(), 503);
    assert_eq!(limiter.queued.load(Ordering::Acquire), 0);
    drop(active);
    assert!(limiter.acquire().await.unwrap().is_some());
}

#[tokio::test]
async fn zero_timeout_rejects_without_entering_queue_and_clone_shares_budget() {
    let limiter = NativeConcurrencyLimit::from_config(&ConcurrencyLimitConfig {
        enabled: true,
        max_in_flight: 1,
        max_queue: 12,
        ..Default::default()
    });
    let cloned = limiter.clone();
    let active = limiter.acquire().await.unwrap();
    assert_eq!(cloned.acquire().await.unwrap_err(), 503);
    assert_eq!(limiter.queued.load(Ordering::Acquire), 0);
    drop(active);
    assert!(cloned.acquire().await.unwrap().is_some());
}
