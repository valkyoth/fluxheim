#[cfg(feature = "stream-proxy")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
#[cfg(feature = "stream-proxy")]
pub struct StreamConnectionSlot {
    current: std::sync::Arc<AtomicUsize>,
}

#[cfg(feature = "stream-proxy")]
impl Drop for StreamConnectionSlot {
    fn drop(&mut self) {
        self.current.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(feature = "stream-proxy")]
pub fn acquire_stream_connection_slot(
    current: &std::sync::Arc<AtomicUsize>,
    max_connections: usize,
) -> Option<StreamConnectionSlot> {
    if max_connections == 0 {
        let mut observed = current.load(Ordering::Acquire);
        loop {
            let next = observed.checked_add(1)?;
            match current.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(StreamConnectionSlot {
                        current: current.clone(),
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }

    let mut observed = current.load(Ordering::Acquire);
    loop {
        if observed >= max_connections {
            return None;
        }
        let next = observed.checked_add(1)?;
        match current.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return Some(StreamConnectionSlot {
                    current: current.clone(),
                });
            }
            Err(actual) => observed = actual,
        }
    }
}
