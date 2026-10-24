#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod error;
pub mod fatal;
pub mod path_safety;
#[cfg(any(test, feature = "test-support"))]
pub mod test_process;
#[cfg(feature = "test-support")]
pub mod test_support;

pub use error::{FluxError, FluxResult};
