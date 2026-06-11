#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod error;
pub mod path_safety;

pub use error::{FluxError, FluxResult};
