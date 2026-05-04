#[cfg(feature = "acme")]
pub mod acme;
#[cfg(feature = "cache")]
pub mod cache;
pub mod config;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "proxy")]
pub mod proxy;
#[cfg(feature = "security")]
pub mod security;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "web")]
pub mod web;

pub fn run() {
    println!("fluxheim: foundation build");
}
