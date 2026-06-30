use std::process;
use std::sync::OnceLock;

pub(super) const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

pub(super) fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_with_seed(bytes, FNV_OFFSET_BASIS)
}

pub(super) fn fnv1a64_with_seed(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

pub(super) fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    if let Err(error) = getrandom::fill(&mut bytes) {
        log::error!(
            target: "fluxheim::security",
            "failed to generate load-balancer random candidate seed: {error}"
        );
        process::abort();
    }
    u64::from_le_bytes(bytes)
}

pub(super) fn maglev_route_secret() -> u64 {
    route_secret(&MAGLEV_ROUTE_SECRET, "Maglev routing hash")
}

pub(super) fn consistent_route_secret() -> u64 {
    route_secret(&CONSISTENT_ROUTE_SECRET, "consistent-hash routing")
}

pub(super) fn fnv_route_secret() -> u64 {
    route_secret(&FNV_ROUTE_SECRET, "FNV routing hash")
}

static MAGLEV_ROUTE_SECRET: OnceLock<u64> = OnceLock::new();
static CONSISTENT_ROUTE_SECRET: OnceLock<u64> = OnceLock::new();
static FNV_ROUTE_SECRET: OnceLock<u64> = OnceLock::new();

fn route_secret(secret: &'static OnceLock<u64>, label: &'static str) -> u64 {
    *secret.get_or_init(|| {
        let mut bytes = [0u8; 8];
        if let Err(error) = getrandom::fill(&mut bytes) {
            log::error!(
                target: "fluxheim::security",
                "failed to seed {label} secret: {error}"
            );
            process::abort();
        }
        u64::from_le_bytes(bytes)
    })
}
