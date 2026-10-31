use crate::{ConcurrencyLimitConfig, Config, RateLimitConfig, RateLimitMode};

#[test]
fn admission_recipe_and_delayed_variant_validate() {
    let mut config: Config =
        toml::from_str(include_str!("../../../examples/limits/local.toml")).unwrap();
    config.validate().unwrap();
    config.vhosts[0].rate_limit.enabled = true;
    config.vhosts[0].routes[0].rate_limit.mode = RateLimitMode::Delay;
    config.vhosts[0].concurrency.queue_timeout_ms = 1000;
    config.validate().unwrap();
}

#[test]
fn rate_options_validate_at_documented_boundaries() {
    let valid = RateLimitConfig {
        enabled: true,
        requests_per_second: 1,
        ..Default::default()
    };
    for invalid in [
        RateLimitConfig {
            requests_per_second: 0,
            ..valid
        },
        RateLimitConfig {
            requests_per_second: 1_000_001,
            ..valid
        },
        RateLimitConfig {
            burst: 1_000_001,
            ..valid
        },
        RateLimitConfig {
            status: 399,
            ..valid
        },
        RateLimitConfig {
            status: 600,
            ..valid
        },
        RateLimitConfig {
            table_max_entries: 0,
            ..valid
        },
        RateLimitConfig {
            table_max_entries: 1_000_001,
            ..valid
        },
        RateLimitConfig {
            entry_ttl_secs: 0,
            ..valid
        },
        RateLimitConfig {
            entry_ttl_secs: 86_401,
            ..valid
        },
        RateLimitConfig {
            max_delay_ms: 60_001,
            ..valid
        },
        RateLimitConfig {
            mode: RateLimitMode::Delay,
            max_delay_ms: 0,
            ..valid
        },
    ] {
        assert!(
            invalid.validate("vhosts.rate_limit").is_err(),
            "{invalid:?}"
        );
        RateLimitConfig {
            enabled: false,
            ..invalid
        }
        .validate("vhosts.rate_limit")
        .unwrap();
    }
    RateLimitConfig {
        requests_per_second: 1_000_000,
        burst: 1_000_000,
        table_max_entries: 1_000_000,
        entry_ttl_secs: 86_400,
        max_delay_ms: 60_000,
        status: 599,
        ..valid
    }
    .validate("vhosts.rate_limit")
    .unwrap();
    RateLimitConfig {
        table_max_entries: 1,
        max_delay_ms: 0,
        ..valid
    }
    .validate("vhosts.rate_limit")
    .unwrap();
}

#[test]
fn concurrency_options_validate_at_documented_boundaries() {
    let valid = ConcurrencyLimitConfig {
        enabled: true,
        max_in_flight: 1,
        ..Default::default()
    };
    for invalid in [
        ConcurrencyLimitConfig {
            max_in_flight: 0,
            ..valid
        },
        ConcurrencyLimitConfig {
            max_in_flight: 1_000_001,
            ..valid
        },
        ConcurrencyLimitConfig {
            max_queue: 1_000_001,
            ..valid
        },
        ConcurrencyLimitConfig {
            queue_timeout_ms: 60_001,
            ..valid
        },
        ConcurrencyLimitConfig {
            status: 399,
            ..valid
        },
        ConcurrencyLimitConfig {
            status: 600,
            ..valid
        },
    ] {
        assert!(
            invalid.validate("vhosts.concurrency").is_err(),
            "{invalid:?}"
        );
        ConcurrencyLimitConfig {
            enabled: false,
            ..invalid
        }
        .validate("vhosts.concurrency")
        .unwrap();
    }
    ConcurrencyLimitConfig {
        max_in_flight: 1_000_000,
        max_queue: 1_000_000,
        queue_timeout_ms: 60_000,
        status: 599,
        ..valid
    }
    .validate("vhosts.concurrency")
    .unwrap();
}
