use super::super::*;
use crate::LoadBalanceRetryConfig;

#[test]
fn validates_load_balance_retry_policy() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            enabled = true
            max_retries = 2
            methods = ["GET", "HEAD"]
            statuses = [500, 502, 503]
            status_ranges = [{ start = 520, end = 529 }]
            budget_per_window = 100
            budget_window_secs = 10
            "#,
    )
    .unwrap();
    config.validate().unwrap();
    assert_eq!(config.proxy.load_balance.retry.budget_per_window, 100);
    assert_eq!(config.proxy.load_balance.retry.budget_window_secs, 10);
    assert_eq!(config.proxy.load_balance.retry.statuses, [500, 502, 503]);
    assert_eq!(config.proxy.load_balance.retry.status_ranges[0].start, 520);

    let unsafe_method: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            enabled = true
            methods = ["POST"]
            budget_per_window = 1
            "#,
    )
    .unwrap();
    assert_eq!(
        unsafe_method.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.methods"
        })
    );

    let invalid_budget: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            budget_window_secs = 0
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_budget.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.budget_window_secs"
        })
    );

    let invalid_status: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            statuses = [404]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.statuses"
        })
    );

    let duplicate_status: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            statuses = [500, 500]
            "#,
    )
    .unwrap();
    assert_eq!(
        duplicate_status.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.statuses"
        })
    );

    let invalid_status_range: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            status_ranges = [{ start = 499, end = 503 }]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status_range.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.status_ranges"
        })
    );
}

#[test]
fn enabled_retry_requires_explicit_positive_budget_in_every_proxy_scope() {
    for prefix in [
        "[proxy.load_balance.retry]",
        "[[vhosts]]\nname = 'retry.test'\nhosts = ['retry.test']\n[vhosts.proxy.load_balance.retry]",
        "[[vhosts]]\nname = 'retry.test'\nhosts = ['retry.test']\n[[vhosts.routes]]\nname = 'retry'\npath_prefix = '/'\n[vhosts.routes.proxy.load_balance.retry]",
    ] {
        for budget in ["", "budget_per_window = 0", "budget_per_window = 1000001"] {
            let config: Config =
                toml::from_str(&format!("{prefix}\nenabled = true\n{budget}\n")).unwrap();
            let error = match config.validate().unwrap_err() {
                ConfigError::VhostSection { source, .. }
                | ConfigError::RouteSection { source, .. } => *source,
                error => error,
            };
            assert_eq!(
                error,
                ConfigError::InvalidLoadBalanceRetry {
                    field: "proxy.load_balance.retry.budget_per_window",
                },
                "{prefix}: {budget}",
            );
        }
    }
}

#[test]
fn retry_budget_boundaries_preserve_disabled_defaults_and_explicit_opt_in() {
    for (enabled, max_retries, budget, valid) in [
        (false, 1, 0, true),
        (true, 0, 0, true),
        (true, 1, 0, false),
        (true, 10, 0, false),
        (true, 1, 1, true),
        (true, 10, 1_000_000, true),
        (true, 1, 1_000_001, false),
    ] {
        let config = LoadBalanceRetryConfig {
            enabled,
            max_retries,
            budget_per_window: budget,
            ..Default::default()
        };
        assert_eq!(config.validate().is_ok(), valid, "{config:?}");
    }
    Config::default().validate().unwrap();
}
