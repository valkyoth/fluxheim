use super::super::*;

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
