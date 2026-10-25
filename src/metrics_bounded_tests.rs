use super::*;

fn local_budget(limit: usize) -> Arc<Budget> {
    Arc::new(Budget {
        used: AtomicUsize::new(0),
        limit,
    })
}

#[test]
fn churn_preserves_lifetime_totals_and_bounds_storage_before_allocation() {
    let budget = local_budget(32);
    let counter = IntCounterVec::with_budget(
        Opts::new("churn_total", "test"),
        &["resource"],
        budget.clone(),
    )
    .unwrap();
    counter.with_label_values(&["kept"]).inc_by(7);
    for generation in 0..100_000 {
        counter
            .with_label_values(&[&format!("resource-{generation}")])
            .inc();
    }
    counter.with_label_values(&["kept"]).inc();
    assert_eq!(counter.with_label_values(&["kept"]).get(), 8);
    assert_eq!(budget.used.load(Ordering::Relaxed), 32);
    assert_eq!(counter.collect()[0].get_metric().len(), 32);
    assert_eq!(
        counter.collect()[0]
            .get_metric()
            .iter()
            .map(|m| m.get_counter().get_or_default().value())
            .sum::<f64>(),
        100_008.0
    );
    assert_eq!(counter.admission.lock().unwrap().keys.len(), 31);
    drop(counter);
    assert_eq!(budget.used.load(Ordering::Relaxed), 0);
}

#[test]
fn histogram_cost_includes_inf_sum_count_and_shares_global_budget() {
    let budget = local_budget(18);
    let hist = HistogramVec::with_budget(
        HistogramOpts::new("duration_seconds", "test").buckets(vec![0.01, 0.1, 1.0]),
        &["route"],
        budget.clone(),
    )
    .unwrap();
    let counter =
        IntCounterVec::with_budget(Opts::new("count_total", "test"), &["route"], budget.clone())
            .unwrap();
    for n in 0..1000 {
        hist.with_label_values(&[&n.to_string()]).observe(0.05);
    }
    assert_eq!(hist.collect()[0].get_metric().len(), 2);
    for n in 0..1000 {
        counter.with_label_values(&[&n.to_string()]).inc();
    }
    assert_eq!(budget.used.load(Ordering::Relaxed), 18);
    assert_eq!(counter.collect()[0].get_metric().len(), 6);
    let total: u64 = hist.collect()[0]
        .get_metric()
        .iter()
        .map(|m| m.get_histogram().sample_count())
        .sum();
    assert_eq!(total, 1000);
}

#[test]
fn gauges_do_not_publish_a_false_overflow_aggregate_and_reset_releases_slots() {
    let budget = local_budget(3);
    let gauge =
        IntGaugeVec::with_budget(Opts::new("active", "test"), &["route"], budget.clone()).unwrap();
    gauge.with_label_values(&["a"]).set(7);
    gauge.with_label_values(&["b"]).set(8);
    gauge.with_label_values(&["c"]).set(999);
    assert_eq!(gauge.collect()[0].get_metric().len(), 2);
    assert!(
        !gauge.collect()[0]
            .get_metric()
            .iter()
            .any(|m| m.get_label()[0].value() == "overflow")
    );
    for _ in 0..1000 {
        gauge.reset();
        gauge.with_label_values(&["new"]).set(1);
        assert_eq!(gauge.collect()[0].get_metric().len(), 1);
        assert_eq!(budget.used.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn concurrent_first_use_and_invalid_labels_cannot_bypass_admission() {
    let budget = local_budget(64);
    let counter = IntCounterVec::with_budget(
        Opts::new("concurrent_total", "test"),
        &["a", "b"],
        budget.clone(),
    )
    .unwrap();
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let counter = &counter;
            scope.spawn(move || {
                for i in 0..1000 {
                    counter
                        .with_label_values(&[&worker.to_string(), &i.to_string()])
                        .inc();
                }
            });
        }
    });
    counter
        .with_label_values(&[&"x".repeat(1_000_000), "b"])
        .inc();
    counter.with_label_values(&[]).inc();
    assert_eq!(budget.used.load(Ordering::Relaxed), 64);
    assert_eq!(counter.collect()[0].get_metric().len(), 64);
    assert_eq!(
        counter.collect()[0]
            .get_metric()
            .iter()
            .map(|m| m.get_counter().get_or_default().value())
            .sum::<f64>(),
        8002.0
    );
}

#[test]
fn label_tuple_keys_cannot_alias_and_family_cannot_starve_every_other_family() {
    let budget = local_budget(10_000);
    let counter = IntCounterVec::with_budget(
        Opts::new("tuple_total", "test"),
        &["a", "b"],
        budget.clone(),
    )
    .unwrap();
    counter.with_label_values(&["a", "bc"]).inc_by(3);
    counter.with_label_values(&["ab", "c"]).inc_by(5);
    assert_eq!(counter.with_label_values(&["a", "bc"]).get(), 3);
    assert_eq!(counter.with_label_values(&["ab", "c"]).get(), 5);
    for i in 0..10000 {
        counter.with_label_values(&[&i.to_string(), ""]).inc();
    }
    assert_eq!(budget.used.load(Ordering::Relaxed), FAMILY_LIMIT);
}

#[test]
fn reserved_overflow_labels_never_create_duplicate_exported_samples() {
    let counter = IntCounterVec::with_budget(
        Opts::new("reserved_total", "test"),
        &["a", "b"],
        local_budget(10),
    )
    .unwrap();
    counter.with_label_values(&["overflow", "overflow"]).inc();
    assert_eq!(counter.collect()[0].get_metric().len(), 1);
    assert_eq!(counter.overflow.get(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn full_registry_churn_has_bounded_resident_growth() {
    if std::env::var_os("FLUXHEIM_METRICS_RSS_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "metrics::bounded::tests::full_registry_churn_has_bounded_resident_growth",
                "--nocapture",
            ])
            .env("FLUXHEIM_METRICS_RSS_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let rss = || {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap()
            * 1024
    };
    let before = rss();
    let budget = local_budget(VECTOR_LIMIT);
    let counters: Vec<_> = (0..10)
        .map(|i| {
            IntCounterVec::with_budget(
                Opts::new(format!("rss_{i}_total"), "test"),
                &["resource"],
                budget.clone(),
            )
            .unwrap()
        })
        .collect();
    for generation in 0..2500 {
        for counter in &counters {
            counter
                .with_label_values(&[&format!("{generation:0128}")])
                .inc();
        }
    }
    let warm = rss();
    for generation in 2500..100_000 {
        for counter in &counters {
            counter
                .with_label_values(&[&format!("{generation:0128}")])
                .inc();
        }
    }
    let after = rss();
    println!(
        "metrics RSS bytes: before={before} warm={warm} after={after}; budget={}",
        budget.used.load(Ordering::Relaxed)
    );
    assert_eq!(budget.used.load(Ordering::Relaxed), VECTOR_LIMIT);
    assert!(after.saturating_sub(before) < 64 * 1024 * 1024);
    assert!(after.saturating_sub(warm) < 8 * 1024 * 1024);
}
