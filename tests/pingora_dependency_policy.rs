use std::collections::BTreeSet;

#[test]
fn pingora_dependency_exceptions_have_enforced_targets() {
    let current_version = env!("CARGO_PKG_VERSION");
    let packages = cargo_lock_packages(include_str!("../Cargo.lock"));
    let exceptions = include_str!("../docs/pingora-dependency-exceptions.tsv");
    let mut expired = BTreeSet::new();

    for (line_number, line) in exceptions.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert!(
            fields.len() >= 4,
            "malformed pingora dependency exception on line {}: {line}",
            line_number + 1
        );
        let profile = fields[0];
        let crate_name = fields[1];
        let removal_target = fields[2];
        assert!(
            parse_version(removal_target).is_some(),
            "invalid removal_target {removal_target:?} for {profile}/{crate_name}"
        );
        if packages.contains(crate_name) && version_at_or_after(current_version, removal_target) {
            expired.insert(format!("{profile}\t{crate_name}\t{removal_target}"));
        }
    }

    assert!(
        expired.is_empty(),
        "Pingora dependency exceptions expired while crates are still present in Cargo.lock for Fluxheim {current_version}:\n{}",
        expired.into_iter().collect::<Vec<_>>().join("\n")
    );
}

fn cargo_lock_packages(lock: &str) -> BTreeSet<&str> {
    let mut packages = BTreeSet::new();
    let mut in_package = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_package = true;
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(value) = line
            .strip_prefix("name = \"")
            .and_then(|value| value.strip_suffix('"'))
        {
            packages.insert(value);
            in_package = false;
        }
    }
    packages
}

fn version_at_or_after(current: &str, target: &str) -> bool {
    let Some(current) = parse_version(current) else {
        panic!("invalid current Fluxheim version: {current}");
    };
    let Some(target) = parse_version(target) else {
        panic!("invalid removal target version: {target}");
    };
    current >= target
}

fn parse_version(version: &str) -> Option<(u64, u64, u64)> {
    let version = version.strip_prefix('v').unwrap_or(version);
    let mut parts = version
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}
