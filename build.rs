fn main() {
    emit_version_metadata();
    emit_windows_stack_reserve();

    let tls_backends = [
        ("tls-rustls", "CARGO_FEATURE_TLS_RUSTLS"),
        ("tls-openssl", "CARGO_FEATURE_TLS_OPENSSL"),
        ("tls-boringssl", "CARGO_FEATURE_TLS_BORINGSSL"),
        ("tls-s2n", "CARGO_FEATURE_TLS_S2N"),
    ]
    .into_iter()
    .filter_map(|(name, env)| std::env::var_os(env).map(|_| name))
    .collect::<Vec<_>>();

    if tls_backends.len() > 1 {
        fail(&format!(
            "select only one Fluxheim TLS backend feature: tls-rustls, tls-openssl, tls-boringssl, or tls-s2n; selected {}",
            tls_backends.join(", ")
        ));
    }

    let privacy_mode = std::env::var_os("CARGO_FEATURE_PRIVACY_MODE").is_some();
    if privacy_mode && std::env::var_os("CARGO_FEATURE_CACHE").is_some() {
        fail(
            "privacy-mode cannot be combined with the cache feature; build with --no-default-features --features profile-privacy or select proxy,web,tls-*,privacy-mode explicitly",
        );
    }

    if privacy_mode && std::env::var_os("CARGO_FEATURE_METRICS").is_some() {
        fail(
            "privacy-mode cannot be combined with metrics; zero-retention builds must not compile request metrics",
        );
    }
}

fn emit_windows_stack_reserve() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        // Windows defaults PE executables to a 1 MiB main-thread stack. Full config
        // validation constructs the native router and requires Linux/macOS-equivalent headroom.
        println!("cargo:rustc-link-arg-bins=/STACK:8388608");
    }
}

fn emit_version_metadata() {
    println!("cargo:rerun-if-env-changed=FLUXHEIM_BUILD_ID");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let package_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into());
    let build_id = std::env::var("FLUXHEIM_BUILD_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| git_build_id(&package_version).unwrap_or_default());
    let version = if build_id.is_empty() {
        package_version
    } else {
        format!("{package_version} ({build_id})")
    };

    println!("cargo:rustc-env=FLUXHEIM_VERSION={version}");
}

fn git_build_id(package_version: &str) -> Option<String> {
    let dirty = git_dirty();
    let exact_tag = git_output(["describe", "--tags", "--exact-match", "HEAD"]);
    if exact_tag.as_deref() == Some(&format!("v{package_version}")) && !dirty {
        return None;
    }

    let commit = git_output(["rev-parse", "--short=8", "HEAD"])?;
    let branch = git_output(["rev-parse", "--abbrev-ref", "HEAD"])
        .filter(|branch| branch != "HEAD")
        .or_else(|| git_output(["describe", "--tags", "--always", "HEAD"]))
        .unwrap_or_else(|| "detached".to_owned());
    let mut build_id = format!("{}-g{}", sanitize_build_id_segment(&branch), commit);
    if dirty {
        build_id.push_str("-dirty");
    }
    Some(build_id)
}

fn git_dirty() -> bool {
    std::process::Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .status()
        .map(|status| !status.success())
        .unwrap_or(false)
}

fn git_output<const N: usize>(args: [&str; N]) -> Option<String> {
    let output = std::process::Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn sanitize_build_id_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
