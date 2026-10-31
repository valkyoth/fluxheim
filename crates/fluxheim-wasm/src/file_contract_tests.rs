use super::*;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const CHILD_TEST: &str = "file::contract_tests::wasm_fifo_loader_child";
const ROOT_ENV: &str = "FLUXHEIM_WASM_FIFO_TEST_ROOT";

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn wasm_fifo_loader_child() {
    let Some(root) = std::env::var_os(ROOT_ENV) else {
        return;
    };
    let root = PathBuf::from(root);
    let plugin = root.join("plugin.wasm");
    let error = load_plugin_file(
        &plugin,
        std::slice::from_ref(&root),
        WasmSandboxLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        WasmPluginError::UnsafePath {
            message: "plugin handle must be a regular file",
            ..
        }
    ));
    assert!(matches!(
        validate_plugin_path(&plugin, std::slice::from_ref(&root)),
        Err(WasmPluginError::UnsafePath { .. })
    ));

    fs::remove_file(&plugin).unwrap();
    let bytes = b"\0asm\x01\0\0\0";
    fs::write(&plugin, bytes).unwrap();
    let canonical = plugin.canonicalize().unwrap();
    validate_plugin_path(&plugin, std::slice::from_ref(&root)).unwrap();

    // Exercise the open helper after deterministic leaf replacement. This is
    // an open-window test, not a scheduler-dependent public-loader race test.
    fs::remove_file(&plugin).unwrap();
    make_fifo(&plugin);
    assert!(matches!(
        open_plugin_file(&canonical, &plugin),
        Err(WasmPluginError::UnsafePath { .. })
    ));
    fs::remove_file(&plugin).unwrap();
    let target = root.join("other.wasm");
    fs::write(&target, bytes).unwrap();
    std::os::unix::fs::symlink(&target, &plugin).unwrap();
    assert!(open_plugin_file(&canonical, &plugin).is_err());

    fs::remove_file(&plugin).unwrap();
    fs::write(&plugin, bytes).unwrap();
    let loaded = load_plugin_file(&plugin, &[root], WasmSandboxLimits::default()).unwrap();
    assert_eq!(loaded.bytes(), bytes);
    assert_eq!(loaded.sha256_hex(), sha256_hex(bytes));
}

fn make_fifo(path: &Path) {
    use std::os::unix::fs::FileTypeExt as _;

    #[cfg(not(target_os = "macos"))]
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    #[cfg(target_os = "macos")]
    assert!(
        Command::new("/usr/bin/mkfifo")
            .args(["-m", "600"])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_fifo());
}

#[test]
fn wasm_fifo_is_rejected_without_a_writer_and_repaired_file_loads() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    make_fifo(&root.join("plugin.wasm"));
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST])
        .env(ROOT_ENV, &root)
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "child did not reject the special file");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "loader did not finish without a FIFO writer"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
