//! Test-only re-execution within the compiler-selected Cargo output directory.

use std::io;
use std::path::Path;
use std::process::Command;

#[derive(Clone, Copy)]
pub enum TestBinary {
    Common,
    Server,
}

pub fn self_command(binary: TestBinary) -> io::Result<Command> {
    let profile = Path::new(env!("OUT_DIR"))
        .ancestors()
        .nth(3)
        .ok_or_else(invalid_executable)?;
    let directory = profile.join("deps").canonicalize()?;
    let executable = std::env::current_exe()?.canonicalize()?;
    checked_command(&directory, &executable, binary)
}

fn invalid_executable() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unexpected test executable",
    )
}

fn checked_command(directory: &Path, executable: &Path, binary: TestBinary) -> io::Result<Command> {
    let prefix = match binary {
        TestBinary::Common => "fluxheim_common-",
        TestBinary::Server => "fluxheim-",
    };
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid_executable)?;
    let hash = name
        .strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(std::env::consts::EXE_SUFFIX))
        .ok_or_else(invalid_executable)?;
    if hash.len() != 16 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_executable());
    }
    // Exact comparison against the trusted build directory and a closed crate
    // name + Cargo hash. Never invoke argv[0], PATH or a caller-provided program.
    let expected = directory.join(format!("{prefix}{hash}{}", std::env::consts::EXE_SUFFIX));
    if executable != expected {
        return Err(invalid_executable());
    }
    Ok(Command::new(executable))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_common_test_binary_is_allowed() {
        assert!(self_command(TestBinary::Common).is_ok());
        assert!(self_command(TestBinary::Server).is_err());
    }

    #[test]
    fn rejects_other_directories_crates_and_malformed_hashes() {
        let root = Path::new("trusted").join("deps");
        let name = format!("fluxheim-0123456789abcdef{}", std::env::consts::EXE_SUFFIX);
        assert!(checked_command(&root, &root.join(&name), TestBinary::Server).is_ok());
        for path in [
            Path::new("outside").join(&name),
            root.join("..").join(&name),
            root.join("nested").join(&name),
            root.join("sh"),
            root.join("fluxheim-$(command)"),
            root.join("fluxheim-0123456789abcdeg"),
            root.join("fluxheim_common-0123456789abcdef"),
        ] {
            assert!(
                checked_command(&root, &path, TestBinary::Server).is_err(),
                "{path:?}"
            );
        }
    }
}
