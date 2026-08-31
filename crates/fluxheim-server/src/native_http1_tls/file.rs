use std::io;
use std::path::Path;

use crate::NativeHttp1Error;

const MAX_UPSTREAM_TLS_FILE_BYTES: u64 = 1024 * 1024;

#[cfg(target_os = "linux")]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit native upstream TLS file opening before building Fluxheim"
);

pub(super) fn read_upstream_tls_file(path: &Path) -> Result<Vec<u8>, NativeHttp1Error> {
    read_upstream_tls_input(path, false)
}

pub(super) fn read_upstream_tls_secret_file(path: &Path) -> Result<Vec<u8>, NativeHttp1Error> {
    read_upstream_tls_input(path, true)
}

fn read_upstream_tls_input(path: &Path, confidential: bool) -> Result<Vec<u8>, NativeHttp1Error> {
    let safe_path = canonical_upstream_tls_file_path(path)?;
    let metadata = std::fs::symlink_metadata(&safe_path).map_err(NativeHttp1Error::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        )));
    }

    #[cfg(windows)]
    let file = if confidential {
        fluxheim_config::fs_trust::open_confidential_file(&safe_path)
            .map_err(NativeHttp1Error::Io)?
    } else {
        fluxheim_config::fs_trust::open_regular_file(&safe_path).map_err(NativeHttp1Error::Io)?
    };
    #[cfg(not(windows))]
    let file = {
        let _ = confidential;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(UPSTREAM_TLS_O_NOFOLLOW);
        }
        options.open(&safe_path).map_err(NativeHttp1Error::Io)?
    };
    let metadata = file.metadata().map_err(NativeHttp1Error::Io)?;
    if !metadata.is_file() {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        )));
    }
    if metadata.len() > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        )));
    }

    let mut contents = Vec::new();
    let mut limited = std::io::Read::take(file, MAX_UPSTREAM_TLS_FILE_BYTES.saturating_add(1));
    std::io::Read::read_to_end(&mut limited, &mut contents).map_err(NativeHttp1Error::Io)?;
    if contents.len() as u64 > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        )));
    }
    Ok(contents)
}

fn canonical_upstream_tls_file_path(path: &Path) -> Result<std::path::PathBuf, NativeHttp1Error> {
    let file_name = path.file_name().ok_or_else(|| {
        NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("upstream TLS path has no file name: {}", path.display()),
        ))
    })?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let canonical_parent = std::fs::canonicalize(parent).map_err(NativeHttp1Error::Io)?;
    Ok(canonical_parent.join(file_name))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NATIVE_HTTP1_TLS_TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let sequence = NATIVE_HTTP1_TLS_TEST_DIR_COUNTER.fetch_add(1, Ordering::AcqRel);
        let base = std::path::PathBuf::from("target/fluxheim-native-http1-tls-tests");
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join(format!(
            "fluxheim-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn upstream_tls_file_reader_rejects_oversized_files() {
        let directory = unique_temp_dir("native-upstream-tls-large");
        let path = directory.join("ca.pem");
        std::fs::write(
            &path,
            vec![b'a'; MAX_UPSTREAM_TLS_FILE_BYTES.saturating_add(1) as usize],
        )
        .unwrap();

        let error = read_upstream_tls_file(&path).unwrap_err();

        assert!(
            matches!(&error, NativeHttp1Error::Io(error) if error.kind() == io::ErrorKind::InvalidData),
            "unexpected error: {error:?}"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn upstream_tls_file_reader_rejects_final_symlink() {
        use std::os::unix::fs::symlink;

        let directory = unique_temp_dir("native-upstream-tls-symlink");
        let target = directory.join("target.pem");
        let link = directory.join("linked.pem");
        std::fs::write(&target, b"not a real certificate").unwrap();
        symlink(&target, &link).unwrap();

        let error = read_upstream_tls_file(&link).unwrap_err();

        assert!(
            matches!(&error, NativeHttp1Error::Io(error) if error.kind() == io::ErrorKind::InvalidInput),
            "unexpected error: {error:?}"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
