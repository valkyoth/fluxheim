use super::*;

#[test]
fn private_unix_listener_replaces_socket_and_rejects_files() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    let test_dir = unique_short_temp_dir();
    std::fs::create_dir_all(&test_dir).unwrap();
    let socket_path = test_dir.join("reload.sock");

    let first = replace_private_unix_listener(&socket_path).unwrap();
    let metadata = std::fs::symlink_metadata(&socket_path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let second = replace_private_unix_listener(&socket_path).unwrap();
    drop(first);
    drop(second);

    let file_path = test_dir.join("not-a-socket");
    std::fs::write(&file_path, b"nope").unwrap();
    let error = match replace_private_unix_listener(&file_path) {
        Ok(listener) => {
            drop(listener);
            panic!("non-socket path accepted")
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);

    std::fs::remove_dir_all(&test_dir).unwrap();
}

fn unique_short_temp_dir() -> std::path::PathBuf {
    let unique = format!(
        "fh-srv-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::path::Path::new("/tmp").join(unique)
}
