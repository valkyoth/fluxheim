use std::io::Read as _;

use super::*;

#[test]
fn rejects_non_relative_components_before_native_open() {
    assert!(validated_relative_components(Path::new("../outside")).is_err());
    assert!(validated_relative_components(Path::new("file:stream")).is_err());
    assert!(validated_relative_components(Path::new("")).is_err());
}

#[test]
fn opens_nested_regular_file_relative_to_retained_directories() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("nested")).unwrap();
    std::fs::write(root.path().join("nested").join("asset.txt"), b"asset").unwrap();

    let mut file = open_regular_file_beneath(root.path(), Path::new("nested/asset.txt"))
        .expect("handle-relative open should succeed");
    let mut body = String::new();
    file.read_to_string(&mut body).unwrap();

    assert_eq!(body, "asset");
}

#[test]
fn absolute_create_rename_open_and_remove_stay_handle_relative() {
    use std::io::Write as _;

    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    assert!(
        root.as_os_str().to_string_lossy().starts_with(r"\\?\"),
        "Windows canonical paths must exercise verbatim path handling"
    );
    let source = root.join("source.bin");
    let destination = root.join("destination.bin");
    let mut created = create_new_regular_file(&source, true).unwrap();
    created.write_all(b"state").unwrap();
    drop(created);

    rename_regular_file(&source, &destination).unwrap();
    assert!(!source.exists());
    let mut opened = open_existing_regular_file(&destination, false).unwrap();
    let mut contents = Vec::new();
    opened.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"state");
    drop(opened);

    remove_regular_file(&destination).unwrap();
    assert!(!destination.exists());
}

#[test]
fn hard_link_is_created_from_the_retained_source_handle() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source.bin");
    let destination = root.path().join("linked.bin");
    std::fs::write(&source, b"state").unwrap();

    create_hard_link_regular_file(&source, &destination).unwrap();

    assert_eq!(std::fs::read(destination).unwrap(), b"state");
}

#[test]
fn private_directory_is_created_with_a_protected_acl() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("private");

    create_private_directory(&directory).unwrap();

    let descriptor = windows_permissions::wrappers::GetNamedSecurityInfo(
        &directory,
        windows_permissions::constants::SeObjectType::SE_FILE_OBJECT,
        windows_permissions::constants::SecurityInformation::Dacl,
    )
    .unwrap();
    assert!(
        descriptor
            .as_sddl()
            .unwrap()
            .to_string_lossy()
            .contains("D:P")
    );
}

#[test]
fn acl_update_opener_retains_parent_handles_and_requires_a_directory() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("nested");
    let file = root.path().join("file.txt");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(&file, b"not-a-directory").unwrap();

    let opened = open_existing_directory_for_acl_update(&nested)
        .expect("directory ACL-update open should succeed");
    assert!(opened.metadata().unwrap().is_dir());
    assert!(open_existing_directory_for_acl_update(&file).is_err());
}

#[test]
fn rejects_directory_junction_component() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"outside").unwrap();
    let junction = root.path().join("junction");
    let status = std::process::Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(dunce::simplified(&junction))
        .arg(dunce::simplified(outside.path()))
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "failed to create test directory junction");

    let result = open_regular_file_beneath(root.path(), Path::new("junction/secret.txt"));
    std::fs::remove_dir(&junction).unwrap();

    assert!(result.is_err(), "directory junction traversal was accepted");
}
