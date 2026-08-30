#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Component, Path};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// Opens a regular file beneath `root` without following a reparse point in
/// any relative path component. Every directory handle remains live until its
/// child has been opened, so a rename cannot redirect subsequent traversal.
pub fn open_regular_file_beneath(root: &Path, relative: &Path) -> io::Result<File> {
    let components = validated_relative_components(relative)?;
    let mut directory = open_root_directory(root)?;

    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let opened = open_relative_component(&directory, component, final_component)?;
        if final_component {
            return Ok(opened);
        }
        directory = opened;
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "relative path is empty",
    ))
}

fn validated_relative_components(relative: &Path) -> io::Result<Vec<&OsStr>> {
    let mut components = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path must contain only relative normal components",
            ));
        };
        let wide = name.encode_wide().collect::<Vec<_>>();
        if wide.is_empty()
            || wide.iter().any(|unit| {
                *unit == 0
                    || *unit == u16::from(b'/')
                    || *unit == u16::from(b'\\')
                    || *unit == u16::from(b':')
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path component contains a forbidden Windows character",
            ));
        }
        components.push(name);
    }
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path is empty",
        ));
    }
    Ok(components)
}

fn open_root_directory(root: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(
            windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
    let directory = options.open(root)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root is a reparse point or is not a directory",
        ));
    }
    Ok(directory)
}

fn open_relative_component(parent: &File, name: &OsStr, regular_file: bool) -> io::Result<File> {
    let mut wide = name.encode_wide().collect::<Vec<_>>();
    let byte_len = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path component is too long"))?;
    let name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>()).unwrap_or(u32::MAX),
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = std::ptr::null_mut();
    let desired_access = FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if regular_file {
            FILE_READ_DATA
        } else {
            FILE_LIST_DIRECTORY
        };
    let create_options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if regular_file {
            FILE_NON_DIRECTORY_FILE
        } else {
            FILE_DIRECTORY_FILE
        };

    // SAFETY: all pointers reference live, correctly initialized values for
    // the duration of the call. `RootDirectory` is a live owned file handle,
    // and a successful returned handle is transferred exactly once to `File`.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &attributes,
            &mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            create_options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: the conversion function has no pointer arguments and accepts
        // the NTSTATUS returned directly by `NtCreateFile`.
        let error = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    if handle.is_null() {
        return Err(io::Error::other(
            "NtCreateFile succeeded without returning a handle",
        ));
    }

    // SAFETY: successful `NtCreateFile` returned a new owned HANDLE. `File`
    // assumes sole ownership and closes it once.
    let file = unsafe { File::from_raw_handle(handle) };
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (regular_file && !metadata.is_file())
        || (!regular_file && !metadata.is_dir())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relative path component is a reparse point or has the wrong type",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
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
    fn rejects_directory_junction_component() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"outside").unwrap();
        let junction = root.path().join("junction");
        let command = format!(
            "mklink /J \"{}\" \"{}\"",
            junction.display(),
            outside.path().display()
        );
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", &command])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "failed to create test directory junction");

        let result = open_regular_file_beneath(root.path(), Path::new("junction/secret.txt"));
        std::fs::remove_dir(&junction).unwrap();

        assert!(result.is_err(), "directory junction traversal was accepted");
    }
}
