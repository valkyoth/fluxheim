use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::fs::MetadataExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::validated_name_wide;

#[derive(Clone, Copy)]
pub(super) enum RequiredPathType {
    Any,
    Directory,
    RegularFile,
}

pub(super) fn create_relative_private_directory(
    parent: &File,
    name: &OsStr,
    security_descriptor: *const SECURITY_DESCRIPTOR,
) -> io::Result<File> {
    open_relative_component_with_security(
        parent,
        name,
        RequiredPathType::Directory,
        FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE,
        FILE_CREATE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        security_descriptor,
    )
}

pub(super) fn open_relative_component(
    parent: &File,
    name: &OsStr,
    required_type: RequiredPathType,
    desired_access: u32,
    disposition: u32,
    share_mode: u32,
) -> io::Result<File> {
    open_relative_component_with_security(
        parent,
        name,
        required_type,
        desired_access,
        disposition,
        share_mode,
        std::ptr::null(),
    )
}

fn open_relative_component_with_security(
    parent: &File,
    name: &OsStr,
    required_type: RequiredPathType,
    desired_access: u32,
    disposition: u32,
    share_mode: u32,
    security_descriptor: *const SECURITY_DESCRIPTOR,
) -> io::Result<File> {
    let mut wide = validated_name_wide(name)?;
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
        SecurityDescriptor: security_descriptor,
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = std::ptr::null_mut();
    let create_options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | match required_type {
            RequiredPathType::Any => 0,
            RequiredPathType::Directory => FILE_DIRECTORY_FILE,
            RequiredPathType::RegularFile => FILE_NON_DIRECTORY_FILE,
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
            share_mode,
            disposition,
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
        || matches!(required_type, RequiredPathType::RegularFile) && !metadata.is_file()
        || matches!(required_type, RequiredPathType::Directory) && !metadata.is_dir()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relative path component is a reparse point or has the wrong type",
        ));
    }
    Ok(file)
}
