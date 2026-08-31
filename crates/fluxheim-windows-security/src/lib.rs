#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Component, Path, PathBuf};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_LINK_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileLinkInformation,
    NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
    RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_RENAME_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo, FileRenameInfo,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE, SetFileInformationByHandle,
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
        let opened = open_relative_component(
            &directory,
            component,
            final_component,
            if final_component {
                FILE_READ_ATTRIBUTES | FILE_READ_DATA | SYNCHRONIZE
            } else {
                FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE
            },
            FILE_OPEN,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
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

pub fn open_existing_regular_file(path: &Path, write: bool) -> io::Result<File> {
    open_absolute_regular_file(path, write, FILE_OPEN)
}

pub fn create_new_regular_file(path: &Path, read: bool) -> io::Result<File> {
    let access = GENERIC_WRITE | if read { GENERIC_READ } else { 0 };
    open_absolute_regular_file_with_access(path, access, FILE_CREATE)
}

pub fn open_or_create_regular_file(path: &Path) -> io::Result<File> {
    open_absolute_regular_file_with_access(path, GENERIC_READ | GENERIC_WRITE, FILE_OPEN_IF)
}

pub fn create_private_directory(path: &Path) -> io::Result<()> {
    let current = windows_permissions::utilities::current_process_sid()?;
    let descriptor: windows_permissions::LocalBox<windows_permissions::SecurityDescriptor> =
        format!("D:P(A;;FA;;;{current})(A;;FA;;;SY)(A;;FA;;;BA)").parse()?;
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.is_empty() || wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private directory path is empty or contains NUL",
        ));
    }
    wide.push(0);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor.as_ptr().cast(),
        bInheritHandle: 0,
    };
    // SAFETY: the path is NUL-terminated, and both the self-relative security
    // descriptor and its attributes remain live for the duration of the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn rename_regular_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source = open_absolute_regular_file_with_access(
        source,
        DELETE_ACCESS | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
    )?;
    let (destination_parent, destination_name) = open_absolute_parent(destination)?;
    let wide = validated_name_wide(&destination_name)?;
    let header_size = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let name_bytes = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename target is too long"))?;
    let buffer_size = header_size
        .checked_add(name_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename target is too long"))?;
    let mut buffer = aligned_native_buffer(buffer_size)?;
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `buffer` is sized for the fixed header plus the complete UTF-16
    // name. All writes stay within that allocation, and both handles remain
    // live through `SetFileInformationByHandle`.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = true;
        (*info).RootDirectory = destination_parent.as_raw_handle() as HANDLE;
        (*info).FileNameLength = u32::try_from(name_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "rename target is too long")
        })?;
        std::ptr::copy_nonoverlapping(wide.as_ptr(), (*info).FileName.as_mut_ptr(), wide.len());
        if SetFileInformationByHandle(
            source.as_raw_handle() as HANDLE,
            FileRenameInfo,
            info.cast(),
            u32::try_from(buffer_size).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "rename target is too long")
            })?,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn create_hard_link_regular_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source = open_absolute_regular_file_with_access(
        source,
        DELETE_ACCESS | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
    )?;
    let (destination_parent, destination_name) = open_absolute_parent(destination)?;
    let wide = validated_name_wide(&destination_name)?;
    let header_size = std::mem::offset_of!(FILE_LINK_INFORMATION, FileName);
    let name_bytes = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "link target is too long"))?;
    let buffer_size = header_size
        .checked_add(name_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "link target is too long"))?;
    let mut buffer = aligned_native_buffer(buffer_size)?;
    let info = buffer.as_mut_ptr().cast::<FILE_LINK_INFORMATION>();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `buffer` contains the complete variable-length link structure,
    // and both the source and destination-directory handles remain live.
    let status = unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = destination_parent.as_raw_handle() as HANDLE;
        (*info).FileNameLength = u32::try_from(name_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "link target is too long"))?;
        std::ptr::copy_nonoverlapping(wide.as_ptr(), (*info).FileName.as_mut_ptr(), wide.len());
        NtSetInformationFile(
            source.as_raw_handle() as HANDLE,
            &mut status_block,
            info.cast(),
            u32::try_from(buffer_size).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "link target is too long")
            })?,
            FileLinkInformation,
        )
    };
    if status < 0 {
        // SAFETY: this converts the NTSTATUS returned by the preceding call.
        let error = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok(())
}

pub fn remove_regular_file(path: &Path) -> io::Result<()> {
    let file = open_absolute_regular_file_with_access(
        path,
        DELETE_ACCESS | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
    )?;
    remove_open_regular_file(&file)
}

pub fn remove_open_regular_file(file: &File) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `disposition` is the exact structure required by
    // `FileDispositionInfo`, and `file` remains live for the call.
    let result = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(u32::MAX),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const DELETE_ACCESS: u32 = 0x0001_0000;

fn aligned_native_buffer(byte_len: usize) -> io::Result<Vec<usize>> {
    let word_size = std::mem::size_of::<usize>();
    let word_count = byte_len
        .checked_add(word_size - 1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "native buffer is too long"))?
        / word_size;
    Ok(vec![0; word_count])
}

fn open_absolute_regular_file(path: &Path, write: bool, disposition: u32) -> io::Result<File> {
    let access = GENERIC_READ | if write { GENERIC_WRITE } else { 0 };
    open_absolute_regular_file_with_access(path, access, disposition)
}

fn open_absolute_regular_file_with_access(
    path: &Path,
    access: u32,
    disposition: u32,
) -> io::Result<File> {
    let (parent, name) = open_absolute_parent(path)?;
    open_relative_component(
        &parent,
        &name,
        true,
        access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        disposition,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

fn open_absolute_parent(path: &Path) -> io::Result<(File, std::ffi::OsString)> {
    let (root, relative) = absolute_root_and_relative(path)?;
    let mut components = validated_relative_components(&relative)?;
    let name = components
        .pop()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_os_string();
    let mut directory = open_root_directory(&root)?;
    for component in components {
        directory = open_relative_component(
            &directory,
            component,
            false,
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE,
            FILE_OPEN,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
    }
    Ok((directory, name))
}

fn absolute_root_and_relative(path: &Path) -> io::Result<(PathBuf, PathBuf)> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secure Windows path must be absolute",
        ));
    }
    let mut root = PathBuf::new();
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => root.push(component.as_os_str()),
            Component::Normal(_) => relative.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "secure Windows path contains parent traversal",
                ));
            }
        }
    }
    if root.as_os_str().is_empty() || relative.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secure Windows path has no rooted file name",
        ));
    }
    Ok((root, relative))
}

fn validated_name_wide(name: &OsStr) -> io::Result<Vec<u16>> {
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
    Ok(wide)
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

fn open_relative_component(
    parent: &File,
    name: &OsStr,
    regular_file: bool,
    desired_access: u32,
    disposition: u32,
    share_mode: u32,
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
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = std::ptr::null_mut();
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
#[path = "windows_security_tests.rs"]
mod tests;
