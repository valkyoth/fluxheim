#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use windows_sys::Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN, FILE_OPEN_IF};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT, SYNCHRONIZE, WRITE_DAC,
};

mod file_mutation;
mod path_handles;
mod relative_open;
pub use file_mutation::{
    create_hard_link_regular_file, create_private_directory, remove_open_regular_file,
    remove_regular_file, rename_regular_file,
};
pub use path_handles::RetainedPathHandles;
use relative_open::{RequiredPathType, open_relative_component};

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
            if final_component {
                RequiredPathType::RegularFile
            } else {
                RequiredPathType::Directory
            },
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
    open_existing_regular_file_with_ancestors(path, write)?.into_target()
}

pub fn create_new_regular_file(path: &Path, read: bool) -> io::Result<File> {
    create_new_regular_file_with_ancestors(path, read)?.into_target()
}

pub fn create_new_regular_file_with_ancestors(
    path: &Path,
    read: bool,
) -> io::Result<RetainedPathHandles> {
    // The caller may reject the creation after inspecting the retained parent
    // handles. DELETE access makes that fail-closed rollback reliable.
    let access = GENERIC_WRITE | DELETE_ACCESS | if read { GENERIC_READ } else { 0 };
    open_absolute_regular_path(
        path,
        access,
        FILE_CREATE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

pub fn open_or_create_regular_file(path: &Path) -> io::Result<File> {
    open_absolute_regular_file_with_access(path, GENERIC_READ | GENERIC_WRITE, FILE_OPEN_IF)
}

pub fn inspect_absolute_path(path: &Path) -> io::Result<RetainedPathHandles> {
    open_absolute_path(
        path,
        RequiredPathType::Any,
        READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        true,
    )
}

pub fn open_existing_regular_file_with_ancestors(
    path: &Path,
    write: bool,
) -> io::Result<RetainedPathHandles> {
    let access = GENERIC_READ | READ_CONTROL | if write { GENERIC_WRITE } else { 0 };
    open_absolute_regular_path(
        path,
        access,
        FILE_OPEN,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

pub fn create_new_exclusive_regular_file_with_ancestors(
    path: &Path,
) -> io::Result<RetainedPathHandles> {
    open_absolute_regular_path(
        path,
        GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS | READ_CONTROL | WRITE_DAC,
        FILE_CREATE,
        0,
    )
}

/// Opens an existing directory for ACL inspection and replacement without
/// following a reparse point in any path component.
pub fn open_existing_directory_for_acl_update(path: &Path) -> io::Result<File> {
    open_existing_directory_with_ancestors(path, READ_CONTROL | WRITE_DAC)?.into_target()
}

pub fn open_existing_directory_for_sync(path: &Path) -> io::Result<RetainedPathHandles> {
    open_existing_directory_with_ancestors(path, GENERIC_WRITE | READ_CONTROL)
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

fn open_absolute_regular_file_with_access(
    path: &Path,
    access: u32,
    disposition: u32,
) -> io::Result<File> {
    open_absolute_regular_path(
        path,
        access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        disposition,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
    .and_then(RetainedPathHandles::into_target)
}

fn open_absolute_regular_path(
    path: &Path,
    access: u32,
    disposition: u32,
    share_mode: u32,
) -> io::Result<RetainedPathHandles> {
    let _ = absolute_root_and_relative(path)?;
    open_absolute_path(
        path,
        RequiredPathType::RegularFile,
        access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        disposition,
        share_mode,
        false,
    )
}

fn open_existing_directory_with_ancestors(
    path: &Path,
    target_access: u32,
) -> io::Result<RetainedPathHandles> {
    open_absolute_path(
        path,
        RequiredPathType::Directory,
        target_access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        false,
    )
}

fn open_absolute_path(
    path: &Path,
    target_type: RequiredPathType,
    target_access: u32,
    target_disposition: u32,
    target_share_mode: u32,
    allow_missing: bool,
) -> io::Result<RetainedPathHandles> {
    let (root, relative) = absolute_root_and_optional_relative(path)?;
    let mut handles = vec![open_root_directory(&root)?];
    if relative.as_os_str().is_empty() {
        return Ok(RetainedPathHandles {
            handles,
            target_exists: true,
        });
    }
    let components = validated_relative_components(&relative)?;
    if components.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secure Windows path exceeds component limit",
        ));
    }
    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let result = open_relative_component(
            handles
                .last()
                .ok_or_else(|| io::Error::other("retained path lost its parent handle"))?,
            component,
            if final_component {
                target_type
            } else {
                RequiredPathType::Directory
            },
            if final_component {
                target_access
            } else {
                READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE
            },
            if final_component {
                target_disposition
            } else {
                FILE_OPEN
            },
            if final_component {
                target_share_mode
            } else {
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            },
        );
        match result {
            Ok(handle) => handles.push(handle),
            Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => {
                return Ok(RetainedPathHandles {
                    handles,
                    target_exists: false,
                });
            }
            Err(error) => return Err(error),
        }
    }
    Ok(RetainedPathHandles {
        handles,
        target_exists: true,
    })
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
            RequiredPathType::Directory,
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE,
            FILE_OPEN,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
    }
    Ok((directory, name))
}

fn absolute_root_and_relative(path: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let (root, relative) = absolute_root_and_optional_relative(path)?;
    if relative.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secure Windows path has no rooted file name",
        ));
    }
    Ok((root, relative))
}

fn absolute_root_and_optional_relative(path: &Path) -> io::Result<(PathBuf, PathBuf)> {
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
    if root.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secure Windows path has no root",
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

#[cfg(test)]
#[path = "windows_security_tests.rs"]
mod tests;
