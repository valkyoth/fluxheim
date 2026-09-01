use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_LINK_INFORMATION, FILE_OPEN, FILE_RENAME_INFORMATION, FileLinkInformation,
    FileRenameInformation, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{HANDLE, RtlNtStatusToDosError};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_DISPOSITION_INFO, FILE_READ_ATTRIBUTES, FileDispositionInfo,
    SYNCHRONIZE, SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::{
    DELETE_ACCESS, aligned_native_buffer, open_absolute_parent,
    open_absolute_regular_file_with_access, validated_name_wide,
};

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
    let header_size = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let name_bytes = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename target is too long"))?;
    let buffer_size = header_size
        .checked_add(name_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename target is too long"))?;
    let mut buffer = aligned_native_buffer(buffer_size)?;
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `buffer` is sized for the fixed header plus the complete UTF-16
    // name. All writes stay within that allocation, and both handles remain
    // live through `NtSetInformationFile`.
    let status = unsafe {
        (*info).Anonymous.ReplaceIfExists = true;
        (*info).RootDirectory = destination_parent.as_raw_handle() as HANDLE;
        (*info).FileNameLength = u32::try_from(name_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "rename target is too long")
        })?;
        std::ptr::copy_nonoverlapping(wide.as_ptr(), (*info).FileName.as_mut_ptr(), wide.len());
        NtSetInformationFile(
            source.as_raw_handle() as HANDLE,
            &mut status_block,
            info.cast(),
            u32::try_from(buffer_size).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "rename target is too long")
            })?,
            FileRenameInformation,
        )
    };
    if status < 0 {
        // SAFETY: this converts the NTSTATUS returned by the preceding call.
        let error = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(error as i32));
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
