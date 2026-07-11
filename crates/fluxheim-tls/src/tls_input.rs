use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sanitization::{SecretVec, sanitize_bytes};

pub(crate) const MAX_CERT_CHAIN_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_CA_BUNDLE_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_CHAIN_CERTIFICATES: usize = 16;
pub(crate) const MAX_CA_CERTIFICATES: usize = 4096;

pub(crate) fn read_bounded_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let (mut file, admitted) = open_admitted_file(path, maximum)?;
    let mut contents = Vec::new();
    contents.try_reserve_exact(admitted).map_err(|error| {
        io::Error::other(format!("failed to reserve bounded TLS input: {error}"))
    })?;
    contents.resize(admitted, 0);
    file.read_exact(&mut contents)?;
    reject_reader_growth(&mut file)?;
    Ok(contents)
}

pub(crate) fn read_bounded_secret(path: &Path, maximum: u64) -> io::Result<SecretVec> {
    let (mut file, admitted) = open_admitted_file(path, maximum)?;
    read_admitted_secret(&mut file, admitted)
}

fn open_admitted_file(path: &Path, maximum: u64) -> io::Result<(File, usize)> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS input is not a regular file",
        ));
    }
    if metadata.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS input exceeds its permitted size",
        ));
    }
    let admitted = usize::try_from(metadata.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS input size does not fit this platform",
        )
    })?;
    Ok((file, admitted))
}

fn read_admitted_secret(reader: &mut impl Read, admitted: usize) -> io::Result<SecretVec> {
    let mut contents = SecretVec::from_fn(admitted, |_| 0);
    contents.with_secret_mut(|bytes| reader.read_exact(bytes))?;
    reject_reader_growth(reader)?;
    Ok(contents)
}

fn reject_reader_growth(reader: &mut impl Read) -> io::Result<()> {
    let mut growth_probe = [0_u8; 1];
    let read_result = reader.read(&mut growth_probe);
    sanitize_bytes(&mut growth_probe);
    if read_result? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS input grew beyond its admitted size",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Error, Seek, SeekFrom, Write};

    use super::*;

    #[test]
    fn bounded_tls_input_rejects_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.pem");
        std::fs::write(&path, [0_u8; 9]).unwrap();

        let error = read_bounded_file(&path, 8).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn bounded_tls_input_reads_exact_admitted_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.pem");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"certificate").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        assert_eq!(read_bounded_file(&path, 32).unwrap(), b"certificate");
    }

    #[test]
    fn bounded_secret_rejects_growth_after_admitted_bytes() {
        let mut reader = Cursor::new(b"secret-extra".as_slice());

        let error = read_admitted_secret(&mut reader, 6).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn bounded_secret_drops_protected_partial_read_on_error() {
        struct FailingReader {
            emitted: bool,
        }

        impl Read for FailingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.emitted {
                    return Err(Error::other("injected read failure"));
                }
                self.emitted = true;
                buffer[..3].copy_from_slice(b"key");
                Ok(3)
            }
        }

        let error = read_admitted_secret(&mut FailingReader { emitted: false }, 6).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
    }
}
