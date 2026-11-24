use super::*;
use sha2::{Digest, Sha256};

const CLAIM_TMP: &str = ".claim.tmp";
const HASH_BYTES: usize = 32;

pub(super) fn publish(
    dir: &Path,
    index: usize,
    name: &str,
    data: &[u8],
    owner: ops::ManagedCertificateOwner,
) -> io::Result<()> {
    let claim = dir.join(format!(".claim-{index}"));
    let dest = dir.join(name);
    for path in [&claim, &dest] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
    }
    let mut receipt = Sha256::digest(data).to_vec();
    receipt.extend_from_slice(name.as_bytes());
    write_private(dir, CLAIM_TMP, &receipt, owner)?;
    fs::rename(dir.join(CLAIM_TMP), claim)?;
    sync_directory_io(dir)?;
    write_private(dir, TMP, data, owner)?;
    fs::rename(dir.join(TMP), dest)?;
    sync_directory_io(dir)
}

fn unlink_regular(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && !ops::certificate_metadata_is_link(&m) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(io::ErrorKind::InvalidData.into()),
        Err(e) => Err(e),
    }
}

fn open_present(path: &Path) -> io::Result<Option<fs::File>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Ok(m) if m.is_file() && !ops::certificate_metadata_is_link(&m) => {
            fluxheim_config::fs_trust::open_confidential_file(path).map(Some)
        }
        Ok(_) => Err(io::ErrorKind::InvalidData.into()),
        Err(e) => Err(e),
    }
}

fn retire_file(dir: &Path, index: usize, kind: Kind) -> io::Result<()> {
    let claim = dir.join(format!(".claim-{index}"));
    let Some(file) = open_present(&claim)? else {
        return Ok(());
    };
    let mut row = Vec::new();
    file.take((HASH_BYTES + MAX_HTTP_01_TOKEN_BYTES + 1) as u64)
        .read_to_end(&mut row)?;
    let (digest, name) = row
        .split_at_checked(HASH_BYTES)
        .ok_or(io::ErrorKind::InvalidData)?;
    let name = std::str::from_utf8(name).map_err(|_| io::ErrorKind::InvalidData)?;
    let max = match kind {
        Kind::Http if valid_http_01_token(name) => MAX_HTTP_01_KEY_AUTHORIZATION_BYTES as usize,
        Kind::Alpn if index == 0 && name == MANAGED_FULLCHAIN_FILE => MAX_CERTIFICATE_CHAIN_BYTES,
        Kind::Alpn if index == 1 && name == MANAGED_PRIVATE_KEY_FILE => MAX_PRIVATE_KEY_BYTES,
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    let path = dir.join(name);
    if let Some(mut file) = open_present(&path)? {
        let size =
            usize::try_from(file.metadata()?.len()).map_err(|_| io::ErrorKind::InvalidData)?;
        if size > max {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut contents = SecretVec::from_fn(size, |_| 0);
        contents.with_secret_mut(|buf| file.read_exact(buf))?;
        if file.read(&mut [0])? != 0
            || !contents.with_secret(|buf| &Sha256::digest(buf)[..] == digest)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        drop(file);
        fs::remove_file(path)?;
    }
    fs::remove_file(claim)
}

pub(super) fn clear(dir: &Path, kind: Kind) -> io::Result<()> {
    let mut first = None;
    let limit = match kind {
        Kind::Http => MAX,
        Kind::Alpn => 2,
    };
    for index in 0..limit {
        if let Err(e) = retire_file(dir, index, kind) {
            first.get_or_insert(e);
        }
    }
    for name in [LEASE, TMP, CLAIM_TMP] {
        if let Err(e) = unlink_regular(&dir.join(name)) {
            first.get_or_insert(e);
        }
    }
    if let Some(e) = first {
        return Err(e);
    }
    // An unclaimed file is not ours. Keep it quarantined for inspection.
    fs::remove_dir(dir)
}
