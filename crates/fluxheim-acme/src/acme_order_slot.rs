use super::*;
use acme_certificate_install::fs_ops as ops;
use fluxheim_config::acme_publication::{ACTIVE_DIR, LEASE, ORDER_DIR};

pub(super) const MAX: usize = fluxheim_config::config_acme::MAX_VHOST_ACME_DOMAINS;
const RETIRED: &str = "retired";
const TMP: &str = ".pending";

#[path = "acme_order_receipt.rs"]
mod receipt;

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Http,
    Alpn,
}

pub(super) struct Slot {
    root: PathBuf,
    kind: Kind,
    owner: ops::ManagedCertificateOwnership,
    _exclusive: AcmeMutationLock,
    live: Option<AcmeMutationLock>,
    count: usize,
}

fn directory(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !ops::certificate_metadata_is_link(&m) => Ok(true),
        Ok(_) => Err(io::ErrorKind::InvalidData.into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn write_private(
    dir: &Path,
    name: &str,
    data: &[u8],
    owner: ops::ManagedCertificateOwner,
) -> io::Result<()> {
    #[cfg(unix)]
    let fd = crate::acme_directory::open_directory_no_symlinks(dir)?;
    #[cfg(unix)]
    let fd = Some(&fd);
    #[cfg(not(unix))]
    let fd = None;
    ops::write_new_file(dir, &dir.join(name), data, 0o600, owner, fd).map_err(io::Error::other)
}

fn lease(dir: &Path, owner: ops::ManagedCertificateOwner) -> io::Result<Option<AcmeMutationLock>> {
    let path = dir.join(LEASE);
    if !path.try_exists()? {
        // A concurrent creator may win the exclusive create.
        if let Err(e) = write_private(dir, LEASE, b"", owner)
            && !path.try_exists()?
        {
            return Err(e);
        }
    }
    let file = fluxheim_config::fs_trust::open_regular_file(&path)?;
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    drop(file);
    AcmeMutationLock::try_acquire(dir)
}

impl Slot {
    pub(super) fn open(
        storage: &Path,
        parent: &Path,
        kind: Kind,
        create: bool,
    ) -> io::Result<Option<Self>> {
        let root = parent.join(ORDER_DIR);
        if !create && !directory(&root)? {
            return Ok(None);
        }
        let owner = ops::managed_certificate_ownership(storage).map_err(io::Error::other)?;
        ops::ensure_safe_directory(&root, &owner).map_err(io::Error::other)?;
        let Some(exclusive) = lease(&root, owner.file_owner())? else {
            return Ok(None);
        };
        let slot = Self {
            root,
            kind,
            owner,
            _exclusive: exclusive,
            live: None,
            count: 0,
        };
        slot.retire()?;
        if create {
            ops::ensure_safe_directory(&slot.active(), &slot.owner).map_err(io::Error::other)?;
        }
        Ok(Some(slot))
    }

    fn active(&self) -> PathBuf {
        self.root.join(ACTIVE_DIR)
    }

    fn activate(&mut self) -> io::Result<()> {
        if self.live.is_none() {
            self.live = Some(
                lease(&self.active(), self.owner.file_owner())?.ok_or(io::ErrorKind::WouldBlock)?,
            );
        }
        Ok(())
    }

    pub(super) fn publish_http(&mut self, token: &str, value: &str) -> io::Result<()> {
        if !valid_http_01_token(token)
            || !valid_http_01_key_authorization(value)
            || self.count >= MAX
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let active = self.active();
        receipt::publish(
            &active,
            self.count,
            token,
            value.trim_end_matches(['\r', '\n']).as_bytes(),
            self.owner.file_owner(),
        )?;
        self.count += 1;
        self.activate()
    }

    #[cfg(all(test, feature = "acme-client"))]
    pub(super) fn publish_pair(&mut self, domain: &str, cert: &[u8], key: &[u8]) -> io::Result<()> {
        validate_issued_material(cert, key, &[normalized_domain(domain)])
            .map_err(io::Error::other)?;
        let active = self.active();
        receipt::publish(
            &active,
            0,
            MANAGED_FULLCHAIN_FILE,
            cert,
            self.owner.file_owner(),
        )?;
        receipt::publish(
            &active,
            1,
            MANAGED_PRIVATE_KEY_FILE,
            key,
            self.owner.file_owner(),
        )?;
        self.activate()
    }

    pub(super) fn deactivate(&mut self) {
        self.live.take();
    }

    pub(super) fn retire(&self) -> io::Result<()> {
        let retired = self.root.join(RETIRED);
        if directory(&retired)? {
            self.clear_retired(&retired)?;
        }
        let active = self.active();
        if directory(&active)? {
            fs::rename(active, &retired)?;
            sync_directory_io(&self.root)?;
            self.clear_retired(&retired)?;
        }
        Ok(())
    }

    fn clear_retired(&self, path: &Path) -> io::Result<()> {
        receipt::clear(path, self.kind)?;
        sync_directory_io(&self.root)
    }
}
