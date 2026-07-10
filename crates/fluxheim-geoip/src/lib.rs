#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeoContext {
    country_iso: Option<String>,
    asn: Option<u32>,
}

impl GeoContext {
    pub fn new(country_iso: Option<String>, asn: Option<u32>) -> Self {
        Self { country_iso, asn }
    }

    pub fn country_iso(&self) -> Option<&str> {
        self.country_iso.as_deref()
    }

    pub fn asn(&self) -> Option<u32> {
        self.asn
    }

    pub fn is_empty(&self) -> bool {
        self.country_iso.is_none() && self.asn.is_none()
    }
}

#[cfg(feature = "runtime")]
mod geoip_runtime {
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io::{self, Read};
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};

    use fluxheim_config::config_geoip::MAX_GEOIP_DATABASES;
    use fluxheim_config::{GeoIpConfig, GeoIpProvider};
    use maxminddb::{Reader, geoip2, path};

    use crate::GeoContext;

    mod file_path;
    #[cfg(test)]
    mod tests;
    mod value;

    use file_path::{O_NOFOLLOW, path_contains_symlink};
    use value::{admitted_geoip_total, normalized_country};

    const MAX_GEOIP_DATABASE_BYTES: u64 = 512 * 1024 * 1024;
    const MAX_TOTAL_GEOIP_DATABASE_BYTES: u64 = 1024 * 1024 * 1024;

    #[derive(Clone, Copy, Debug)]
    struct GeoIpLoadLimits {
        max_database_bytes: u64,
        max_total_bytes: u64,
        max_databases: usize,
    }

    impl GeoIpLoadLimits {
        const fn production() -> Self {
            Self {
                max_database_bytes: MAX_GEOIP_DATABASE_BYTES,
                max_total_bytes: MAX_TOTAL_GEOIP_DATABASE_BYTES,
                max_databases: MAX_GEOIP_DATABASES,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct GeoIpPolicyUsage {
        pub country: bool,
        pub asn: bool,
    }

    #[derive(Debug)]
    pub struct GeoIpRuntime {
        databases: Vec<GeoIpDatabase>,
        fallback_enabled: bool,
    }

    impl GeoIpRuntime {
        pub fn from_config(
            config: &GeoIpConfig,
            policy_usage: GeoIpPolicyUsage,
        ) -> io::Result<Option<Self>> {
            Self::from_config_with_limits(config, policy_usage, GeoIpLoadLimits::production())
        }

        fn from_config_with_limits(
            config: &GeoIpConfig,
            policy_usage: GeoIpPolicyUsage,
            limits: GeoIpLoadLimits,
        ) -> io::Result<Option<Self>> {
            if !config.enabled {
                return Ok(None);
            }
            let database_count = config.databases.len();
            if database_count == 0 || database_count > limits.max_databases {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "GeoIP requires 1..={} databases; got {database_count}",
                        limits.max_databases
                    ),
                ));
            }
            let mut databases = Vec::new();
            databases
                .try_reserve_exact(database_count)
                .map_err(|error| {
                    io::Error::other(format!("failed to reserve GeoIP database list: {error}"))
                })?;
            let mut total_bytes = 0u64;
            for configured in &config.databases {
                let verified = open_verified_mmdb(&configured.path, limits.max_database_bytes)?;
                let next_total =
                    admitted_geoip_total(total_bytes, verified.byte_len, limits.max_total_bytes)?;
                let database = GeoIpDatabase::from_open_file(configured.provider, verified)?;
                databases.push(database);
                total_bytes = next_total;
            }
            warn_if_policy_coverage_missing(&databases, policy_usage);
            Ok(Some(Self {
                databases,
                fallback_enabled: config.fallback_enabled,
            }))
        }

        pub fn lookup(&self, ip: IpAddr) -> Option<GeoContext> {
            let mut country = None;
            let mut asn = None;

            for database in &self.databases {
                let (database_country, database_asn) = database.lookup(ip);
                if country.is_none() {
                    country = database_country;
                }
                if asn.is_none() {
                    asn = database_asn;
                }
                if country.is_some() && asn.is_some() {
                    break;
                }
                if !self.fallback_enabled {
                    break;
                }
            }

            let context = GeoContext::new(country, asn);
            (!context.is_empty()).then_some(context)
        }
    }

    #[derive(Debug)]
    struct GeoIpDatabase {
        reader: Reader<Vec<u8>>,
        database_type: String,
    }

    impl GeoIpDatabase {
        fn from_open_file(provider: GeoIpProvider, verified: VerifiedMmdbFile) -> io::Result<Self> {
            let contents = read_verified_mmdb(verified)?;
            let reader = Reader::from_source(contents).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "failed to parse {} GeoIP database: {error}",
                        provider.as_str()
                    ),
                )
            })?;
            let database_type = reader.metadata().database_type.clone();
            Ok(Self {
                reader,
                database_type,
            })
        }

        fn lookup(&self, ip: IpAddr) -> (Option<String>, Option<u32>) {
            let Ok(lookup) = self.reader.lookup(ip) else {
                return (None, None);
            };
            let country = lookup
                .decode_path::<&str>(&path!["country", "iso_code"])
                .ok()
                .flatten()
                .or_else(|| {
                    lookup
                        .decode_path::<&str>(&path!["registered_country", "iso_code"])
                        .ok()
                        .flatten()
                });
            let asn = lookup
                .decode::<geoip2::Asn<'_>>()
                .ok()
                .flatten()
                .and_then(|asn| asn.autonomous_system_number.filter(|asn| *asn > 0));
            (country.and_then(normalized_country), asn)
        }

        fn appears_to_provide_country(&self) -> bool {
            let database_type = self.database_type.to_ascii_lowercase();
            database_type.contains("country") || database_type.contains("city")
        }

        fn appears_to_provide_asn(&self) -> bool {
            let database_type = self.database_type.to_ascii_lowercase();
            database_type.contains("asn")
                || database_type.contains("connection-type")
                || database_type.contains("isp")
        }
    }

    fn warn_if_policy_coverage_missing(
        databases: &[GeoIpDatabase],
        policy_usage: GeoIpPolicyUsage,
    ) {
        if policy_usage.country
            && !databases
                .iter()
                .any(GeoIpDatabase::appears_to_provide_country)
        {
            log::warn!(
                target: "fluxheim::security",
                "geoip: country access policies are configured but no loaded database type appears to provide country records"
            );
        }
        if policy_usage.asn && !databases.iter().any(GeoIpDatabase::appears_to_provide_asn) {
            log::warn!(
                target: "fluxheim::security",
                "geoip: ASN access policies are configured but no loaded database type appears to provide ASN records"
            );
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct MmdbFileState {
        len: u64,
        modified: Option<std::time::SystemTime>,
        #[cfg(unix)]
        device: u64,
        #[cfg(unix)]
        inode: u64,
        #[cfg(unix)]
        change_seconds: i64,
        #[cfg(unix)]
        change_nanoseconds: i64,
    }

    impl MmdbFileState {
        fn from_metadata(metadata: &Metadata) -> Self {
            #[cfg(unix)]
            use std::os::unix::fs::MetadataExt as _;

            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                #[cfg(unix)]
                device: metadata.dev(),
                #[cfg(unix)]
                inode: metadata.ino(),
                #[cfg(unix)]
                change_seconds: metadata.ctime(),
                #[cfg(unix)]
                change_nanoseconds: metadata.ctime_nsec(),
            }
        }
    }

    #[derive(Debug)]
    struct VerifiedMmdbFile {
        file: File,
        path: PathBuf,
        byte_len: u64,
        state: MmdbFileState,
    }

    #[cfg(unix)]
    fn open_regular_mmdb(path: &Path) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        options.read(true).custom_flags(O_NOFOLLOW);
        options.open(path)
    }

    #[cfg(not(unix))]
    fn open_regular_mmdb(path: &Path) -> io::Result<File> {
        OpenOptions::new().read(true).open(path)
    }

    fn open_verified_mmdb(path: &Path, max_bytes: u64) -> io::Result<VerifiedMmdbFile> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("GeoIP database path must be absolute: {}", path.display()),
            ));
        }
        if path_contains_symlink(path)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "GeoIP database path must not contain symlinks: {}",
                    path.display()
                ),
            ));
        }
        let path_metadata = fs::symlink_metadata(path)?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("GeoIP database must be a regular file: {}", path.display()),
            ));
        }
        let file = open_regular_mmdb(path)?;
        let opened_metadata = file.metadata()?;
        if !opened_metadata.is_file() || !same_mmdb_file(&path_metadata, &opened_metadata) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "GeoIP database identity changed while opening: {}",
                    path.display()
                ),
            ));
        }
        validate_mmdb_permissions(&file, path)?;
        let byte_len = opened_metadata.len();
        if byte_len > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "GeoIP database exceeds {max_bytes} bytes: {}",
                    path.display()
                ),
            ));
        }
        Ok(VerifiedMmdbFile {
            file,
            path: path.to_path_buf(),
            byte_len,
            state: MmdbFileState::from_metadata(&opened_metadata),
        })
    }

    #[cfg(unix)]
    fn same_mmdb_file(path_metadata: &Metadata, opened_metadata: &Metadata) -> bool {
        use std::os::unix::fs::MetadataExt as _;

        path_metadata.dev() == opened_metadata.dev() && path_metadata.ino() == opened_metadata.ino()
    }

    #[cfg(not(unix))]
    fn same_mmdb_file(path_metadata: &Metadata, opened_metadata: &Metadata) -> bool {
        path_metadata.len() == opened_metadata.len()
            && path_metadata.modified().ok() == opened_metadata.modified().ok()
    }

    #[cfg(unix)]
    fn validate_mmdb_permissions(file: &File, path: &Path) -> io::Result<()> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let process_uid = rustix::process::geteuid().as_raw();
        let root_uid = fs::symlink_metadata(Path::new("/"))?.uid();
        let metadata = file.metadata()?;
        validate_mmdb_owner(metadata.uid(), process_uid, root_uid, path, "database")?;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "GeoIP database must not be group- or world-writable: {}",
                    path.display()
                ),
            ));
        }
        let Some(parent) = path.parent() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GeoIP database path has no parent directory",
            ));
        };
        for directory in parent.ancestors() {
            let metadata = fs::symlink_metadata(directory)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "GeoIP parent is not a trusted directory: {}",
                        directory.display()
                    ),
                ));
            }
            validate_mmdb_owner(
                metadata.uid(),
                process_uid,
                root_uid,
                directory,
                "parent directory",
            )?;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "GeoIP parent directory must not be group- or world-writable: {}",
                        directory.display()
                    ),
                ));
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn validate_mmdb_owner(
        owner_uid: u32,
        process_uid: u32,
        root_uid: u32,
        path: &Path,
        kind: &str,
    ) -> io::Result<()> {
        if owner_uid == 0 || owner_uid == process_uid || owner_uid == root_uid {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("GeoIP {kind} has an untrusted owner: {}", path.display()),
        ))
    }

    #[cfg(not(unix))]
    fn validate_mmdb_permissions(_file: &File, _path: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "GeoIP database ACL validation is not implemented on this platform",
        ))
    }

    fn read_verified_mmdb(verified: VerifiedMmdbFile) -> io::Result<Vec<u8>> {
        read_verified_mmdb_with_post_read(verified, || {})
    }

    fn read_verified_mmdb_with_post_read(
        mut verified: VerifiedMmdbFile,
        post_read: impl FnOnce(),
    ) -> io::Result<Vec<u8>> {
        let capacity = usize::try_from(verified.byte_len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "GeoIP database size cannot be represented on this platform",
            )
        })?;
        let mut contents = Vec::new();
        contents.try_reserve_exact(capacity).map_err(|error| {
            io::Error::other(format!("failed to reserve GeoIP database buffer: {error}"))
        })?;
        let mut limited = verified
            .file
            .by_ref()
            .take(verified.byte_len.saturating_add(1));
        limited.read_to_end(&mut contents)?;
        if contents.len() as u64 != verified.byte_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "GeoIP database size changed while reading: {}",
                    verified.path.display()
                ),
            ));
        }
        post_read();
        let final_state = MmdbFileState::from_metadata(&verified.file.metadata()?);
        if final_state != verified.state {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "GeoIP database changed while reading: {}",
                    verified.path.display()
                ),
            ));
        }
        Ok(contents)
    }
}

#[cfg(feature = "runtime")]
pub use geoip_runtime::{GeoIpPolicyUsage, GeoIpRuntime};
