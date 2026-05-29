use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::{Reader, geoip2, path};

use crate::config::{GeoIpConfig, GeoIpProvider};
use crate::geo_context::GeoContext;

const MAX_GEOIP_DATABASE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_GEOIP_DATABASE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GeoIpPolicyUsage {
    pub(crate) country: bool,
    pub(crate) asn: bool,
}

#[derive(Debug)]
pub struct GeoIpRuntime {
    databases: Vec<GeoIpDatabase>,
    fallback_enabled: bool,
}

impl GeoIpRuntime {
    pub(crate) fn from_config(
        config: &GeoIpConfig,
        policy_usage: GeoIpPolicyUsage,
    ) -> io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let mut databases = Vec::with_capacity(config.databases.len());
        let mut total_bytes = 0u64;
        for database in &config.databases {
            let database = GeoIpDatabase::open(database.provider, &database.path)?;
            total_bytes = total_bytes.saturating_add(database.byte_len as u64);
            if total_bytes > MAX_TOTAL_GEOIP_DATABASE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "total GeoIP database size {total_bytes} bytes exceeds {MAX_TOTAL_GEOIP_DATABASE_BYTES} bytes"
                    ),
                ));
            }
            databases.push(database);
        }
        warn_if_policy_coverage_missing(&databases, policy_usage);
        Ok(Some(Self {
            databases,
            fallback_enabled: config.fallback_enabled,
        }))
    }

    pub(crate) fn lookup(&self, ip: IpAddr) -> Option<GeoContext> {
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
    byte_len: usize,
}

impl GeoIpDatabase {
    fn open(provider: GeoIpProvider, path: &Path) -> io::Result<Self> {
        let contents = read_regular_mmdb(path)?;
        let byte_len = contents.len();
        let reader = Reader::from_source(contents).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse {} GeoIP database: {error}",
                    provider.as_str()
                ),
            )
        })?;
        let database_type = reader.metadata.database_type.clone();
        Ok(Self {
            reader,
            database_type,
            byte_len,
        })
    }

    fn lookup(&self, ip: IpAddr) -> (Option<String>, Option<u32>) {
        let Ok(lookup) = self.reader.lookup(ip) else {
            return (None, None);
        };
        let country = lookup
            .decode_path::<String>(&path!["country", "iso_code"])
            .ok()
            .flatten()
            .or_else(|| {
                lookup
                    .decode_path::<String>(&path!["registered_country", "iso_code"])
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

fn warn_if_policy_coverage_missing(databases: &[GeoIpDatabase], policy_usage: GeoIpPolicyUsage) {
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

fn normalized_country(value: String) -> Option<String> {
    let value = value.trim();
    (value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_alphabetic()))
        .then(|| value.to_ascii_uppercase())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe GeoIP database loading before building Fluxheim"
);

#[cfg(unix)]
fn open_regular_mmdb(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.read(true).custom_flags(O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("GeoIP database is not a regular file: {}", path.display()),
        ));
    }
    if metadata.len() > MAX_GEOIP_DATABASE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "GeoIP database exceeds {MAX_GEOIP_DATABASE_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_regular_mmdb(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().read(true).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("GeoIP database is not a regular file: {}", path.display()),
        ));
    }
    if metadata.len() > MAX_GEOIP_DATABASE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "GeoIP database exceeds {MAX_GEOIP_DATABASE_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    Ok(file)
}

fn read_regular_mmdb(path: &Path) -> io::Result<Vec<u8>> {
    // This rejects obvious symlink components before opening. The final
    // component is also opened with O_NOFOLLOW on Unix. On Unix platforms
    // without openat2(RESOLVE_NO_SYMLINKS), a writable parent directory still
    // has a narrow intermediate-directory substitution window; deploy GeoIP
    // databases under root/service-owned directories.
    if path_contains_symlink(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "GeoIP database path must not contain symlinks: {}",
                path.display()
            ),
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("GeoIP database must not be a symlink: {}", path.display()),
        ));
    }
    let mut file = open_regular_mmdb(path)?;
    let mut contents = Vec::with_capacity(metadata.len().min(MAX_GEOIP_DATABASE_BYTES) as usize);
    let mut limited = file.by_ref().take(MAX_GEOIP_DATABASE_BYTES + 1);
    limited.read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_GEOIP_DATABASE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "GeoIP database grew past {MAX_GEOIP_DATABASE_BYTES} bytes during read: {}",
                path.display()
            ),
        ));
    }
    Ok(contents)
}

fn path_contains_symlink(path: &Path) -> io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::normalized_country;

    #[test]
    fn normalizes_country_codes() {
        assert_eq!(normalized_country("se".to_owned()).as_deref(), Some("SE"));
        assert_eq!(normalized_country(" USA ".to_owned()), None);
        assert_eq!(normalized_country("1A".to_owned()), None);
    }
}
