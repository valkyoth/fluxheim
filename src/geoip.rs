use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::{Reader, geoip2, path};

use crate::config::{GeoIpConfig, GeoIpProvider};
use crate::geo_context::GeoContext;

const MAX_GEOIP_DATABASE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub struct GeoIpRuntime {
    databases: Vec<GeoIpDatabase>,
    fallback_enabled: bool,
}

impl GeoIpRuntime {
    pub(crate) fn from_config(config: &GeoIpConfig) -> io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let mut databases = Vec::with_capacity(config.databases.len());
        for database in &config.databases {
            databases.push(GeoIpDatabase::open(database.provider, &database.path)?);
        }
        Ok(Some(Self {
            databases,
            fallback_enabled: config.fallback_enabled,
        }))
    }

    pub(crate) fn lookup(&self, ip: IpAddr) -> Option<GeoContext> {
        let mut country = None;
        let mut asn = None;

        for database in &self.databases {
            if country.is_none() {
                country = database.lookup_country(ip);
            }
            if asn.is_none() {
                asn = database.lookup_asn(ip);
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
}

impl GeoIpDatabase {
    fn open(provider: GeoIpProvider, path: &Path) -> io::Result<Self> {
        let contents = read_regular_mmdb(path)?;
        let reader = Reader::from_source(contents).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse {} GeoIP database: {error}",
                    provider.as_str()
                ),
            )
        })?;
        Ok(Self { reader })
    }

    fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let lookup = self.reader.lookup(ip).ok()?;
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
        country.and_then(normalized_country)
    }

    fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        self.reader
            .lookup(ip)
            .ok()?
            .decode::<geoip2::Asn<'_>>()
            .ok()??
            .autonomous_system_number
            .filter(|asn| *asn > 0)
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
    file.read_to_end(&mut contents)?;
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
