use std::io;

const MAX_RAW_COUNTRY_CODE_BYTES: usize = 8;

pub(super) fn normalized_country(value: &str) -> Option<String> {
    if value.len() > MAX_RAW_COUNTRY_CODE_BYTES {
        return None;
    }
    let value = value.trim();
    (value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_alphabetic()))
        .then(|| value.to_ascii_uppercase())
}

pub(super) fn admitted_geoip_total(current: u64, next: u64, maximum: u64) -> io::Result<u64> {
    let total = current
        .checked_add(next)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "total GeoIP size overflow"))?;
    if total > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("total GeoIP database size {total} bytes exceeds {maximum} bytes"),
        ));
    }
    Ok(total)
}
