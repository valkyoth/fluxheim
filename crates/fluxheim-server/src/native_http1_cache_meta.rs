use std::io::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fluxheim_cache::SerializedCacheObject;

use super::NativeMemoryCacheEntry;

const MAX_NATIVE_DISK_CACHE_META_BYTES: usize = 1024 * 1024;
const MAX_NATIVE_DISK_CACHE_VARY_FIELDS: usize = 64;
const MAX_NATIVE_DISK_CACHE_RESPONSE_HEADERS: usize = 256;
const MAX_NATIVE_DISK_CACHE_REASON_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NativeDiskCacheMeta {
    pub(super) status: u16,
    pub(super) reason: String,
    pub(super) content_length: Option<u64>,
    pub(super) expires_at_unix_secs: u64,
    pub(super) stale_while_revalidate_until_unix_secs: Option<u64>,
    pub(super) stale_if_error_until_unix_secs: Option<u64>,
    pub(super) stored_at_unix_secs: u64,
    pub(super) vary_fields: Vec<String>,
}

impl NativeDiskCacheMeta {
    pub(super) fn from_entry(entry: &NativeMemoryCacheEntry, vary_fields: Vec<String>) -> Self {
        Self {
            status: entry.status,
            reason: entry.reason.clone(),
            content_length: entry.content_length,
            expires_at_unix_secs: native_instant_to_unix_secs(entry.expires_at),
            stale_while_revalidate_until_unix_secs: entry
                .stale_while_revalidate_until
                .map(native_instant_to_unix_secs),
            stale_if_error_until_unix_secs: entry
                .stale_if_error_until
                .map(native_instant_to_unix_secs),
            stored_at_unix_secs: native_instant_to_unix_secs(entry.stored_at),
            vary_fields,
        }
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        let _ = writeln!(&mut encoded, "FLUXHEIM-NATIVE-PROXY-CACHE-v1");
        let _ = writeln!(&mut encoded, "{}", self.status);
        let _ = writeln!(&mut encoded, "{}", self.reason.len());
        let _ = writeln!(
            &mut encoded,
            "{}",
            self.content_length
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        let _ = writeln!(&mut encoded, "{}", self.expires_at_unix_secs);
        let _ = writeln!(
            &mut encoded,
            "{}",
            self.stale_while_revalidate_until_unix_secs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        let _ = writeln!(
            &mut encoded,
            "{}",
            self.stale_if_error_until_unix_secs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        let _ = writeln!(&mut encoded, "{}", self.stored_at_unix_secs);
        let _ = writeln!(&mut encoded, "{}", self.vary_fields.len());
        for field in &self.vary_fields {
            let _ = writeln!(&mut encoded, "{}", field.len());
        }
        encoded.extend_from_slice(self.reason.as_bytes());
        for field in &self.vary_fields {
            encoded.extend_from_slice(field.as_bytes());
        }
        encoded
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_NATIVE_DISK_CACHE_META_BYTES {
            return None;
        }
        let mut offset = 0_usize;
        let magic = native_disk_meta_line(bytes, &mut offset)?;
        if magic != "FLUXHEIM-NATIVE-PROXY-CACHE-v1" {
            return None;
        }
        let status = native_disk_meta_line(bytes, &mut offset)?
            .parse::<u16>()
            .ok()?;
        let reason_len = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        if reason_len > MAX_NATIVE_DISK_CACHE_REASON_BYTES {
            return None;
        }
        let content_length =
            native_disk_meta_optional_u64(native_disk_meta_line(bytes, &mut offset)?)?;
        let expires_at_unix_secs = native_disk_meta_line(bytes, &mut offset)?
            .parse::<u64>()
            .ok()?;
        let stale_while_revalidate_until_unix_secs =
            native_disk_meta_optional_u64(native_disk_meta_line(bytes, &mut offset)?)?;
        let stale_if_error_until_unix_secs =
            native_disk_meta_optional_u64(native_disk_meta_line(bytes, &mut offset)?)?;
        let stored_at_unix_secs = native_disk_meta_line(bytes, &mut offset)?
            .parse::<u64>()
            .ok()?;
        let vary_count = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        if vary_count > MAX_NATIVE_DISK_CACHE_VARY_FIELDS
            || vary_count > bytes.len().saturating_sub(offset)
        {
            return None;
        }
        let mut vary_lens = Vec::new();
        vary_lens.try_reserve_exact(vary_count).ok()?;
        for _ in 0..vary_count {
            vary_lens.push(
                native_disk_meta_line(bytes, &mut offset)?
                    .parse::<usize>()
                    .ok()?,
            );
        }
        let reason_end = offset.checked_add(reason_len)?;
        let reason = std::str::from_utf8(bytes.get(offset..reason_end)?)
            .ok()?
            .to_owned();
        offset = reason_end;
        let mut vary_fields = Vec::new();
        vary_fields.try_reserve_exact(vary_count).ok()?;
        for len in vary_lens {
            let end = offset.checked_add(len)?;
            vary_fields.push(
                std::str::from_utf8(bytes.get(offset..end)?)
                    .ok()?
                    .to_owned(),
            );
            offset = end;
        }
        (offset == bytes.len()).then_some(Self {
            status,
            reason,
            content_length,
            expires_at_unix_secs,
            stale_while_revalidate_until_unix_secs,
            stale_if_error_until_unix_secs,
            stored_at_unix_secs,
            vary_fields,
        })
    }
}

fn native_disk_meta_line<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a str> {
    let relative = bytes
        .get(*offset..)?
        .iter()
        .position(|byte| *byte == b'\n')?;
    let start = *offset;
    let end = start.checked_add(relative)?;
    *offset = end.checked_add(1)?;
    std::str::from_utf8(bytes.get(start..end)?).ok()
}

fn native_disk_meta_optional_u64(value: &str) -> Option<Option<u64>> {
    if value == "-" {
        return Some(None);
    }
    value.parse::<u64>().ok().map(Some)
}

pub(super) fn native_disk_response_header_bytes(entry: &NativeMemoryCacheEntry) -> Vec<u8> {
    let mut encoded = Vec::new();
    let _ = writeln!(&mut encoded, "{}", entry.headers.len());
    for (name, value) in &entry.headers {
        let _ = writeln!(&mut encoded, "{}", name.len());
        let _ = writeln!(&mut encoded, "{}", value.len());
    }
    for (name, value) in &entry.headers {
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(value.as_bytes());
    }
    encoded
}

fn native_disk_response_headers(bytes: &[u8]) -> Option<Vec<(String, String)>> {
    if bytes.len() > MAX_NATIVE_DISK_CACHE_META_BYTES {
        return None;
    }
    let mut offset = 0_usize;
    let count = native_disk_meta_line(bytes, &mut offset)?
        .parse::<usize>()
        .ok()?;
    if count > MAX_NATIVE_DISK_CACHE_RESPONSE_HEADERS || count > bytes.len().saturating_sub(offset)
    {
        return None;
    }
    let mut lengths = Vec::new();
    lengths.try_reserve_exact(count).ok()?;
    for _ in 0..count {
        let name_len = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        let value_len = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        lengths.push((name_len, value_len));
    }
    let mut headers = Vec::new();
    headers.try_reserve_exact(count).ok()?;
    for (name_len, value_len) in lengths {
        let name_end = offset.checked_add(name_len)?;
        let name = std::str::from_utf8(bytes.get(offset..name_end)?)
            .ok()?
            .to_owned();
        offset = name_end;
        let value_end = offset.checked_add(value_len)?;
        let value = std::str::from_utf8(bytes.get(offset..value_end)?)
            .ok()?
            .to_owned();
        offset = value_end;
        headers.push((name, value));
    }
    (offset == bytes.len()).then_some(headers)
}

pub(super) fn native_memory_entry_from_disk_object(
    object: &SerializedCacheObject,
) -> Option<NativeMemoryCacheEntry> {
    let meta = NativeDiskCacheMeta::decode(&object.internal_meta)?;
    let now_system = SystemTime::now();
    let now_instant = Instant::now();
    let entry = NativeMemoryCacheEntry {
        status: meta.status,
        reason: meta.reason,
        headers: native_disk_response_headers(&object.response_header)?,
        content_length: meta.content_length,
        body: object.body.clone(),
        expires_at: native_unix_secs_to_instant(meta.expires_at_unix_secs, now_system, now_instant),
        stale_while_revalidate_until: meta
            .stale_while_revalidate_until_unix_secs
            .map(|secs| native_unix_secs_to_instant(secs, now_system, now_instant)),
        stale_if_error_until: meta
            .stale_if_error_until_unix_secs
            .map(|secs| native_unix_secs_to_instant(secs, now_system, now_instant)),
        stored_at: native_unix_secs_to_instant(meta.stored_at_unix_secs, now_system, now_instant),
        weight: object.weight as u64,
    };
    let now = Instant::now();
    if entry.expires_at <= now && !native_cache_entry_has_stale_window_for_disk(&entry, now) {
        return None;
    }
    Some(entry)
}

fn native_cache_entry_has_stale_window_for_disk(
    entry: &NativeMemoryCacheEntry,
    now: Instant,
) -> bool {
    entry
        .stale_while_revalidate_until
        .is_some_and(|until| until > now)
        || entry.stale_if_error_until.is_some_and(|until| until > now)
}

pub(super) fn native_instant_to_unix_secs(instant: Instant) -> u64 {
    let now_instant = Instant::now();
    let now_system = SystemTime::now();
    let system = if instant >= now_instant {
        now_system
            .checked_add(instant.saturating_duration_since(now_instant))
            .unwrap_or(now_system)
    } else {
        now_system
            .checked_sub(now_instant.saturating_duration_since(instant))
            .unwrap_or(UNIX_EPOCH)
    };
    system
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn native_unix_secs_to_instant(secs: u64, now_system: SystemTime, now_instant: Instant) -> Instant {
    let target = UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .unwrap_or(UNIX_EPOCH);
    if target >= now_system {
        now_instant
            .checked_add(target.duration_since(now_system).unwrap_or_default())
            .unwrap_or(now_instant)
    } else {
        now_instant
            .checked_sub(now_system.duration_since(target).unwrap_or_default())
            .unwrap_or(now_instant)
    }
}

#[cfg(test)]
mod tests {
    use super::{NativeDiskCacheMeta, native_disk_response_headers};

    #[test]
    fn disk_cache_metadata_rejects_unbounded_persistent_counts() {
        let metadata = format!(
            "FLUXHEIM-NATIVE-PROXY-CACHE-v1\n200\n0\n-\n0\n-\n-\n0\n{}\n",
            usize::MAX
        );

        assert!(NativeDiskCacheMeta::decode(metadata.as_bytes()).is_none());
        assert!(native_disk_response_headers(format!("{}\n", usize::MAX).as_bytes()).is_none());
    }
}
