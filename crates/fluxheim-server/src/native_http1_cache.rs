use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fluxheim_cache::{
    DiskCacheObjectKey, SerializedCacheObject, encode_disk_cache_object, parse_disk_cache_object,
    remaining_fresh_ttl_secs, response_age_secs, response_cache_control_max_age,
};
use fluxheim_config::{CacheConfig, CacheDiskBackend};
use sha2::{Digest as _, Sha256};
use tokio::sync::Notify;

use crate::NativeHttp1Response;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeMemoryCacheEntry {
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) content_length: Option<u64>,
    pub(crate) body: Arc<[u8]>,
    pub(crate) expires_at: Instant,
    pub(crate) stale_while_revalidate_until: Option<Instant>,
    pub(crate) stale_if_error_until: Option<Instant>,
    pub(crate) stored_at: Instant,
    pub(crate) weight: u64,
}

#[derive(Debug, Default)]
pub(crate) struct NativeMemoryCacheState {
    pub(crate) objects: HashMap<String, NativeMemoryCacheEntry>,
    pub(crate) variants: HashMap<String, Vec<NativeMemoryCacheVariant>>,
    pub(crate) min_uses: HashMap<String, NativeMemoryCacheCounter>,
    pub(crate) cache_pass: HashMap<String, NativeMemoryCacheCounter>,
    pub(crate) revalidating: HashSet<String>,
    pub(crate) filling: HashMap<String, NativeMemoryCacheFill>,
    pub(crate) bytes: u64,
}

#[derive(Debug)]
pub(crate) struct NativeDiskCache {
    root: PathBuf,
    max_bytes: u64,
    max_object_bytes: fluxheim_config::ByteSize,
    state: Mutex<NativeDiskCacheState>,
}

#[derive(Debug, Default)]
struct NativeDiskCacheState {
    objects: HashMap<String, NativeDiskCacheRecord>,
    variants: HashMap<String, Vec<NativeMemoryCacheVariant>>,
    bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeDiskCacheRecord {
    path: PathBuf,
    weight: u64,
    accessed_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeDiskCacheStoreKey {
    pub(crate) combined: String,
    pub(crate) primary: String,
    pub(crate) user_tag: String,
    pub(crate) index_path: Option<String>,
    pub(crate) vary_fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeDiskCacheMeta {
    status: u16,
    reason: String,
    content_length: Option<u64>,
    expires_at_unix_secs: u64,
    stale_while_revalidate_until_unix_secs: Option<u64>,
    stale_if_error_until_unix_secs: Option<u64>,
    stored_at_unix_secs: u64,
    vary_fields: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeMemoryCacheCounter {
    pub(crate) uses: u32,
    pub(crate) seen_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeMemoryCacheVariant {
    pub(crate) fields: Vec<String>,
    pub(crate) key: String,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeMemoryCacheFill {
    pub(crate) notify: Arc<Notify>,
    pub(crate) started_at: Instant,
}

impl NativeMemoryCacheEntry {
    pub(crate) fn to_response(&self) -> NativeHttp1Response {
        let mut response =
            NativeHttp1Response::new(self.status, self.reason.clone(), self.body.to_vec());
        for (name, value) in &self.headers {
            response = response.with_header(name.clone(), value.clone());
        }
        if let Some(content_length) = self.content_length {
            response = response.with_content_length(content_length);
        }
        response
    }

    pub(crate) fn age_secs(&self) -> u64 {
        Instant::now()
            .saturating_duration_since(self.stored_at)
            .as_secs()
    }
}

impl NativeDiskCache {
    pub(crate) fn from_config(config: &CacheConfig) -> Option<Self> {
        if !native_disk_cache_supported(config) {
            return None;
        }
        let root = config.disk.path.as_ref()?;
        let root = match prepare_native_disk_cache_root(root) {
            Ok(root) => root,
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache root {}: {error}",
                    root.display()
                );
                return None;
            }
        };
        let mut cache = Self {
            root,
            max_bytes: config.disk.max_size_bytes.as_u64(),
            max_object_bytes: config.max_object_bytes,
            state: Mutex::new(NativeDiskCacheState::default()),
        };
        if let Err(error) = cache.rebuild_index() {
            log::warn!(
                target: "fluxheim::native_http1",
                "native disk cache index rebuild {}: {error}",
                cache.root.display()
            );
        }
        Some(cache)
    }

    pub(crate) fn get(
        &self,
        key: &str,
        request_variant_key: impl Fn(&[String]) -> Option<String>,
    ) -> Option<NativeMemoryCacheEntry> {
        if let Some(variants) = self.with_state(|state| state.variants.get(key).cloned()) {
            for variant in variants {
                let Some(variant_key) = request_variant_key(&variant.fields) else {
                    continue;
                };
                if variant_key != variant.key {
                    continue;
                }
                return self.get_combined(&variant.key);
            }
            return None;
        }
        self.get_combined(key)
    }

    pub(crate) fn store(
        &self,
        key: NativeDiskCacheStoreKey,
        entry: &NativeMemoryCacheEntry,
    ) -> std::io::Result<()> {
        let path = self.path_for_combined_key(&key.combined);
        if let Some(parent) = path.parent() {
            create_native_cache_dir_all(parent)?;
        }
        let meta = NativeDiskCacheMeta::from_entry(entry, key.vary_fields.clone());
        let disk_key = DiskCacheObjectKey {
            combined: key.combined.clone(),
            primary: key.primary.clone(),
            user_tag: key.user_tag,
            index_path: key.index_path,
            cache_tags: Vec::new(),
        };
        let encoded = encode_disk_cache_object(
            &disk_key,
            &meta.encode(),
            &native_disk_response_header_bytes(entry),
            &entry.body,
        )?;
        if encoded.len() as u64 > self.max_bytes {
            return Ok(());
        }
        self.write_object_atomically(&path, &encoded)?;
        self.with_state_mut(|state| {
            if let Some(previous) = state.objects.insert(
                key.combined.clone(),
                NativeDiskCacheRecord {
                    path: path.clone(),
                    weight: encoded.len() as u64,
                    accessed_at: SystemTime::now(),
                },
            ) {
                state.bytes = state.bytes.saturating_sub(previous.weight);
            }
            if key.vary_fields.is_empty() {
                state.variants.remove(&key.primary);
            } else {
                let variants = state.variants.entry(key.primary).or_default();
                variants.retain(|variant| variant.key != key.combined);
                variants.push(NativeMemoryCacheVariant {
                    fields: key.vary_fields,
                    key: key.combined,
                });
            }
            state.bytes = state.bytes.saturating_add(encoded.len() as u64);
        });
        self.prune();
        Ok(())
    }

    fn get_combined(&self, combined_key: &str) -> Option<NativeMemoryCacheEntry> {
        let record = self.with_state(|state| state.objects.get(combined_key).cloned())?;
        let object = match self.read_record(&record) {
            Ok(object) => object,
            Err(error) => {
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native disk cache read {}: {error}",
                    record.path.display()
                );
                self.remove_combined(combined_key);
                return None;
            }
        };
        let entry = match native_memory_entry_from_disk_object(&object) {
            Some(entry) => entry,
            None => {
                self.remove_combined(combined_key);
                return None;
            }
        };
        self.with_state_mut(|state| {
            if let Some(record) = state.objects.get_mut(combined_key) {
                record.accessed_at = SystemTime::now();
            }
        });
        Some(entry)
    }

    fn rebuild_index(&mut self) -> std::io::Result<()> {
        let mut state = NativeDiskCacheState::default();
        for shard in std::fs::read_dir(&self.root)? {
            let shard = shard?;
            let shard_path = shard.path();
            if !shard.file_type()?.is_dir()
                || native_cache_path_contains_symlink(&self.root, &shard_path)?
            {
                continue;
            }
            for object in std::fs::read_dir(&shard_path)? {
                let object = object?;
                let path = object.path();
                if object.file_type()?.is_dir()
                    || path.extension().and_then(|value| value.to_str()) != Some("fhc")
                    || native_cache_path_contains_symlink(&self.root, &path)?
                {
                    continue;
                }
                let bytes = match read_native_disk_cache_file(&path) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                let parsed = match parse_disk_cache_object(&bytes, self.max_object_bytes) {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                };
                let Some(combined) = parsed.combined_key.clone() else {
                    continue;
                };
                let Some(primary) = parsed.primary_key.clone() else {
                    continue;
                };
                let Some(meta) = NativeDiskCacheMeta::decode(&parsed.internal_meta) else {
                    continue;
                };
                if native_memory_entry_from_disk_object(&parsed).is_none() {
                    continue;
                }
                let weight = bytes.len() as u64;
                state.bytes = state.bytes.saturating_add(weight);
                state.objects.insert(
                    combined.clone(),
                    NativeDiskCacheRecord {
                        path,
                        weight,
                        accessed_at: SystemTime::now(),
                    },
                );
                if !meta.vary_fields.is_empty() {
                    state
                        .variants
                        .entry(primary)
                        .or_default()
                        .push(NativeMemoryCacheVariant {
                            fields: meta.vary_fields,
                            key: combined,
                        });
                }
            }
        }
        self.state = Mutex::new(state);
        self.prune();
        Ok(())
    }

    fn read_record(
        &self,
        record: &NativeDiskCacheRecord,
    ) -> std::io::Result<SerializedCacheObject> {
        if native_cache_path_contains_symlink(&self.root, &record.path)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native disk cache object path crosses symlink",
            ));
        }
        let bytes = read_native_disk_cache_file(&record.path)?;
        parse_disk_cache_object(&bytes, self.max_object_bytes)
    }

    fn write_object_atomically(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let mut last_error = None;
        for _ in 0..4 {
            let tmp_path = self.temp_path_for(path)?;
            let tmp_safe = NativeSafeDiskCachePath::from_path(tmp_path);
            let destination = NativeSafeDiskCachePath::from_path(path.to_path_buf());
            let write_result = (|| {
                let mut file = tmp_safe.create_new_file()?;
                file.write_all(bytes)?;
                file.sync_all()?;
                destination.rename_from(&tmp_safe)
            })();
            match write_result {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = tmp_safe.remove_file();
                    last_error = Some(error);
                }
                Err(error) => {
                    let _ = tmp_safe.remove_file();
                    return Err(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "native disk cache temporary path collision",
            )
        }))
    }

    fn temp_path_for(&self, path: &Path) -> std::io::Result<PathBuf> {
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache object path has no parent",
            )
        })?;
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random)
            .map_err(|error| std::io::Error::other(format!("cache temp random: {error}")))?;
        let mut encoded = String::with_capacity(random.len() * 2);
        for byte in random {
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        Ok(parent.join(format!(".{encoded}.tmp")))
    }

    fn path_for_combined_key(&self, key: &str) -> PathBuf {
        let digest = Sha256::digest(key.as_bytes());
        let mut encoded = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        self.root.join(&encoded[..2]).join(format!("{encoded}.fhc"))
    }

    fn prune(&self) {
        let mut removed = Vec::new();
        self.with_state_mut(|state| {
            if state.bytes <= self.max_bytes {
                return;
            }
            let mut candidates = state
                .objects
                .iter()
                .map(|(key, record)| {
                    (
                        record.accessed_at,
                        key.clone(),
                        record.weight,
                        record.path.clone(),
                    )
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|(accessed_at, key, _, _)| (*accessed_at, key.clone()));
            for (_, key, weight, path) in candidates {
                if state.bytes <= self.max_bytes {
                    break;
                }
                if state.objects.remove(&key).is_some() {
                    state.bytes = state.bytes.saturating_sub(weight);
                    state.variants.retain(|_, variants| {
                        variants.retain(|variant| variant.key != key);
                        !variants.is_empty()
                    });
                    removed.push(path);
                }
            }
        });
        for path in removed {
            let _ = NativeSafeDiskCachePath::from_path(path).remove_file();
        }
    }

    fn remove_combined(&self, combined_key: &str) {
        let removed = self.with_state_mut(|state| {
            let removed = state.objects.remove(combined_key);
            if let Some(record) = &removed {
                state.bytes = state.bytes.saturating_sub(record.weight);
            }
            state.variants.retain(|_, variants| {
                variants.retain(|variant| variant.key != combined_key);
                !variants.is_empty()
            });
            removed
        });
        if let Some(record) = removed {
            let _ = NativeSafeDiskCachePath::from_path(record.path).remove_file();
        }
    }

    fn with_state<R>(&self, f: impl FnOnce(&NativeDiskCacheState) -> R) -> R {
        match self.state.lock() {
            Ok(state) => f(&state),
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutex poisoned: {error}"
                );
                std::process::abort();
            }
        }
    }

    fn with_state_mut<R>(&self, f: impl FnOnce(&mut NativeDiskCacheState) -> R) -> R {
        match self.state.lock() {
            Ok(mut state) => f(&mut state),
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutex poisoned: {error}"
                );
                std::process::abort();
            }
        }
    }
}

pub(crate) fn native_disk_cache_supported(cache: &CacheConfig) -> bool {
    !cache.disk.enabled
        || (cache.disk.backend == CacheDiskBackend::Filesystem && !cache.disk.encryption.enabled)
}

pub(crate) fn lock_native_memory_cache<'a>(
    state: &'a Mutex<NativeMemoryCacheState>,
    label: &str,
) -> std::sync::MutexGuard<'a, NativeMemoryCacheState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "{label} memory cache mutex poisoned: {error}"
            );
            std::process::abort();
        }
    }
}

impl NativeDiskCacheMeta {
    fn from_entry(entry: &NativeMemoryCacheEntry, vary_fields: Vec<String>) -> Self {
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

    fn encode(&self) -> Vec<u8> {
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

    fn decode(bytes: &[u8]) -> Option<Self> {
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
        let mut vary_lens = Vec::with_capacity(vary_count);
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
        let mut vary_fields = Vec::with_capacity(vary_count);
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

fn native_disk_response_header_bytes(entry: &NativeMemoryCacheEntry) -> Vec<u8> {
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
    let mut offset = 0_usize;
    let count = native_disk_meta_line(bytes, &mut offset)?
        .parse::<usize>()
        .ok()?;
    let mut lengths = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        let value_len = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        lengths.push((name_len, value_len));
    }
    let mut headers = Vec::with_capacity(count);
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

fn native_memory_entry_from_disk_object(
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

fn native_instant_to_unix_secs(instant: Instant) -> u64 {
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

fn prepare_native_disk_cache_root(root: &Path) -> std::io::Result<PathBuf> {
    if native_configured_cache_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native disk cache root must not cross symlinks",
        ));
    }
    create_native_cache_dir_all(root)?;
    if native_configured_cache_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native disk cache root must not cross symlinks",
        ));
    }
    root.canonicalize()
}

fn create_native_cache_dir_all(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(
            component,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::CurDir
        ) {
            continue;
        }
        if matches!(component, std::path::Component::ParentDir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache directory must not contain parent traversal",
            ));
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "native disk cache path component is not a real directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                rustix::fs::mkdir(
                    &current,
                    rustix::fs::Mode::RWXU | rustix::fs::Mode::RGRP | rustix::fs::Mode::XGRP,
                )
                .map_err(native_rustix_to_io_error)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn native_configured_cache_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn native_cache_path_contains_symlink(root: &Path, path: &Path) -> std::io::Result<bool> {
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(true);
    };
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Ok(true);
        }
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn read_native_disk_cache_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug, Clone)]
struct NativeSafeDiskCachePath {
    path: PathBuf,
}

impl NativeSafeDiskCachePath {
    fn from_path(path: PathBuf) -> Self {
        Self { path }
    }

    fn parent_and_name(&self) -> std::io::Result<(&Path, &std::ffi::OsStr)> {
        let parent = self.path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native disk cache path has no parent",
            )
        })?;
        let name = self.path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native disk cache path has no file name",
            )
        })?;
        Ok((parent, name))
    }

    fn open_parent_dir(&self) -> std::io::Result<std::fs::File> {
        let (parent, _) = self.parent_and_name()?;
        let fd = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn create_new_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn open_existing_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn rename_from(&self, source: &Self) -> std::io::Result<()> {
        let (_, source_name) = source.parent_and_name()?;
        let (_, destination_name) = self.parent_and_name()?;
        let source_parent = source.open_parent_dir()?;
        let destination_parent = self.open_parent_dir()?;
        rustix::fs::renameat(
            &source_parent,
            source_name,
            &destination_parent,
            destination_name,
        )
        .map_err(native_rustix_to_io_error)
    }

    fn remove_file(&self) -> std::io::Result<()> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        rustix::fs::unlinkat(&parent, name, rustix::fs::AtFlags::empty())
            .map_err(native_rustix_to_io_error)
    }
}

fn native_rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

pub(crate) fn native_response_header_map(response: &NativeHttp1Response) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in response.headers() {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::from_str(value) else {
            continue;
        };
        headers.append(name, value);
    }
    if let Some(content_length) = response.content_length()
        && let Ok(value) = http::HeaderValue::from_str(&content_length.to_string())
    {
        headers.insert(http::header::CONTENT_LENGTH, value);
    }
    headers
}

pub(crate) fn native_cache_ttl(
    status: u16,
    headers: &http::HeaderMap,
    cache: &CacheConfig,
) -> Option<Duration> {
    cache
        .status_ttls
        .get(&status)
        .copied()
        .or(cache.default_status_ttl_secs)
        .or_else(|| response_cache_control_max_age(headers))
        .map(u64::from)
        .map(Duration::from_secs)
}

pub(crate) fn native_peer_fill_cache_ttl(
    status: u16,
    headers: &http::HeaderMap,
    cache: &CacheConfig,
) -> Option<Duration> {
    let ttl_secs = cache
        .status_ttls
        .get(&status)
        .copied()
        .or(cache.default_status_ttl_secs)
        .or_else(|| response_cache_control_max_age(headers))?;
    remaining_fresh_ttl_secs(ttl_secs, response_age_secs(headers))
        .map(u64::from)
        .map(Duration::from_secs)
}

pub(crate) fn native_cache_entry_weight(
    key: &str,
    response: &NativeHttp1Response,
    body_len: u64,
) -> u64 {
    const ENTRY_OVERHEAD: u64 = 256;

    response.headers().iter().fold(
        body_len
            .saturating_add(ENTRY_OVERHEAD)
            .saturating_add(key.len() as u64)
            .saturating_add(response.reason().len() as u64),
        |weight, (name, value)| {
            weight
                .saturating_add(name.len() as u64)
                .saturating_add(value.len() as u64)
                .saturating_add(4)
        },
    )
}

pub(crate) fn prune_native_memory_cache(state: &mut NativeMemoryCacheState, max_bytes: u64) {
    let now = Instant::now();
    let expired = state
        .objects
        .iter()
        .filter_map(|(key, entry)| {
            let stale_until = [
                entry.stale_while_revalidate_until,
                entry.stale_if_error_until,
            ]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(entry.expires_at);
            (stale_until <= now).then_some(key.clone())
        })
        .collect::<Vec<_>>();
    let expired_bytes = expired
        .iter()
        .filter_map(|key| remove_native_memory_cache_entry(state, key))
        .fold(0_u64, |total, entry| total.saturating_add(entry.weight));
    state.bytes = state.bytes.saturating_sub(expired_bytes);

    if state.bytes > max_bytes {
        let mut by_age = state
            .objects
            .iter()
            .map(|(key, entry)| (entry.stored_at, key.clone()))
            .collect::<Vec<_>>();
        by_age.sort_unstable_by_key(|(stored_at, _)| *stored_at);
        for (_, key) in by_age {
            if state.bytes <= max_bytes {
                break;
            }
            if let Some(entry) = remove_native_memory_cache_entry(state, &key) {
                state.bytes = state.bytes.saturating_sub(entry.weight);
            }
        }
        if state.objects.is_empty() && state.bytes > max_bytes {
            state.bytes = 0;
        } else {
            let actual_bytes = state
                .objects
                .values()
                .fold(0_u64, |total, entry| total.saturating_add(entry.weight));
            state.bytes = state.bytes.min(actual_bytes);
        }
    }
}

pub(crate) fn remove_native_memory_cache_entry(
    state: &mut NativeMemoryCacheState,
    key: &str,
) -> Option<NativeMemoryCacheEntry> {
    let removed = state.objects.remove(key);
    if removed.is_some() {
        prune_native_memory_cache_variants_for_key(state, key);
    }
    removed
}

pub(crate) fn remove_native_memory_cache_variants(
    state: &mut NativeMemoryCacheState,
    base_key: &str,
) -> u64 {
    let Some(variants) = state.variants.remove(base_key) else {
        return 0;
    };
    variants.into_iter().fold(0_u64, |removed_bytes, variant| {
        let Some(entry) = state.objects.remove(&variant.key) else {
            return removed_bytes;
        };
        removed_bytes.saturating_add(entry.weight)
    })
}

fn prune_native_memory_cache_variants_for_key(state: &mut NativeMemoryCacheState, key: &str) {
    state.variants.retain(|_, variants| {
        variants.retain(|variant| variant.key != key);
        !variants.is_empty()
    });
}

pub(crate) fn with_native_cache_status(
    mut response: NativeHttp1Response,
    cache: &CacheConfig,
    status: &str,
    reason: Option<&str>,
    age_secs: Option<u64>,
) -> NativeHttp1Response {
    if let Some(header) = &cache.status_header {
        response.push_header(header.clone(), status.to_owned());
    }
    if let (Some(header), Some(reason)) = (&cache.status_reason_header, reason) {
        response.push_header(header.clone(), reason.to_owned());
    }
    if let Some(age_secs) = age_secs {
        response.remove_header("age");
        response.push_header("age", age_secs.to_string());
    }
    response
}
