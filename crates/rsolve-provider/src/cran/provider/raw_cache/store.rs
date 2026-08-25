use super::*;
#[cfg(test)]
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rsolve_core::RegistryId;
use sha2::{Digest, Sha256};

use super::super::MAX_RESPONSE_BYTES;
use super::super::transport::TransportResponseHeaders;
use super::SnapshotStore;
use super::key::{canonical_key_digest, is_canonical_endpoint};
use super::wire::{
    hex, parse_hex_32, parse_timestamp, timestamp_string, validate_cache_control, validate_etag,
    validate_last_modified,
};
use super::{
    ENTRY_SUFFIX, MAX_ENTRY_BYTES, MAX_HEADER_BYTES, PROJECTION_DIRECTORY, RAW_CACHE_DIRECTORY,
    RAW_CACHE_FORMAT, RAW_CACHE_VERSION, RawCacheEntry, RawCacheError, RawCacheKey, RawCacheLookup,
    RawCachePublishOutcome, RawCacheRepresentation, RawCacheWrite,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
type RetentionHook = Box<dyn Fn(&Path)>;

#[cfg(test)]
thread_local! {
    static RETENTION_BEFORE_DELETE_HOOK: RefCell<Option<RetentionHook>> =
        const { RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_retention_before_delete_hook(hook: Option<RetentionHook>) {
    RETENTION_BEFORE_DELETE_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(test)]
fn run_retention_before_delete_hook(directory: &Path) {
    let hook = RETENTION_BEFORE_DELETE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(directory);
    }
}

#[cfg(not(test))]
fn run_retention_before_delete_hook(_directory: &Path) {}
struct TemporaryPath(PathBuf);

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub(crate) struct RawCache {
    pub(super) registry_id: RegistryId,
    pub(super) directory: PathBuf,
    directory_fd: cap_std::fs::Dir,
}

impl RawCache {
    pub(crate) fn open(store: &SnapshotStore) -> Result<Self, RawCacheError> {
        let directory = store
            .root()
            .join(RAW_CACHE_DIRECTORY)
            .join(RAW_CACHE_VERSION);
        ensure_directory(&store.root().join(RAW_CACHE_DIRECTORY))?;
        ensure_directory(&directory)?;
        ensure_directory(&directory.join(PROJECTION_DIRECTORY))?;
        let directory_fd = {
            let root_fd =
                cap_std::fs::Dir::open_ambient_dir(store.root(), cap_std::ambient_authority())?;
            let raw_cache_fd =
                cap_fs_ext::DirExt::open_dir_nofollow(&root_fd, RAW_CACHE_DIRECTORY)?;
            cap_fs_ext::DirExt::open_dir_nofollow(&raw_cache_fd, RAW_CACHE_VERSION)?
        };
        Ok(Self {
            registry_id: store.registry_id().clone(),
            directory,
            directory_fd,
        })
    }

    pub(crate) fn key(
        &self,
        endpoint: &str,
        representation: RawCacheRepresentation,
    ) -> Result<RawCacheKey, RawCacheError> {
        RawCacheKey::new(&self.registry_id, endpoint, representation)
    }

    pub(crate) fn projection_path(&self, key: &RawCacheKey, body: &[u8]) -> PathBuf {
        self.projection_path_in_namespace(
            ProjectionNamespace::AllPackages,
            key,
            &hex(&Sha256::digest(body)),
        )
    }

    /// Return a derived projection path scoped to a source namespace. Keeping
    /// source projections in separate directories prevents ALLPACKAGES
    /// retention from deleting unrelated current/archive projections.
    pub(crate) fn projection_path_in_namespace(
        &self,
        namespace: ProjectionNamespace,
        key: &RawCacheKey,
        body_digest: &str,
    ) -> PathBuf {
        let directory = self.projection_namespace_path(namespace);
        if namespace == ProjectionNamespace::AllPackages {
            directory.join(format!("{}-{body_digest}.redb", key.digest()))
        } else {
            directory
                .join(key.digest())
                .join(format!("{body_digest}.redb"))
        }
    }

    pub(crate) fn projection_path_for_digest(
        &self,
        key: &RawCacheKey,
        content_sha256: &[u8; 32],
    ) -> PathBuf {
        self.projection_path_in_namespace(
            ProjectionNamespace::AllPackages,
            key,
            &hex(content_sha256),
        )
    }

    pub(crate) fn projection_path_for_hex_digest(
        &self,
        key: &RawCacheKey,
        content_sha256: &str,
    ) -> Option<PathBuf> {
        if content_sha256.len() != 64
            || !content_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return None;
        }
        Some(
            self.directory
                .join(PROJECTION_DIRECTORY)
                .join(format!("{}-{content_sha256}.redb", key.digest())),
        )
    }

    pub(crate) fn qualification_path(&self) -> PathBuf {
        self.directory.join("qualification.json")
    }

    /// Retain only a bounded set of content-addressed projections. The
    /// currently usable projection and one previous projection are retained;
    /// callers run this under the snapshot refresh transaction and treat
    /// cleanup as best-effort so a failed refresh never removes last-known
    /// good metadata.
    pub(crate) fn retain_projections(
        &self,
        active: &Path,
        previous: Option<&Path>,
    ) -> Result<(), RawCacheError> {
        self.retain_projection_namespace(ProjectionNamespace::AllPackages, active, previous)
    }

    pub(crate) fn retain_projection_namespace(
        &self,
        namespace: ProjectionNamespace,
        active: &Path,
        previous: Option<&Path>,
    ) -> Result<(), RawCacheError> {
        let directory = active
            .parent()
            .ok_or_else(|| RawCacheError::Invalid("projection path has no parent".into()))?;
        self.validate_projection_directory(namespace, directory)?;
        retain_projection_files(&self.directory_fd, namespace, directory, active, previous)
    }

    fn validate_projection_directory(
        &self,
        namespace: ProjectionNamespace,
        directory: &Path,
    ) -> Result<(), RawCacheError> {
        let root = self.directory.join(PROJECTION_DIRECTORY);
        ensure_regular_directory_path(&root, "projection root")?;
        let namespace_path = self.projection_namespace_path(namespace);
        ensure_regular_directory_path(&namespace_path, "projection namespace")?;
        if namespace == ProjectionNamespace::AllPackages {
            if directory != namespace_path {
                return Err(RawCacheError::Invalid(
                    "projection is outside its namespace".into(),
                ));
            }
        } else {
            if directory.parent() != Some(namespace_path.as_path())
                || directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_none_or(|name| {
                        name.len() != 64
                            || !name
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    })
            {
                return Err(RawCacheError::Invalid(
                    "projection is outside its raw-key namespace".into(),
                ));
            }
            ensure_regular_directory_path(directory, "projection raw-key directory")?;
        }
        Ok(())
    }

    pub(crate) fn projection_namespace_path(&self, namespace: ProjectionNamespace) -> PathBuf {
        self.directory
            .join(PROJECTION_DIRECTORY)
            .join(match namespace {
                ProjectionNamespace::AllPackages => "",
                ProjectionNamespace::Current => "current",
                ProjectionNamespace::ArchiveHistory => "archive-history",
                ProjectionNamespace::Auxiliary => "auxiliary",
            })
    }

    pub(crate) fn prepare_projection_path(
        &self,
        namespace: ProjectionNamespace,
        key: &RawCacheKey,
    ) -> Result<(), RawCacheError> {
        ensure_directory(&self.projection_namespace_path(namespace))?;
        if namespace != ProjectionNamespace::AllPackages {
            ensure_directory(&self.projection_namespace_path(namespace).join(key.digest()))?;
        }
        Ok(())
    }

    pub(crate) fn lookup(&self, key: &RawCacheKey) -> RawCacheLookup {
        if let Err(error) = self.validate_key_registry(key) {
            return RawCacheLookup::Corrupt(error.to_string().into_boxed_str());
        }
        let path = self.entry_path(key);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return RawCacheLookup::Missing;
            }
            Err(error) => return RawCacheLookup::Corrupt(error.to_string().into_boxed_str()),
        };
        if !metadata.file_type().is_file() {
            return RawCacheLookup::Corrupt("raw cache entry is not a regular file".into());
        }
        if metadata.len() > MAX_ENTRY_BYTES {
            return RawCacheLookup::Corrupt("raw cache entry exceeds size limit".into());
        }
        match self.read_entry(&path, key, metadata.len()) {
            Ok(entry) => RawCacheLookup::Hit(entry),
            Err(error) => RawCacheLookup::Corrupt(error.to_string().into_boxed_str()),
        }
    }

    pub(crate) fn publish(
        &self,
        key: &RawCacheKey,
        write: RawCacheWrite,
    ) -> Result<RawCachePublishOutcome, RawCacheError> {
        self.validate_key_registry(key)?;
        if write.status != 200 {
            return Err(RawCacheError::Invalid(
                "only HTTP 200 responses may be stored in the raw cache".into(),
            ));
        }
        if !cache_control_policy(&write.cache_control, std::time::Duration::ZERO).can_store() {
            self.remove_entry(key)?;
            return Ok(RawCachePublishOutcome::NoStore);
        }
        let header = self.header_for_write(key, &write)?;
        self.write_entry(key, header, &write.body)?;
        Ok(RawCachePublishOutcome::Stored)
    }

    /// Advance only validation time after a later conditional validation. The
    /// observed time and body identity remain unchanged for a future 304.
    pub(crate) fn update_validated_at(
        &self,
        key: &RawCacheKey,
        validated_at: jiff::Timestamp,
    ) -> Result<(), RawCacheError> {
        self.update_validated_at_with_headers(
            key,
            validated_at,
            &TransportResponseHeaders::default(),
        )
    }

    pub(crate) fn update_validated_at_with_headers(
        &self,
        key: &RawCacheKey,
        validated_at: jiff::Timestamp,
        response_headers: &TransportResponseHeaders,
    ) -> Result<(), RawCacheError> {
        let entry = match self.lookup(key) {
            RawCacheLookup::Hit(entry) => entry,
            RawCacheLookup::Missing => {
                return Err(RawCacheError::Invalid("raw cache entry is missing".into()));
            }
            RawCacheLookup::Corrupt(error) => return Err(RawCacheError::Invalid(error)),
        };
        if validated_at < entry.validated_at {
            return Err(RawCacheError::Invalid(
                "raw cache validation time cannot move backwards".into(),
            ));
        }
        let write = RawCacheWrite {
            status: 200,
            body: entry.body,
            observed_at: entry.observed_at,
            validated_at,
            etag: response_headers.etag.clone().or(entry.etag),
            last_modified: response_headers
                .last_modified
                .clone()
                .or(entry.last_modified),
            cache_control: match &response_headers.cache_control {
                CacheControlHeader::Absent => entry.cache_control,
                _ => response_headers.cache_control.clone(),
            },
        };
        if !cache_control_policy(&write.cache_control, std::time::Duration::ZERO).can_store() {
            self.remove_entry(key)?;
            return Ok(());
        }
        let header = self.header_for_write(key, &write)?;
        self.write_entry(key, header, &write.body)
    }

    fn header_for_write(
        &self,
        key: &RawCacheKey,
        write: &RawCacheWrite,
    ) -> Result<RawCacheHeaderV1, RawCacheError> {
        if write.body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(RawCacheError::Invalid(
                "raw cache response body exceeds size limit".into(),
            ));
        }
        if write.validated_at < write.observed_at {
            return Err(RawCacheError::Invalid(
                "raw cache validation time precedes observation time".into(),
            ));
        }
        validate_cache_control(&write.cache_control)?;
        let observed_at = timestamp_string(write.observed_at)?;
        let validated_at = timestamp_string(write.validated_at)?;
        let header = RawCacheHeaderV1 {
            format: RAW_CACHE_FORMAT.into(),
            version: 1,
            registry_id: self.registry_id.to_string(),
            key_sha256: key.digest.clone().into(),
            endpoint: key.endpoint.clone().into(),
            representation: key.representation,
            body_length: write.body.len() as u64,
            body_sha256: hex(&Sha256::digest(&write.body)),
            observed_at,
            validated_at,
            etag: validate_etag(write.etag.as_deref())?,
            last_modified: validate_last_modified(write.last_modified.as_deref())?,
            cache_control: write.cache_control.clone(),
        };
        Ok(header)
    }

    fn write_entry(
        &self,
        key: &RawCacheKey,
        header: RawCacheHeaderV1,
        body: &[u8],
    ) -> Result<(), RawCacheError> {
        let header_bytes = serde_json::to_vec(&header).map_err(|error| {
            RawCacheError::Invalid(format!("unable to encode raw cache header: {error}").into())
        })?;
        if header_bytes.len() > MAX_HEADER_BYTES {
            return Err(RawCacheError::Invalid(
                "raw cache header exceeds size limit".into(),
            ));
        }
        let path = self.entry_path(key);
        let (temporary, mut file) = self.unique_temp_file()?;
        let _cleanup = TemporaryPath(temporary.clone());
        file.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        file.write_all(&header_bytes)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, &path)?;
        File::open(&path)?.sync_all()?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    fn read_entry(
        &self,
        path: &Path,
        key: &RawCacheKey,
        file_length: u64,
    ) -> Result<RawCacheEntry, RawCacheError> {
        let mut file = File::open(path)?;
        let mut length_bytes = [0_u8; HEADER_LENGTH_BYTES];
        file.read_exact(&mut length_bytes)?;
        let header_length = u32::from_le_bytes(length_bytes) as usize;
        if header_length == 0 || header_length > MAX_HEADER_BYTES {
            return Err(RawCacheError::Invalid(
                "raw cache header length is invalid".into(),
            ));
        }
        let total_prefix = HEADER_LENGTH_BYTES
            .checked_add(header_length)
            .ok_or_else(|| RawCacheError::Invalid("raw cache entry length overflow".into()))?;
        if file_length < total_prefix as u64 {
            return Err(RawCacheError::Invalid(
                "raw cache entry is truncated".into(),
            ));
        }
        let mut header_bytes = vec![0_u8; header_length];
        file.read_exact(&mut header_bytes)?;
        let header: RawCacheHeaderV1 = serde_json::from_slice(&header_bytes).map_err(|error| {
            RawCacheError::Invalid(format!("invalid raw cache header: {error}").into())
        })?;
        if serde_json::to_vec(&header).map_err(|error| {
            RawCacheError::Invalid(format!("invalid raw cache header: {error}").into())
        })? != header_bytes
        {
            return Err(RawCacheError::Invalid(
                "raw cache header is not canonical JSON".into(),
            ));
        }
        self.validate_header(key, &header)?;
        if header.body_length > MAX_RESPONSE_BYTES
            || file_length != total_prefix as u64 + header.body_length
        {
            return Err(RawCacheError::Invalid(
                "raw cache body length is invalid".into(),
            ));
        }
        let mut body = vec![0_u8; header.body_length as usize];
        file.read_exact(&mut body)?;
        if hex(&Sha256::digest(&body)) != header.body_sha256 {
            return Err(RawCacheError::Invalid(
                "raw cache body digest mismatch".into(),
            ));
        }
        let observed_at = parse_timestamp(&header.observed_at)?;
        let validated_at = parse_timestamp(&header.validated_at)?;
        Ok(RawCacheEntry {
            key: key.clone(),
            body,
            observed_at,
            validated_at,
            etag: header.etag.map(String::into_boxed_str),
            last_modified: header.last_modified.map(String::into_boxed_str),
            cache_control: header.cache_control,
        })
    }

    fn validate_header(
        &self,
        key: &RawCacheKey,
        header: &RawCacheHeaderV1,
    ) -> Result<(), RawCacheError> {
        if header.format != RAW_CACHE_FORMAT
            || header.version != 1
            || header.registry_id != self.registry_id.as_str()
            || header.key_sha256 != key.digest()
            || header.endpoint != key.endpoint()
            || header.representation != key.representation()
            || parse_hex_32(&header.key_sha256).is_err()
            || header.body_sha256.len() != 64
            || parse_hex_32(&header.body_sha256).is_err()
            || !is_canonical_endpoint(&header.endpoint)
            || canonical_key_digest(&header.registry_id, &header.endpoint, header.representation)?
                != header.key_sha256
        {
            return Err(RawCacheError::Invalid(
                "raw cache header identity is invalid".into(),
            ));
        }
        let observed_at = parse_timestamp(&header.observed_at)?;
        let validated_at = parse_timestamp(&header.validated_at)?;
        validate_etag(header.etag.as_deref())?;
        validate_last_modified(header.last_modified.as_deref())?;
        validate_cache_control(&header.cache_control)?;
        if validated_at < observed_at {
            return Err(RawCacheError::Invalid(
                "raw cache header metadata is invalid".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn entry_path(&self, key: &RawCacheKey) -> PathBuf {
        self.directory
            .join(format!("{}{}", key.digest(), ENTRY_SUFFIX))
    }

    fn validate_key_registry(&self, key: &RawCacheKey) -> Result<(), RawCacheError> {
        if key.registry_id.as_ref() != self.registry_id.as_str() {
            return Err(RawCacheError::Invalid(
                "raw cache key belongs to another registry".into(),
            ));
        }
        Ok(())
    }

    fn remove_entry(&self, key: &RawCacheKey) -> Result<(), RawCacheError> {
        let path = self.entry_path(key);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
                fs::remove_file(path)?;
                sync_directory(&self.directory)?;
                Ok(())
            }
            Ok(_) => Err(RawCacheError::Invalid(
                "raw cache entry is not removable".into(),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn unique_temp_file(&self) -> Result<(PathBuf, File), RawCacheError> {
        let pid = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| RawCacheError::Invalid(error.to_string().into()))?
            .as_nanos();
        for _ in 0..128 {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = self
                .directory
                .join(format!(".raw-entry-{pid}-{timestamp}-{sequence}.tmp"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(RawCacheError::Invalid(
            "unable to allocate raw cache temporary file".into(),
        ))
    }
}

fn projection_name(path: &Path, label: &str) -> Result<std::ffi::OsString, RawCacheError> {
    let name = path.file_name().ok_or_else(|| {
        RawCacheError::Invalid(format!("{label} projection has no file name").into())
    })?;
    Ok(name.to_os_string())
}

fn require_regular_projection(
    directory: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    label: &str,
) -> Result<(), RawCacheError> {
    let stat = directory.symlink_metadata(name)?;
    if !stat.is_file() {
        return Err(RawCacheError::Invalid(
            format!("{label} package projection is missing or not a regular file").into(),
        ));
    }
    Ok(())
}

fn retain_projection_files(
    cache_directory: &cap_std::fs::Dir,
    namespace: ProjectionNamespace,
    directory: &Path,
    active: &Path,
    previous: Option<&Path>,
) -> Result<(), RawCacheError> {
    use cap_fs_ext::DirExt;

    if active.parent() != Some(directory)
        || previous.is_some_and(|path| path.parent() != Some(directory))
    {
        return Err(RawCacheError::Invalid(
            "projection files must be direct children of their directory".into(),
        ));
    }
    let projections_fd = cache_directory.open_dir_nofollow(PROJECTION_DIRECTORY)?;
    let namespace_fd = match namespace {
        ProjectionNamespace::AllPackages => projections_fd,
        ProjectionNamespace::Current => projections_fd.open_dir_nofollow("current")?,
        ProjectionNamespace::ArchiveHistory => {
            projections_fd.open_dir_nofollow("archive-history")?
        }
        ProjectionNamespace::Auxiliary => projections_fd.open_dir_nofollow("auxiliary")?,
    };
    let directory_fd = if namespace == ProjectionNamespace::AllPackages {
        namespace_fd
    } else {
        let key_name = directory
            .file_name()
            .ok_or_else(|| RawCacheError::Invalid("projection directory has no name".into()))?;
        namespace_fd.open_dir_nofollow(key_name)?
    };
    let active_name = projection_name(active, "active")?;
    require_regular_projection(&directory_fd, &active_name, "active")?;
    let previous_name = previous
        .map(|path| projection_name(path, "previous"))
        .transpose()?;
    if let Some(name) = previous_name.as_ref() {
        require_regular_projection(&directory_fd, name, "previous")?;
    }
    let projection_entries = directory_fd
        .entries()?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".redb"))
        })
        .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_file()))
        .collect::<Vec<_>>();

    // The capability directory pins the original directory object. Even if
    // any path component is replaced with a symlink after this point, entry
    // removal remains relative to the already-open directory.
    run_retention_before_delete_hook(directory);
    for entry in projection_entries {
        if entry.file_name() == active_name
            || previous_name
                .as_ref()
                .is_some_and(|candidate| entry.file_name() == *candidate)
        {
            continue;
        }
        let _ = entry.remove_file();
    }
    // Synchronize the same capability when the platform supports directory
    // synchronization. Cleanup correctness does not depend on this optional
    // durability step.
    if let Ok(file) = directory_fd
        .try_clone()
        .map(cap_std::fs::Dir::into_std_file)
    {
        let _ = file.sync_all();
    }
    Ok(())
}

fn ensure_regular_directory_path(path: &Path, label: &str) -> Result<(), RawCacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(RawCacheError::Invalid(
            format!("{label} is not a regular directory").into(),
        )),
        Err(error) => Err(RawCacheError::Invalid(
            format!("{label} is unavailable: {error}").into(),
        )),
    }
}

fn ensure_directory(path: &Path) -> Result<(), RawCacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(RawCacheError::Invalid(
            "raw cache namespace is not a regular directory".into(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => match fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => ensure_directory(path),
            Err(error) => Err(error.into()),
        },
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), RawCacheError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), RawCacheError> {
    // Windows has no portable directory fsync operation. The file and
    // replacement calls use write-through semantics instead.
    Ok(())
}

#[cfg(unix)]
fn replace_file(from: &Path, to: &Path) -> Result<(), RawCacheError> {
    fs::rename(from, to).map_err(Into::into)
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> Result<(), RawCacheError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let from = from
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let to = to
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
