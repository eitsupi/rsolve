use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory, RegistryId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    ReadOnlySnapshotCandidateLoader, SnapshotBuildInput, SnapshotError, SnapshotGenerationBuilder,
    SnapshotHeaderV1, ValidatedGeneration, decode_header, hex, parse_hex_32, validate_generation,
};

const CURRENT_NAME: &str = "current";
const CURRENT_VALIDATION_NAME: &str = "current-validation";
const REFRESH_LOCK_NAME: &str = "refresh.lock";
const GENERATIONS_DIR: &str = "generations";
const TMP_DIR: &str = "tmp";
const POINTER_LIMIT: usize = 16 * 1024;
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentPointerV1 {
    format: String,
    version: u32,
    registry_id: String,
    generation: String,
    header_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentValidationSourceV2 {
    pub(crate) id: String,
    pub(crate) content_sha256: String,
    pub(crate) endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentValidationV2 {
    pub(crate) format: String,
    pub(crate) version: u32,
    pub(crate) registry_id: String,
    pub(crate) generation: String,
    pub(crate) compatibility_profile: u32,
    pub(crate) parser_schema: u32,
    pub(crate) normalization_policy: u32,
    pub(crate) validated_at: String,
    pub(crate) refresh_sequence: u64,
    pub(crate) effective_endpoint: String,
    pub(crate) sources: Vec<CurrentValidationSourceV2>,
}

struct CurrentValidationFacts {
    registry_id: String,
    compatibility_profile: u32,
    parser_schema: u32,
    normalization_policy: u32,
    validated_at: String,
    effective_endpoint: String,
    sources: Vec<CurrentValidationSourceV2>,
}

fn current_validation_facts(
    input: &SnapshotBuildInput,
) -> Result<CurrentValidationFacts, SnapshotError> {
    let mut sources = input
        .sources
        .iter()
        .map(|source| {
            let observed = super::source_observation(source)?;
            Ok(CurrentValidationSourceV2 {
                id: observed.id,
                content_sha256: observed.content_sha256,
                endpoint: observed.endpoint,
            })
        })
        .collect::<Result<Vec<_>, SnapshotError>>()?;
    sources.sort_by(|left, right| left.id.cmp(&right.id));
    let mut endpoints = sources
        .iter()
        .map(|source| source.endpoint.clone())
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    Ok(CurrentValidationFacts {
        registry_id: input.registry_id.to_string(),
        compatibility_profile: input.compatibility_profile,
        parser_schema: input.parser_schema,
        normalization_policy: input.normalization_policy,
        validated_at: input.created_at.clone(),
        effective_endpoint: endpoints.join("\n"),
        sources,
    })
}

#[derive(Debug)]
pub enum SnapshotStoreError {
    Io(io::Error),
    Invalid(Box<str>),
    Busy,
}

#[derive(Debug)]
pub(crate) enum SnapshotPublishError {
    Build(SnapshotError),
    Store(SnapshotStoreError),
    Reopen(CandidateLoadError),
}

impl fmt::Display for SnapshotPublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(error) => write!(f, "snapshot generation build failed: {error}"),
            Self::Store(error) => write!(f, "snapshot publication failed: {error}"),
            Self::Reopen(error) => write!(f, "published snapshot reopen failed: {error}"),
        }
    }
}

impl std::error::Error for SnapshotPublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Reopen(error) => Some(error),
        }
    }
}

impl fmt::Display for SnapshotStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "snapshot store I/O error: {error}"),
            Self::Invalid(error) => f.write_str(error),
            Self::Busy => f.write_str("snapshot refresh lock is already held"),
        }
    }
}

impl std::error::Error for SnapshotStoreError {}

impl From<io::Error> for SnapshotStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefreshLockMode {
    Blocking,
    Try,
}

#[derive(Debug)]
pub(crate) struct RefreshLock {
    file: File,
    path: PathBuf,
}

/// Owns the store refresh lock across the complete metadata transaction.
/// Network acquisition, composition, publication and retention may all use
/// this guard; callers must not acquire a second refresh lock while it lives.
pub(crate) struct SnapshotRefreshGuard<'a> {
    store: &'a SnapshotStore,
    lock: RefreshLock,
}

pub struct SnapshotStore {
    root: PathBuf,
    registry_id: RegistryId,
}

struct TemporaryPath(PathBuf);

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl SnapshotStore {
    pub fn open(
        root: impl Into<PathBuf>,
        registry_id: RegistryId,
    ) -> Result<Self, SnapshotStoreError> {
        let root = root.into();
        fs::create_dir_all(root.join(GENERATIONS_DIR))?;
        fs::create_dir_all(root.join(TMP_DIR))?;
        Ok(Self { root, registry_id })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn registry_id(&self) -> &RegistryId {
        &self.registry_id
    }

    /// Builds, validates, publishes, and opens one immutable generation while
    /// holding the refresh lock. The resulting loader is pinned before the
    /// lock is released and returned directly after unlock, so a concurrent
    /// publisher cannot change which generation this call returns.
    pub(crate) fn build_and_publish(
        &self,
        input: SnapshotBuildInput,
    ) -> Result<ReadOnlySnapshotCandidateLoader, SnapshotPublishError> {
        self.build_and_publish_inner(input, None, |_| {})
    }

    pub(crate) fn build_and_publish_with_endpoint(
        &self,
        input: SnapshotBuildInput,
        effective_endpoint: impl Into<Box<str>>,
    ) -> Result<ReadOnlySnapshotCandidateLoader, SnapshotPublishError> {
        self.build_and_publish_inner(input, Some(effective_endpoint.into()), |_| {})
    }

    #[cfg(test)]
    pub(crate) fn build_and_publish_with_test_hook<F>(
        &self,
        input: SnapshotBuildInput,
        after_unlock: F,
    ) -> Result<ReadOnlySnapshotCandidateLoader, SnapshotPublishError>
    where
        F: FnOnce(&Self),
    {
        self.build_and_publish_inner(input, None, after_unlock)
    }

    fn build_and_publish_inner<F>(
        &self,
        input: SnapshotBuildInput,
        effective_endpoint: Option<Box<str>>,
        after_unlock: F,
    ) -> Result<ReadOnlySnapshotCandidateLoader, SnapshotPublishError>
    where
        F: FnOnce(&Self),
    {
        let lock = self
            .acquire_refresh_lock(RefreshLockMode::Blocking)
            .map_err(SnapshotPublishError::Store)?;
        let loader = self.build_and_publish_locked(&lock, input, effective_endpoint)?;
        drop(lock);
        after_unlock(self);
        Ok(loader)
    }

    pub(crate) fn build_and_publish_with_refresh_guard(
        &self,
        guard: &SnapshotRefreshGuard<'_>,
        input: SnapshotBuildInput,
        effective_endpoint: impl Into<Box<str>>,
    ) -> Result<ReadOnlySnapshotCandidateLoader, SnapshotPublishError> {
        self.build_and_publish_locked(&guard.lock, input, Some(effective_endpoint.into()))
    }

    fn build_and_publish_locked(
        &self,
        lock: &RefreshLock,
        input: SnapshotBuildInput,
        effective_endpoint: Option<Box<str>>,
    ) -> Result<ReadOnlySnapshotCandidateLoader, SnapshotPublishError> {
        let staging_path = self
            .unique_staging_path()
            .map_err(SnapshotPublishError::Store)?;
        let staging_cleanup = TemporaryPath(staging_path.clone());
        let validation_facts = effective_endpoint
            .as_ref()
            .map(|_| current_validation_facts(&input))
            .transpose()
            .map_err(SnapshotPublishError::Build)?;
        let generation = SnapshotGenerationBuilder::new(input, &staging_path)
            .build()
            .map_err(SnapshotPublishError::Build)?;
        let generation_name = generation.generation().to_owned();
        self.publish_generation(lock, generation)
            .map_err(SnapshotPublishError::Store)?;
        // Pin the generation that this operation published before releasing
        // the lock. A later publisher may replace `current` immediately after
        // unlock, but must not change the loader returned by this operation.
        let loader = self
            .open_generation_locked(&generation_name)
            .map_err(SnapshotPublishError::Reopen)?;
        if let (Some(validation_facts), Some(effective_endpoint)) =
            (validation_facts, effective_endpoint)
        {
            self.write_current_validation(
                lock,
                loader.header(),
                validation_facts,
                Some(effective_endpoint),
            )
            .map_err(SnapshotPublishError::Store)?;
        }
        drop(staging_cleanup);
        Ok(loader)
    }

    fn unique_staging_path(&self) -> Result<PathBuf, SnapshotStoreError> {
        let pid = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| store_invalid(error.to_string()))?
            .as_nanos();
        for _ in 0..128 {
            let sequence = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = self
                .root
                .join(TMP_DIR)
                .join(format!(".rsolve-staged-{pid}-{timestamp}-{sequence}.redb"));
            if !path.exists() {
                return Ok(path);
            }
        }
        Err(store_invalid(
            "unable to allocate a unique snapshot staging path",
        ))
    }

    pub fn read_current(&self) -> Result<ReadOnlySnapshotCandidateLoader, CandidateLoadError> {
        self.read_current_optional()?
            .ok_or_else(|| store_candidate_error("current snapshot pointer is missing"))
    }

    /// Read the current generation, distinguishing an absent pointer from a
    /// present but corrupt or unreadable cache. No repair or network access is
    /// performed.
    pub fn read_current_optional(
        &self,
    ) -> Result<Option<ReadOnlySnapshotCandidateLoader>, CandidateLoadError> {
        // Serialize pointer reads with publication and cleanup.  The loader must be
        // opened while this lock is held so cleanup cannot remove the generation
        // selected by the pointer before the read-only database pins it.
        let _refresh_lock = self
            .acquire_refresh_lock(RefreshLockMode::Blocking)
            .map_err(|error| {
                store_candidate_error(format!("unable to acquire snapshot refresh lock: {error}"))
            })?;
        self.read_current_optional_locked(&_refresh_lock)
    }

    fn read_current_optional_locked(
        &self,
        _refresh_lock: &RefreshLock,
    ) -> Result<Option<ReadOnlySnapshotCandidateLoader>, CandidateLoadError> {
        let pointer_bytes = match read_at_most(&self.root.join(CURRENT_NAME), POINTER_LIMIT) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(store_candidate_error(format!(
                    "unable to read current pointer: {error}"
                )));
            }
        };
        let pointer = decode_pointer(&pointer_bytes, &self.registry_id)?;
        let loader = self.open_generation_locked(&pointer.generation)?;
        let header_bytes = super::encode_header(loader.header()).map_err(|error| {
            store_candidate_error(format!("unable to encode generation header: {error}"))
        })?;
        let actual_header_sha256 = hex(&Sha256::digest(&header_bytes));
        if actual_header_sha256 != pointer.header_sha256 {
            return Err(store_candidate_error(
                "current pointer header digest mismatch",
            ));
        }
        Ok(Some(loader))
    }

    pub(crate) fn read_current_validation(
        &self,
    ) -> Result<Option<CurrentValidationV2>, SnapshotStoreError> {
        let _refresh_lock = self.acquire_refresh_lock(RefreshLockMode::Blocking)?;
        self.read_current_validation_locked(&_refresh_lock)
    }

    fn read_current_validation_locked(
        &self,
        _refresh_lock: &RefreshLock,
    ) -> Result<Option<CurrentValidationV2>, SnapshotStoreError> {
        let bytes = match read_at_most(&self.root.join(CURRENT_VALIDATION_NAME), POINTER_LIMIT) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let record = serde_json::from_slice::<CurrentValidationV2>(&bytes).map_err(|error| {
            store_invalid(format!("invalid current validation record: {error}"))
        })?;
        if serde_json::to_vec(&record)
            .map_err(|error| store_invalid(format!("invalid current validation record: {error}")))?
            != bytes
        {
            return Err(store_invalid(
                "current validation record is not canonical JSON",
            ));
        }
        if record.format != "rsolve-metadata-current-validation" || record.version != 2 {
            return Err(store_invalid(
                "unknown current validation record format or version",
            ));
        }
        if record.registry_id != self.registry_id.as_str()
            || record.generation.len() != 64
            || parse_hex_32(&record.generation).is_err()
            || record.compatibility_profile == 0
            || record.parser_schema == 0
            || record.normalization_policy == 0
            || record.refresh_sequence == 0
            || !super::is_rfc3339_seconds(&record.validated_at)
            || record.effective_endpoint.is_empty()
            || record.sources.is_empty()
            || record
                .sources
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(store_invalid("current validation record is not canonical"));
        }
        if record.sources.iter().any(|source| {
            source.id.len() != 64
                || parse_hex_32(&source.id).is_err()
                || parse_hex_32(&source.content_sha256).is_err()
                || source.endpoint.is_empty()
        }) {
            return Err(store_invalid(
                "current validation source identity is invalid",
            ));
        }
        Ok(Some(record))
    }

    fn write_current_validation(
        &self,
        lock: &RefreshLock,
        header: &SnapshotHeaderV1,
        facts: CurrentValidationFacts,
        effective_endpoint: Option<Box<str>>,
    ) -> Result<(), SnapshotStoreError> {
        if lock.path != self.root.join(REFRESH_LOCK_NAME) {
            return Err(store_invalid("refresh lock belongs to another store"));
        }
        let effective_endpoint = effective_endpoint
            .map(String::from)
            .unwrap_or_else(|| facts.effective_endpoint.clone());
        if effective_endpoint.is_empty() {
            return Err(store_invalid(
                "current validation effective endpoint must not be empty",
            ));
        }
        let refresh_sequence = next_refresh_sequence(
            self.read_current_validation_locked(lock)
                .ok()
                .flatten()
                .map(|record| record.refresh_sequence),
        )?;
        let record = CurrentValidationV2 {
            format: "rsolve-metadata-current-validation".into(),
            version: 2,
            registry_id: facts.registry_id,
            generation: header.generation.clone(),
            compatibility_profile: facts.compatibility_profile,
            parser_schema: facts.parser_schema,
            normalization_policy: facts.normalization_policy,
            validated_at: facts.validated_at,
            refresh_sequence,
            effective_endpoint,
            sources: facts.sources,
        };
        let bytes = serde_json::to_vec(&record).map_err(|error| {
            store_invalid(format!("unable to encode current validation: {error}"))
        })?;
        let (temp, mut file) = self.unique_validation_file()?;
        let temp_cleanup = TemporaryPath(temp.clone());
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        super::replace_file(&temp, &self.root.join(CURRENT_VALIDATION_NAME))
            .map_err(SnapshotStoreError::Io)?;
        sync_file(&self.root.join(CURRENT_VALIDATION_NAME)).map_err(SnapshotStoreError::Io)?;
        sync_directory(&self.root).map_err(SnapshotStoreError::Io)?;
        drop(temp_cleanup);
        Ok(())
    }

    fn unique_validation_file(&self) -> Result<(PathBuf, File), SnapshotStoreError> {
        let pid = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| store_invalid(error.to_string()))?
            .as_nanos();
        for sequence in 0..128_u32 {
            let path = self.root.join(format!(
                ".rsolve-current-validation-{pid}-{timestamp}-{sequence}.tmp"
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(store_invalid(
            "unable to allocate current validation temp file",
        ))
    }

    fn open_generation_locked(
        &self,
        generation: &str,
    ) -> Result<ReadOnlySnapshotCandidateLoader, CandidateLoadError> {
        let generation_path = self
            .root
            .join(GENERATIONS_DIR)
            .join(format!("{generation}.redb"));
        let loader =
            ReadOnlySnapshotCandidateLoader::open(&generation_path, self.registry_id.clone())?;
        if loader.header().registry_id != self.registry_id.as_str()
            || loader.header().generation != generation
        {
            return Err(store_candidate_error(
                "generation identity does not match the requested store generation",
            ));
        }
        Ok(loader)
    }

    pub(crate) fn acquire_refresh_lock(
        &self,
        mode: RefreshLockMode,
    ) -> Result<RefreshLock, SnapshotStoreError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join(REFRESH_LOCK_NAME))?;
        match mode {
            RefreshLockMode::Blocking => file.lock().map_err(SnapshotStoreError::Io)?,
            RefreshLockMode::Try => match file.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => return Err(SnapshotStoreError::Busy),
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(SnapshotStoreError::Io(error));
                }
            },
        }
        Ok(RefreshLock {
            file,
            path: self.root.join(REFRESH_LOCK_NAME),
        })
    }

    pub(crate) fn begin_refresh(&self) -> Result<SnapshotRefreshGuard<'_>, SnapshotStoreError> {
        let lock = self.acquire_refresh_lock(RefreshLockMode::Blocking)?;
        Ok(SnapshotRefreshGuard { store: self, lock })
    }

    pub(crate) fn publish_generation(
        &self,
        lock: &RefreshLock,
        generation: ValidatedGeneration,
    ) -> Result<(), SnapshotStoreError> {
        if lock.path != self.root.join(REFRESH_LOCK_NAME) {
            return Err(store_invalid("refresh lock belongs to another store"));
        }
        let staged_path = generation.path().to_path_buf();
        let tmp_root = self.root.join(TMP_DIR);
        if staged_path.parent() != Some(tmp_root.as_path()) || !is_regular_file(&staged_path) {
            return Err(store_invalid(
                "validated generation is not a store-owned staged file",
            ));
        }
        let header_bytes = generation.header_bytes();
        let header = decode_header(header_bytes).map_err(store_invalid)?;
        if header.registry_id != self.registry_id.as_str()
            || header.generation != generation.generation()
        {
            return Err(store_invalid("validated generation does not match store"));
        }
        let source_header =
            validate_generation(&staged_path, &self.registry_id).map_err(store_invalid)?;
        if source_header != header {
            return Err(store_invalid("validated generation changed"));
        }
        sync_file(&staged_path).map_err(SnapshotStoreError::Io)?;
        let final_path = self
            .root
            .join(GENERATIONS_DIR)
            .join(format!("{}.redb", generation.generation()));
        let final_is_regular = match fs::symlink_metadata(&final_path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(store_invalid("generation path is not a regular file"));
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let (final_header, staged_reused) = if final_is_regular {
            let existing_header = super::read_generation_header(&final_path)
                .and_then(|bytes| super::decode_header(&bytes))
                .ok();
            match existing_header {
                Some(existing_header) => {
                    if !same_semantic_generation(&existing_header, &header) {
                        return Err(store_invalid("generation filename collision"));
                    }
                    if validate_generation(&final_path, &self.registry_id).is_ok() {
                        (
                            super::encode_header(&existing_header).map_err(store_invalid)?,
                            true,
                        )
                    } else {
                        super::replace_file(&staged_path, &final_path)
                            .map_err(SnapshotStoreError::Io)?;
                        sync_file(&final_path).map_err(SnapshotStoreError::Io)?;
                        (header_bytes.to_vec(), false)
                    }
                }
                None => {
                    super::replace_file(&staged_path, &final_path)
                        .map_err(SnapshotStoreError::Io)?;
                    sync_file(&final_path).map_err(SnapshotStoreError::Io)?;
                    (header_bytes.to_vec(), false)
                }
            }
        } else {
            super::replace_file(&staged_path, &final_path).map_err(SnapshotStoreError::Io)?;
            sync_file(&final_path).map_err(SnapshotStoreError::Io)?;
            (header_bytes.to_vec(), false)
        };
        if staged_reused {
            fs::remove_file(&staged_path)?;
        }
        sync_directory(&self.root.join(GENERATIONS_DIR)).map_err(SnapshotStoreError::Io)?;
        let pointer = CurrentPointerV1 {
            format: "rsolve-metadata-current".into(),
            version: 1,
            registry_id: self.registry_id.to_string(),
            generation: header.generation.clone(),
            header_sha256: hex(&Sha256::digest(&final_header)),
        };
        publish_pointer(&self.root, &pointer)?;
        Ok(())
    }

    pub(crate) fn cleanup(
        &self,
        lock: &RefreshLock,
        retain_generations: &[&str],
    ) -> Result<(), SnapshotStoreError> {
        if lock.path != self.root.join(REFRESH_LOCK_NAME) {
            return Err(store_invalid("refresh lock belongs to another store"));
        }
        let current = match self.current_generation_name() {
            Ok(current) => current,
            Err(SnapshotStoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let retained = |generation: &str| {
            current.as_deref() == Some(generation) || retain_generations.contains(&generation)
        };
        for entry in fs::read_dir(self.root.join(TMP_DIR))? {
            let path = entry?.path();
            remove_regular_file(&path);
        }
        for entry in fs::read_dir(&self.root)? {
            let path = entry?.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if file_name.starts_with(".rsolve-current-") && file_name.ends_with(".tmp") {
                remove_regular_file(&path);
            }
        }
        for entry in fs::read_dir(self.root.join(GENERATIONS_DIR))? {
            let path = entry?.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(generation) = file_name.strip_suffix(".redb") else {
                continue;
            };
            if !retained(generation) && parse_hex_32(generation).is_ok() && is_regular_file(&path) {
                remove_regular_file(&path);
            }
        }
        Ok(())
    }

    fn current_generation_name(&self) -> Result<Option<String>, SnapshotStoreError> {
        let bytes = match read_at_most(&self.root.join(CURRENT_NAME), POINTER_LIMIT) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let pointer = decode_pointer_store(&bytes, &self.registry_id)?;
        Ok(Some(pointer.generation))
    }
}

impl SnapshotRefreshGuard<'_> {
    pub(crate) fn store(&self) -> &SnapshotStore {
        self.store
    }

    pub(crate) fn read_current_optional(
        &self,
    ) -> Result<Option<ReadOnlySnapshotCandidateLoader>, CandidateLoadError> {
        self.store.read_current_optional_locked(&self.lock)
    }

    pub(crate) fn read_current_validation(
        &self,
    ) -> Result<Option<CurrentValidationV2>, SnapshotStoreError> {
        self.store.read_current_validation_locked(&self.lock)
    }

    pub(crate) fn cleanup(&self, retain_generations: &[&str]) -> Result<(), SnapshotStoreError> {
        self.store.cleanup(&self.lock, retain_generations)
    }
}

fn same_semantic_generation(existing: &SnapshotHeaderV1, expected: &SnapshotHeaderV1) -> bool {
    existing.format == expected.format
        && existing.version == expected.version
        && existing.history_encoding == expected.history_encoding
        && existing.normalization_policy == expected.normalization_policy
        && existing.compatibility_profile == expected.compatibility_profile
        && existing.parser_schema == expected.parser_schema
        && existing.registry_id == expected.registry_id
        && existing.generation == expected.generation
        && existing.coverage == expected.coverage
        && existing
            .sources
            .iter()
            .map(|source| &source.id)
            .collect::<Vec<_>>()
            == expected
                .sources
                .iter()
                .map(|source| &source.id)
                .collect::<Vec<_>>()
        && existing.package_count == expected.package_count
        && existing.observation_count == expected.observation_count
        && existing.eligible_release_count == expected.eligible_release_count
        && existing.incomplete_package_count == expected.incomplete_package_count
        && existing.history_manifest_sha256 == expected.history_manifest_sha256
}

fn decode_pointer(
    bytes: &[u8],
    configured_registry_id: &RegistryId,
) -> Result<CurrentPointerV1, CandidateLoadError> {
    decode_pointer_store(bytes, configured_registry_id)
        .map_err(|error| store_candidate_error(error.to_string()))
}

fn decode_pointer_store(
    bytes: &[u8],
    configured_registry_id: &RegistryId,
) -> Result<CurrentPointerV1, SnapshotStoreError> {
    if bytes.len() > POINTER_LIMIT {
        return Err(store_invalid("current pointer exceeds byte limit"));
    }
    let pointer: CurrentPointerV1 =
        serde_json::from_slice(bytes).map_err(|error| store_invalid(error.to_string()))?;
    let canonical =
        serde_json::to_vec(&pointer).map_err(|error| store_invalid(error.to_string()))?;
    if canonical != bytes {
        return Err(store_invalid("current pointer is not canonical JSON"));
    }
    if pointer.format != "rsolve-metadata-current" || pointer.version != 1 {
        return Err(store_invalid("unknown current pointer format or version"));
    }
    let pointer_registry =
        RegistryId::new(&pointer.registry_id).map_err(|error| store_invalid(error.to_string()))?;
    if pointer_registry != *configured_registry_id {
        return Err(store_invalid("current pointer registry mismatch"));
    }
    parse_hex_32(&pointer.generation).map_err(store_invalid)?;
    parse_hex_32(&pointer.header_sha256).map_err(store_invalid)?;
    if pointer.generation.contains('/')
        || pointer.generation.contains('\\')
        || pointer.generation.contains('.')
    {
        return Err(store_invalid(
            "current pointer generation is not a filename id",
        ));
    }
    Ok(pointer)
}

/// Read at most `max_bytes` while retaining one extra byte to detect overflow.
fn read_at_most(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "bounded read limit overflow")
    })?;
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(read_limit);
    file.take(read_limit as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn publish_pointer(root: &Path, pointer: &CurrentPointerV1) -> Result<(), SnapshotStoreError> {
    let bytes = serde_json::to_vec(pointer).map_err(|error| store_invalid(error.to_string()))?;
    if bytes.len() > POINTER_LIMIT {
        return Err(store_invalid("current pointer exceeds byte limit"));
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| store_invalid(error.to_string()))?
        .as_nanos();
    let temp_path = root.join(format!(".rsolve-current-{nonce}.tmp"));
    let _temporary_path = TemporaryPath(temp_path.clone());
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)?;
    file.write_all(&bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    replace_file(&temp_path, &root.join(CURRENT_NAME))?;
    sync_directory(root).map_err(SnapshotStoreError::Io)
}

fn sync_file(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn replace_file(from: &Path, to: &Path) -> Result<(), SnapshotStoreError> {
    fs::rename(from, to).map_err(Into::into)
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> Result<(), SnapshotStoreError> {
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
    if unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(SnapshotStoreError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn store_invalid(error: impl fmt::Display) -> SnapshotStoreError {
    SnapshotStoreError::Invalid(error.to_string().into_boxed_str())
}

fn next_refresh_sequence(previous: Option<u64>) -> Result<u64, SnapshotStoreError> {
    previous
        .map_or(Some(1), |sequence| sequence.checked_add(1))
        .ok_or_else(|| store_invalid("current validation refresh sequence overflow"))
}

fn store_candidate_error(error: impl fmt::Display) -> CandidateLoadError {
    CandidateLoadError::new(
        CandidateLoadErrorCategory::SnapshotInvalid,
        error.to_string(),
    )
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn remove_regular_file(path: &Path) {
    if is_regular_file(path) {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::next_refresh_sequence;

    #[test]
    fn refresh_sequence_has_deterministic_boundaries() {
        assert_eq!(next_refresh_sequence(None).unwrap(), 1);
        assert_eq!(next_refresh_sequence(Some(0)).unwrap(), 1);
        assert_eq!(next_refresh_sequence(Some(u64::MAX - 1)).unwrap(), u64::MAX);
        assert!(next_refresh_sequence(Some(u64::MAX)).is_err());
    }
}
