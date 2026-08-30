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
    PreparedGeneration, ReadOnlySnapshotCandidateLoader, SnapshotBuildInput, SnapshotError,
    SnapshotGenerationBuilder, SnapshotHeaderV1, ValidatedGeneration, decode_header, hex,
    parse_hex_32, validate_generation,
};

const VIEWS_DIR: &str = "views";
const REFRESH_LOCK_NAME: &str = "refresh.lock";
const GENERATIONS_DIR: &str = "generations";
const TMP_DIR: &str = "tmp";
const VIEW_HEAD_LIMIT: usize = 1024 * 1024;
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewCoverageV1 {
    state: String,
    scope: String,
    freshness: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewValidationFieldsV1 {
    compatibility_profile: u32,
    parser_schema: u32,
    normalization_policy: u32,
    validated_at: String,
    refresh_sequence: u64,
    effective_endpoint: String,
    sources: Vec<ViewValidationSourceV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewHeadV1 {
    format: String,
    version: u32,
    registry_id: String,
    view_key: String,
    coverage: ViewCoverageV1,
    generation: String,
    header_sha256: String,
    validation: ViewValidationFieldsV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewValidationSourceV1 {
    pub(crate) id: String,
    pub(crate) content_sha256: String,
    pub(crate) endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewValidationV1 {
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
    pub(crate) sources: Vec<ViewValidationSourceV1>,
}

struct ViewValidationInput {
    registry_id: String,
    compatibility_profile: u32,
    parser_schema: u32,
    normalization_policy: u32,
    validated_at: String,
    effective_endpoint: String,
    sources: Vec<ViewValidationSourceV1>,
}

fn view_validation_facts(input: &SnapshotBuildInput) -> Result<ViewValidationInput, SnapshotError> {
    let mut sources = input
        .sources
        .iter()
        .map(|source| {
            let observed = super::source_observation(source)?;
            Ok(ViewValidationSourceV1 {
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
    Ok(ViewValidationInput {
        registry_id: input.registry_id.to_string(),
        compatibility_profile: input.compatibility_profile,
        parser_schema: input.parser_schema,
        normalization_policy: input.normalization_policy,
        validated_at: input.created_at.clone(),
        effective_endpoint: endpoints.join("\n"),
        sources,
    })
}

pub(crate) fn view_key_for_parts(
    registry_id: &RegistryId,
    state: &str,
    scope: &str,
    freshness: &str,
    effective_endpoint: &str,
) -> Box<str> {
    let mut digest = Sha256::new();
    for part in [
        b"rsolve.metadata-view-key\0v1".as_slice(),
        registry_id.as_str().as_bytes(),
        state.as_bytes(),
        scope.as_bytes(),
        freshness.as_bytes(),
        effective_endpoint.as_bytes(),
    ] {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    hex(&digest.finalize()).into_boxed_str()
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
        fs::create_dir_all(root.join(VIEWS_DIR))?;
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
        let derived_endpoint = view_validation_facts(&input)
            .map_err(SnapshotPublishError::Build)?
            .effective_endpoint;
        let effective_endpoint = effective_endpoint.or_else(|| Some(derived_endpoint.into()));
        let generation = SnapshotGenerationBuilder::new(input, &staging_path)
            .prepare_staged()
            .map_err(SnapshotPublishError::Build)?;
        let generation_name = generation.generation().to_owned();
        self.publish_prepared_generation(lock, generation, effective_endpoint)
            .map_err(SnapshotPublishError::Store)?;
        // Pin the generation that this operation published before releasing
        // the lock. A later publisher may replace the selected view immediately after
        // unlock, but must not change the loader returned by this operation.
        let loader = self
            .open_generation_locked(&generation_name)
            .map_err(SnapshotPublishError::Reopen)?;
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

    pub fn read_latest_view(&self) -> Result<ReadOnlySnapshotCandidateLoader, CandidateLoadError> {
        self.read_latest_view_optional()?
            .ok_or_else(|| store_candidate_error("snapshot view head is missing"))
    }

    pub(crate) fn read_view_optional(
        &self,
        view_key: &str,
    ) -> Result<Option<ReadOnlySnapshotCandidateLoader>, CandidateLoadError> {
        let refresh_lock = self
            .acquire_refresh_lock(RefreshLockMode::Blocking)
            .map_err(|error| {
                store_candidate_error(format!("unable to acquire snapshot refresh lock: {error}"))
            })?;
        self.read_view_optional_locked(&refresh_lock, view_key)
            .map(|result| result.map(|(_, loader)| loader))
    }

    pub(crate) fn read_view_with_validation(
        &self,
        view_key: &str,
    ) -> Result<Option<(ReadOnlySnapshotCandidateLoader, ViewValidationV1)>, CandidateLoadError>
    {
        let refresh_lock = self
            .acquire_refresh_lock(RefreshLockMode::Blocking)
            .map_err(|error| {
                store_candidate_error(format!("unable to acquire snapshot refresh lock: {error}"))
            })?;
        self.read_view_optional_locked(&refresh_lock, view_key)
            .map(|result| result.map(|(head, loader)| (loader, validation_record(&head))))
    }

    pub(crate) fn read_view_for_endpoint(
        &self,
        endpoint: &str,
    ) -> Result<Option<(ReadOnlySnapshotCandidateLoader, ViewValidationV1)>, CandidateLoadError>
    {
        let refresh_lock = self
            .acquire_refresh_lock(RefreshLockMode::Blocking)
            .map_err(|error| {
                store_candidate_error(format!("unable to acquire snapshot refresh lock: {error}"))
            })?;
        self.read_view_for_endpoint_locked(&refresh_lock, endpoint)
            .map(|result| result.map(|(head, loader)| (loader, validation_record(&head))))
    }

    pub fn read_latest_view_optional(
        &self,
    ) -> Result<Option<ReadOnlySnapshotCandidateLoader>, CandidateLoadError> {
        let refresh_lock = self
            .acquire_refresh_lock(RefreshLockMode::Blocking)
            .map_err(|error| {
                store_candidate_error(format!("unable to acquire snapshot refresh lock: {error}"))
            })?;
        self.read_latest_view_head_optional_locked(&refresh_lock)
            .map(|result| result.map(|(_, loader)| loader))
    }

    pub(crate) fn has_view_heads(&self) -> Result<bool, SnapshotStoreError> {
        let views = match fs::read_dir(self.root.join(VIEWS_DIR)) {
            Ok(views) => views,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(SnapshotStoreError::Io(error)),
        };
        for entry in views {
            let path = entry?.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read_latest_view_head_optional_locked(
        &self,
        refresh_lock: &RefreshLock,
    ) -> Result<Option<(ViewHeadV1, ReadOnlySnapshotCandidateLoader)>, CandidateLoadError> {
        let views = match fs::read_dir(self.root.join(VIEWS_DIR)) {
            Ok(views) => views,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(store_candidate_error(format!(
                    "unable to read snapshot views: {error}"
                )));
            }
        };
        let mut candidates = Vec::new();
        let mut invalid = false;
        for entry in views {
            let path = entry
                .map_err(|error| {
                    store_candidate_error(format!("unable to enumerate snapshot views: {error}"))
                })?
                .path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let Some(file_name) = path.file_stem().and_then(|name| name.to_str()) else {
                invalid = true;
                continue;
            };
            match self.read_view_optional_locked(refresh_lock, file_name) {
                Ok(Some(candidate)) => candidates.push(candidate),
                Ok(None) => {}
                Err(_) => invalid = true,
            }
        }
        if candidates.is_empty() {
            return if invalid {
                Err(store_candidate_error("all snapshot view heads are invalid"))
            } else {
                Ok(None)
            };
        }
        candidates.sort_by(|left, right| {
            left.0
                .validation
                .refresh_sequence
                .cmp(&right.0.validation.refresh_sequence)
                .then_with(|| left.0.view_key.cmp(&right.0.view_key))
        });
        Ok(candidates.pop())
    }

    pub(crate) fn read_latest_view_validation(
        &self,
    ) -> Result<Option<ViewValidationV1>, SnapshotStoreError> {
        let refresh_lock = self.acquire_refresh_lock(RefreshLockMode::Blocking)?;
        self.read_latest_view_validation_locked(&refresh_lock)
    }

    fn read_latest_view_validation_locked(
        &self,
        refresh_lock: &RefreshLock,
    ) -> Result<Option<ViewValidationV1>, SnapshotStoreError> {
        Ok(self
            .read_latest_view_head_optional_locked(refresh_lock)
            .map_err(|error| store_invalid(error.to_string()))?
            .map(|(head, _)| validation_record(&head)))
    }

    pub(crate) fn read_latest_view_validation_revision(
        &self,
    ) -> Result<Option<Box<str>>, SnapshotStoreError> {
        let refresh_lock = self.acquire_refresh_lock(RefreshLockMode::Blocking)?;
        Ok(self
            .read_latest_view_validation_locked(&refresh_lock)?
            .map(|record| view_validation_revision_token(&record)))
    }

    /// Reads the latest validation fact without waiting for the refresh lock.
    /// This is used only as an opaque pre-wait observation by refresh callers;
    /// the locked view reader remains the authoritative validation boundary.
    pub(crate) fn read_latest_view_validation_revision_unlocked(
        &self,
    ) -> Result<Option<Box<str>>, SnapshotStoreError> {
        self.read_view_validation_revision_unlocked(None)
    }

    pub(crate) fn read_view_validation_revision_for_endpoint_unlocked(
        &self,
        endpoint: &str,
    ) -> Result<Option<Box<str>>, SnapshotStoreError> {
        self.read_view_validation_revision_unlocked(Some(endpoint))
    }

    fn read_view_validation_revision_unlocked(
        &self,
        endpoint: Option<&str>,
    ) -> Result<Option<Box<str>>, SnapshotStoreError> {
        let views = match fs::read_dir(self.root.join(VIEWS_DIR)) {
            Ok(views) => views,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(SnapshotStoreError::Io(error)),
        };
        let mut latest: Option<ViewHeadV1> = None;
        let mut malformed = false;
        for entry in views {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(_error) if endpoint.is_some() => {
                    malformed = true;
                    continue;
                }
                Err(error) => return Err(SnapshotStoreError::Io(error)),
            };
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let Some(view_key) = path.file_stem().and_then(|name| name.to_str()) else {
                if endpoint.is_some() {
                    malformed = true;
                    continue;
                }
                continue;
            };
            let bytes = match read_at_most(&path, VIEW_HEAD_LIMIT) {
                Ok(bytes) => bytes,
                Err(_error) if endpoint.is_some() => {
                    malformed = true;
                    continue;
                }
                Err(error) => return Err(SnapshotStoreError::Io(error)),
            };
            let head = match decode_view_head(&bytes, &self.registry_id) {
                Ok(head) => head,
                Err(_error) if endpoint.is_some() => {
                    malformed = true;
                    continue;
                }
                Err(error) => return Err(store_invalid(error.to_string())),
            };
            if head.view_key != view_key {
                if endpoint.is_some() {
                    malformed = true;
                    continue;
                }
                return Err(store_invalid(
                    "snapshot view filename does not match its key",
                ));
            }
            if endpoint.is_some_and(|expected| {
                !view_endpoint_matches(&head.validation.effective_endpoint, expected)
            }) {
                continue;
            }
            if latest.as_ref().is_none_or(|current| {
                (head.validation.refresh_sequence, &head.view_key)
                    > (current.validation.refresh_sequence, &current.view_key)
            }) {
                latest = Some(head);
            }
        }
        if latest.is_none() && malformed {
            return Err(store_invalid(
                "snapshot view validation observation is malformed",
            ));
        }
        Ok(latest.map(|head| view_validation_revision_token(&validation_record(&head))))
    }

    fn read_view_optional_locked(
        &self,
        _refresh_lock: &RefreshLock,
        view_key: &str,
    ) -> Result<Option<(ViewHeadV1, ReadOnlySnapshotCandidateLoader)>, CandidateLoadError> {
        if view_key.len() != 64 || parse_hex_32(view_key).is_err() {
            return Err(store_candidate_error("snapshot view key is invalid"));
        }
        let path = self.root.join(VIEWS_DIR).join(format!("{view_key}.json"));
        let bytes = match read_at_most(&path, VIEW_HEAD_LIMIT) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(store_candidate_error(format!(
                    "unable to read snapshot view: {error}"
                )));
            }
        };
        let head = decode_view_head(&bytes, &self.registry_id)?;
        if head.view_key != view_key {
            return Err(store_candidate_error(
                "snapshot view filename does not match its key",
            ));
        }
        let expected_key = view_key_for_parts(
            &self.registry_id,
            &head.coverage.state,
            &head.coverage.scope,
            &head.coverage.freshness,
            &head.validation.effective_endpoint,
        );
        if expected_key.as_ref() != head.view_key {
            return Err(store_candidate_error(
                "snapshot view key does not match its contents",
            ));
        }
        let loader = self.open_generation_locked(&head.generation)?;
        let header_bytes = super::encode_header(loader.header()).map_err(|error| {
            store_candidate_error(format!("unable to encode generation header: {error}"))
        })?;
        if hex(&Sha256::digest(&header_bytes)) != head.header_sha256
            || loader.header().coverage.state != head.coverage.state
            || loader.header().coverage.scope != head.coverage.scope
            || loader.header().coverage.freshness != head.coverage.freshness
            || loader.header().compatibility_profile != head.validation.compatibility_profile
            || loader.header().parser_schema != head.validation.parser_schema
            || loader.header().normalization_policy != head.validation.normalization_policy
        {
            return Err(store_candidate_error(
                "snapshot view validation does not match generation",
            ));
        }
        Ok(Some((head, loader)))
    }

    fn read_view_for_endpoint_locked(
        &self,
        refresh_lock: &RefreshLock,
        endpoint: &str,
    ) -> Result<Option<(ViewHeadV1, ReadOnlySnapshotCandidateLoader)>, CandidateLoadError> {
        let views = match fs::read_dir(self.root.join(VIEWS_DIR)) {
            Ok(views) => views,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(store_candidate_error(format!(
                    "unable to read snapshot views: {error}"
                )));
            }
        };
        let mut matching = Vec::new();
        let mut invalid = false;
        for entry in views {
            let path = entry
                .map_err(|error| {
                    store_candidate_error(format!("unable to enumerate snapshot views: {error}"))
                })?
                .path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let Some(view_key) = path.file_stem().and_then(|name| name.to_str()) else {
                continue;
            };
            match self.read_view_optional_locked(refresh_lock, view_key) {
                Ok(Some((head, loader)))
                    if view_endpoint_matches(&head.validation.effective_endpoint, endpoint) =>
                {
                    matching.push((head, loader));
                }
                Ok(_) => {}
                Err(_) => invalid = true,
            }
        }
        matching.sort_by(|left, right| {
            left.0
                .validation
                .refresh_sequence
                .cmp(&right.0.validation.refresh_sequence)
                .then_with(|| left.0.view_key.cmp(&right.0.view_key))
        });
        if matching.is_empty() && invalid {
            return Err(store_candidate_error(
                "all snapshot views for the requested endpoint are invalid",
            ));
        }
        Ok(matching.pop())
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

    pub(crate) fn try_begin_refresh(
        &self,
    ) -> Result<Option<SnapshotRefreshGuard<'_>>, SnapshotStoreError> {
        let lock = match self.acquire_refresh_lock(RefreshLockMode::Try) {
            Ok(lock) => lock,
            Err(SnapshotStoreError::Busy) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(Some(SnapshotRefreshGuard { store: self, lock }))
    }

    pub(crate) fn publish_generation(
        &self,
        lock: &RefreshLock,
        generation: ValidatedGeneration,
    ) -> Result<(), SnapshotStoreError> {
        let staged_path = generation.path().to_path_buf();
        let header_bytes = generation.header_bytes().to_vec();
        let header = self.validate_staged_generation(
            lock,
            &staged_path,
            generation.generation(),
            &header_bytes,
            "validated generation",
        )?;
        self.publish_staged_generation(lock, staged_path, header, header_bytes, None)
    }

    fn publish_prepared_generation(
        &self,
        lock: &RefreshLock,
        generation: PreparedGeneration,
        effective_endpoint: Option<Box<str>>,
    ) -> Result<(), SnapshotStoreError> {
        let staged_path = generation.path().to_path_buf();
        let header = self.validate_staged_generation(
            lock,
            &staged_path,
            generation.generation(),
            generation.header_bytes(),
            "prepared generation",
        )?;
        if header != *generation.header() {
            return Err(store_invalid("prepared generation metadata changed"));
        }
        self.publish_staged_generation(
            lock,
            staged_path,
            header,
            generation.header_bytes().to_vec(),
            effective_endpoint,
        )
    }

    fn validate_staged_generation(
        &self,
        lock: &RefreshLock,
        staged_path: &Path,
        generation_name: &str,
        header_bytes: &[u8],
        label: &str,
    ) -> Result<SnapshotHeaderV1, SnapshotStoreError> {
        if lock.path != self.root.join(REFRESH_LOCK_NAME) {
            return Err(store_invalid("refresh lock belongs to another store"));
        }
        let tmp_root = self.root.join(TMP_DIR);
        if staged_path.parent() != Some(tmp_root.as_path()) || !is_regular_file(staged_path) {
            return Err(store_invalid(format!(
                "{label} is not a store-owned staged file"
            )));
        }
        let header = decode_header(header_bytes).map_err(store_invalid)?;
        if header.registry_id != self.registry_id.as_str() || header.generation != generation_name {
            return Err(store_invalid(format!("{label} does not match store")));
        }
        let source_header =
            validate_generation(staged_path, &self.registry_id).map_err(store_invalid)?;
        if source_header != header {
            return Err(store_invalid(format!("{label} changed")));
        }
        Ok(header)
    }

    fn publish_staged_generation(
        &self,
        lock: &RefreshLock,
        staged_path: PathBuf,
        header: SnapshotHeaderV1,
        header_bytes: Vec<u8>,
        effective_endpoint: Option<Box<str>>,
    ) -> Result<(), SnapshotStoreError> {
        if lock.path != self.root.join(REFRESH_LOCK_NAME) {
            return Err(store_invalid("refresh lock belongs to another store"));
        }
        let tmp_root = self.root.join(TMP_DIR);
        if staged_path.parent() != Some(tmp_root.as_path()) || !is_regular_file(&staged_path) {
            return Err(store_invalid("generation is not a store-owned staged file"));
        }
        sync_file(&staged_path).map_err(SnapshotStoreError::Io)?;
        let final_path = self
            .root
            .join(GENERATIONS_DIR)
            .join(format!("{}.redb", header.generation));
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
        let endpoint = effective_endpoint
            .map(String::from)
            .or_else(|| {
                header
                    .sources
                    .iter()
                    .map(|source| source.endpoint.clone())
                    .min()
            })
            .ok_or_else(|| store_invalid("snapshot view endpoint must not be empty"))?;
        let previous_sequence = self
            .read_latest_view_validation_locked(lock)?
            .map(|record| record.refresh_sequence);
        let sequence = next_refresh_sequence(previous_sequence)?;
        let validation = ViewValidationFieldsV1 {
            compatibility_profile: header.compatibility_profile,
            parser_schema: header.parser_schema,
            normalization_policy: header.normalization_policy,
            validated_at: header.created_at.clone(),
            refresh_sequence: sequence,
            effective_endpoint: endpoint,
            sources: header
                .sources
                .iter()
                .map(|source| ViewValidationSourceV1 {
                    id: source.id.clone(),
                    content_sha256: source.content_sha256.clone(),
                    endpoint: source.endpoint.clone(),
                })
                .collect(),
        };
        let view_key = view_key_for_parts(
            &self.registry_id,
            &header.coverage.state,
            &header.coverage.scope,
            &header.coverage.freshness,
            &validation.effective_endpoint,
        );
        let head = ViewHeadV1 {
            format: "rsolve-metadata-view".into(),
            version: 1,
            registry_id: self.registry_id.to_string(),
            view_key: view_key.into_string(),
            coverage: ViewCoverageV1 {
                state: header.coverage.state.clone(),
                scope: header.coverage.scope.clone(),
                freshness: header.coverage.freshness.clone(),
            },
            generation: header.generation.clone(),
            header_sha256: hex(&Sha256::digest(&final_header)),
            validation,
        };
        publish_view_head(&self.root, &head)?;
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
        let mut retained_generations = retain_generations
            .iter()
            .map(|generation| (*generation).to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        if let Ok(entries) = fs::read_dir(self.root.join(VIEWS_DIR)) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                let Some(key) = path.file_stem().and_then(|name| name.to_str()) else {
                    continue;
                };
                if let Ok(Some((head, _))) = self.read_view_optional_locked(lock, key) {
                    retained_generations.insert(head.generation);
                }
            }
        }
        for entry in fs::read_dir(self.root.join(TMP_DIR))? {
            let path = entry?.path();
            remove_regular_file(&path);
        }
        for entry in fs::read_dir(self.root.join(GENERATIONS_DIR))? {
            let path = entry?.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(generation) = file_name.strip_suffix(".redb") else {
                continue;
            };
            if !retained_generations.contains(generation)
                && parse_hex_32(generation).is_ok()
                && is_regular_file(&path)
            {
                remove_regular_file(&path);
            }
        }
        Ok(())
    }
}

impl SnapshotRefreshGuard<'_> {
    pub(crate) fn store(&self) -> &SnapshotStore {
        self.store
    }

    pub(crate) fn read_latest_view_optional(
        &self,
    ) -> Result<Option<ReadOnlySnapshotCandidateLoader>, CandidateLoadError> {
        self.store
            .read_latest_view_head_optional_locked(&self.lock)
            .map(|result| result.map(|(_, loader)| loader))
    }

    pub(crate) fn read_latest_view_validation(
        &self,
    ) -> Result<Option<ViewValidationV1>, SnapshotStoreError> {
        self.store.read_latest_view_validation_locked(&self.lock)
    }

    pub(crate) fn read_view_for_endpoint(
        &self,
        endpoint: &str,
    ) -> Result<Option<(ReadOnlySnapshotCandidateLoader, ViewValidationV1)>, CandidateLoadError>
    {
        self.store
            .read_view_for_endpoint_locked(&self.lock, endpoint)
            .map(|result| result.map(|(head, loader)| (loader, validation_record(&head))))
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

fn validation_record(head: &ViewHeadV1) -> ViewValidationV1 {
    ViewValidationV1 {
        format: "rsolve-metadata-view-validation".into(),
        version: 1,
        registry_id: head.registry_id.clone(),
        generation: head.generation.clone(),
        compatibility_profile: head.validation.compatibility_profile,
        parser_schema: head.validation.parser_schema,
        normalization_policy: head.validation.normalization_policy,
        validated_at: head.validation.validated_at.clone(),
        refresh_sequence: head.validation.refresh_sequence,
        effective_endpoint: head.validation.effective_endpoint.clone(),
        sources: head.validation.sources.clone(),
    }
}

fn view_endpoint_matches(effective_endpoint: &str, expected_endpoint: &str) -> bool {
    effective_endpoint.split('\n').any(|observed| {
        observed == expected_endpoint
            || observed
                .strip_prefix(expected_endpoint)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn decode_view_head(
    bytes: &[u8],
    configured_registry_id: &RegistryId,
) -> Result<ViewHeadV1, CandidateLoadError> {
    if bytes.len() > VIEW_HEAD_LIMIT {
        return Err(store_candidate_error(
            "snapshot view head exceeds byte limit",
        ));
    }
    let head: ViewHeadV1 = serde_json::from_slice(bytes)
        .map_err(|error| store_candidate_error(format!("invalid snapshot view head: {error}")))?;
    let canonical = serde_json::to_vec(&head).map_err(|error| {
        store_candidate_error(format!("unable to encode snapshot view head: {error}"))
    })?;
    if canonical != bytes {
        return Err(store_candidate_error(
            "snapshot view head is not canonical JSON",
        ));
    }
    let registry = RegistryId::new(&head.registry_id)
        .map_err(|error| store_candidate_error(error.to_string()))?;
    if head.format != "rsolve-metadata-view"
        || head.version != 1
        || registry != *configured_registry_id
        || head.view_key.len() != 64
        || parse_hex_32(&head.view_key).is_err()
        || head.generation.len() != 64
        || parse_hex_32(&head.generation).is_err()
        || head.header_sha256.len() != 64
        || parse_hex_32(&head.header_sha256).is_err()
        || head.coverage.state.is_empty()
        || head.coverage.scope.is_empty()
        || head.coverage.freshness.is_empty()
        || head.validation.compatibility_profile == 0
        || head.validation.parser_schema == 0
        || head.validation.normalization_policy == 0
        || head.validation.refresh_sequence == 0
        || !super::is_rfc3339_seconds(&head.validation.validated_at)
        || head.validation.effective_endpoint.is_empty()
        || head.validation.sources.is_empty()
        || head
            .validation
            .sources
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(store_candidate_error("snapshot view head is not canonical"));
    }
    if head.validation.sources.iter().any(|source| {
        source.id.len() != 64
            || parse_hex_32(&source.id).is_err()
            || source.content_sha256.len() != 64
            || parse_hex_32(&source.content_sha256).is_err()
            || source.endpoint.is_empty()
    }) {
        return Err(store_candidate_error(
            "snapshot view source identity is invalid",
        ));
    }
    Ok(head)
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

fn publish_view_head(root: &Path, head: &ViewHeadV1) -> Result<(), SnapshotStoreError> {
    let bytes = serde_json::to_vec(head).map_err(|error| store_invalid(error.to_string()))?;
    if bytes.len() > VIEW_HEAD_LIMIT {
        return Err(store_invalid("snapshot view head exceeds byte limit"));
    }
    let views_root = root.join(VIEWS_DIR);
    fs::create_dir_all(&views_root)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| store_invalid(error.to_string()))?
        .as_nanos();
    let temp_path = views_root.join(format!(".rsolve-view-{nonce}.tmp"));
    let _temporary_path = TemporaryPath(temp_path.clone());
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)?;
    file.write_all(&bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    replace_file(
        &temp_path,
        &views_root.join(format!("{}.json", head.view_key)),
    )?;
    sync_directory(&views_root).map_err(SnapshotStoreError::Io)
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
        .ok_or_else(|| store_invalid("view validation refresh sequence overflow"))
}

pub(crate) fn view_validation_revision_token(record: &ViewValidationV1) -> Box<str> {
    let bytes = serde_json::to_vec(record).expect("validated view record is serializable");
    let mut digest = Sha256::new();
    digest.update(b"rsolve-metadata-view-validation-revision-v1");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    hex(&digest.finalize()).into_boxed_str()
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
