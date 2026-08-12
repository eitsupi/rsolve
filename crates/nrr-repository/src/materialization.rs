//! Project-local repository materialization.
//!
//! This module intentionally accepts only selected package/artifact records and
//! verified cache handles.  It does not know how a selection was produced.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use nrr_core::{PackageName, Provenance, RPackageVersion, ReleaseIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::util::{hex_lower, sync_directory, unique_nonce};
use crate::{CacheError, CachedArtifact};

const GITIGNORE: &[u8] = b"*\n";
const GITIGNORE_NAME: &str = ".gitignore";
const STATE_NAME: &str = "materialization.toml";
const TRANSACTION_NAME: &str = ".materialization.transaction.toml";
const LOCK_NAME: &str = "materialization.lock";
const REPOSITORY_NAME: &str = "repository";
const STAGING_PREFIX: &str = ".repository.partial.";

/// One finally selected source artifact to put in the project repository.
///
/// The package name is taken from the release identity.  Keeping the identity
/// beside the cache handle allows local state to point back to the logical
/// release without making the repository crate aware of resolution types.
#[derive(Clone, Debug)]
pub struct MaterializationArtifact {
    pub identity: ReleaseIdentity,
    pub version: RPackageVersion,
    pub artifact: CachedArtifact,
}

impl MaterializationArtifact {
    pub fn new(
        identity: ReleaseIdentity,
        version: RPackageVersion,
        artifact: CachedArtifact,
    ) -> Self {
        Self {
            identity,
            version,
            artifact,
        }
    }

    pub fn package(&self) -> &PackageName {
        self.identity.name()
    }
}

/// Alias used by orchestration code that calls the input a selected artifact.
pub type SelectedArtifact = MaterializationArtifact;

/// Input to [`materialize`].
pub struct MaterializationRequest<'a> {
    /// The project directory containing `.nrr`.
    pub project_root: &'a Path,
    /// The selected set; no resolver or candidate catalog is consulted.
    pub artifacts: &'a [MaterializationArtifact],
}

impl<'a> MaterializationRequest<'a> {
    pub fn new(project_root: &'a Path, artifacts: &'a [MaterializationArtifact]) -> Self {
        Self {
            project_root,
            artifacts,
        }
    }
}

/// How a cache object was published into the project view.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializationMethod {
    /// Linux FICLONE (or a platform clone implementation in a future port).
    Clone,
    /// An independent byte-for-byte copy.
    Copy,
}

impl MaterializationMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clone => "clone",
            Self::Copy => "copy",
        }
    }
}

/// One machine-local materialization record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationRecord {
    pub identity: String,
    pub package: String,
    pub version: String,
    pub artifact_sha256: String,
    pub size: u64,
    pub destination: String,
    pub method: MaterializationMethod,
}

/// The project-local state committed after repository publication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationState {
    pub schema_version: u32,
    pub records: Vec<MaterializationRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MaterializationTransaction {
    pub(crate) schema_version: u32,
    pub(crate) state_temp: String,
    pub(crate) staging_dir: String,
    pub(crate) records: Vec<MaterializationRecord>,
}

impl MaterializationState {
    pub fn records(&self) -> &[MaterializationRecord] {
        &self.records
    }
}

/// Errors while constructing and publishing a project repository.
#[derive(Debug, Error)]
pub enum MaterializationError {
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid materialization input: {reason}")]
    InvalidInput { reason: String },
    #[error("selected package name is duplicated: {package}")]
    DuplicatePackage { package: String },
    #[error(
        "selected version for {package} ({selected}) does not match its provenance version ({provenance})"
    )]
    ProvenanceVersionMismatch {
        package: String,
        selected: String,
        provenance: String,
    },
    #[error("repository destination is duplicated: {path}")]
    DuplicateDestination { path: PathBuf },
    #[error("existing materialization conflicts with the selected artifact at {path}")]
    ExistingConflict { path: PathBuf },
    #[error("materialization state is invalid at {path}: {reason}")]
    InvalidState { path: PathBuf, reason: String },
    #[error("materialization transaction cannot be recovered at {path}: {reason}")]
    TransactionConflict { path: PathBuf, reason: String },
    #[error("cache object is invalid at {path}: {reason}")]
    InvalidCacheObject { path: PathBuf, reason: String },
    #[error("cache error while materializing {path}: {source}")]
    Cache {
        path: PathBuf,
        #[source]
        source: CacheError,
    },
}

/// Materialize selected cached source archives into `project/.nrr`.
///
/// The repository is built in a sibling staging directory and renamed only
/// after all selected objects have been copied.  State is written through a
/// temporary file and committed after the repository.  A rerun with the same
/// state is a validated no-op; a different selection never overwrites an
/// existing project view.
pub fn materialize(
    request: MaterializationRequest<'_>,
) -> Result<MaterializationState, MaterializationError> {
    let nrr = request.project_root.join(".nrr");
    ensure_directory(&nrr, "create .nrr directory")?;
    ensure_gitignore(&nrr)?;

    let lock_path = nrr.join(LOCK_NAME);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| io_error("create materialization lock", &lock_path, source))?;
    lock.lock()
        .map_err(|source| io_error("lock materialization", &lock_path, source))?;

    validate_inputs(request.artifacts)?;
    let state_path = nrr.join(STATE_NAME);
    let transaction_path = nrr.join(TRANSACTION_NAME);
    let repository = nrr.join(REPOSITORY_NAME);

    recover_transaction(
        &nrr,
        &state_path,
        &transaction_path,
        &repository,
        request.artifacts,
    )?;
    if state_path.exists() {
        if !is_regular_file(&state_path) {
            return Err(MaterializationError::InvalidState {
                path: state_path,
                reason: "state path is not a regular file".to_owned(),
            });
        }
        let state = read_state(&state_path)?;
        validate_existing_state(&state, request.artifacts, &repository)?;
        return Ok(state);
    }
    if repository.exists() {
        return Err(MaterializationError::ExistingConflict { path: repository });
    }

    let artifacts = canonical_artifacts(request.artifacts);
    let staging = nrr.join(format!("{STAGING_PREFIX}{}", unique_nonce()));
    ensure_directory(&staging, "create repository staging directory")?;
    let contrib = staging.join("src").join("contrib");
    let methods = match materialize_files(&contrib, &artifacts) {
        Ok(methods) => methods,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    if let Err(error) = sync_directory(&contrib).map_err(|error| MaterializationError::Cache {
        path: contrib.clone(),
        source: error,
    }) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    if let Err(error) = sync_directory(&staging).map_err(|error| MaterializationError::Cache {
        path: staging.clone(),
        source: error,
    }) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }

    // Prepare state before exposing the repository.  The temporary state is
    // not the committed state and is ignored by the project-local gitignore.
    let state = MaterializationState {
        schema_version: 1,
        records: artifacts
            .iter()
            .zip(methods)
            .map(|(selected, method)| record_for(selected, method))
            .collect(),
    };
    let state_temp = nrr.join(format!(".{STATE_NAME}.partial.{}", unique_nonce()));
    if let Err(error) = write_state_temp(&state_temp, &state) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }

    let state_temp_name = state_temp
        .file_name()
        .and_then(|name| name.to_str())
        .expect("materialization state temporary has an UTF-8 file name")
        .to_owned();
    let transaction = MaterializationTransaction {
        schema_version: 1,
        state_temp: state_temp_name,
        staging_dir: staging
            .file_name()
            .and_then(|name| name.to_str())
            .expect("repository staging has an UTF-8 file name")
            .to_owned(),
        records: state.records.clone(),
    };
    let transaction_temp = nrr.join(format!("{TRANSACTION_NAME}.partial.{}", unique_nonce()));
    if let Err(error) = write_transaction_temp(&transaction_temp, &transaction) {
        let _ = fs::remove_file(&state_temp);
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    if let Err(source) = fs::rename(&transaction_temp, &transaction_path) {
        let _ = fs::remove_file(&transaction_temp);
        let _ = fs::remove_file(&state_temp);
        let _ = fs::remove_dir_all(&staging);
        return Err(io_error(
            "publish materialization transaction",
            &transaction_path,
            source,
        ));
    }
    // The marker and state temp are durable before exposing the repository.
    // If the process exits after the repository rename, the next invocation
    // can validate these files and finish the state rename.
    match sync_directory(&nrr).map_err(|error| MaterializationError::Cache {
        path: nrr.clone(),
        source: error,
    }) {
        Ok(()) => {}
        Err(error) => return Err(error),
    }

    if let Err(source) = fs::rename(&staging, &repository) {
        // Keep marker, state temp, and staging intact.  The next invocation
        // can diagnose an external repository conflict or resume safely.
        return Err(io_error("publish repository", &repository, source));
    }
    // Make the repository directory entry durable before publishing the state
    // pointer.  A crash before the next rename leaves a recoverable marker.
    sync_directory(&nrr).map_err(|error| MaterializationError::Cache {
        path: nrr.clone(),
        source: error,
    })?;
    if let Err(source) = fs::rename(&state_temp, &state_path) {
        // Keep repository, state temp, and marker intact.  They form the
        // recoverable transaction that the next invocation will validate.
        return Err(io_error(
            "publish materialization state",
            &state_path,
            source,
        ));
    }
    // State is now durable before removing the marker.  If cleanup is
    // interrupted, recovery sees the committed state and only removes the
    // stale marker after validating it.
    sync_directory(&nrr).map_err(|error| MaterializationError::Cache {
        path: nrr.clone(),
        source: error,
    })?;
    fs::remove_file(&transaction_path).map_err(|source| {
        io_error(
            "remove materialization transaction",
            &transaction_path,
            source,
        )
    })?;
    sync_directory(&nrr).map_err(|error| MaterializationError::Cache {
        path: nrr,
        source: error,
    })?;
    Ok(state)
}

fn validate_inputs(artifacts: &[MaterializationArtifact]) -> Result<(), MaterializationError> {
    let mut packages = HashSet::new();
    let mut destinations = HashSet::new();
    for selected in artifacts {
        let package = selected.package().as_str();
        if !valid_filename_component(package)
            || !valid_filename_component(selected.version.as_str())
        {
            return Err(MaterializationError::InvalidInput {
                reason: format!(
                    "package or version is not a safe filename component: {package}_{}",
                    selected.version
                ),
            });
        }
        match selected.identity.provenance() {
            Provenance::RegistryRelease { version, .. }
            | Provenance::BioconductorRelease { version, .. }
            | Provenance::RBasePackage { r_version: version }
                if version != &selected.version =>
            {
                return Err(MaterializationError::ProvenanceVersionMismatch {
                    package: package.to_owned(),
                    selected: selected.version.to_string(),
                    provenance: version.to_string(),
                });
            }
            Provenance::RegistryRelease { .. }
            | Provenance::BioconductorRelease { .. }
            | Provenance::RBasePackage { .. }
            | Provenance::GitCommit { .. }
            | Provenance::ImmutableSource { .. } => {}
        }
        let destination = format!("{package}_{}.tar.gz", selected.version);
        if !destinations.insert(destination.clone()) {
            return Err(MaterializationError::DuplicateDestination {
                path: PathBuf::from(destination),
            });
        }
        if !packages.insert(package.to_owned()) {
            return Err(MaterializationError::DuplicatePackage {
                package: package.to_owned(),
            });
        }
        if selected.artifact.size == 0 {
            return Err(MaterializationError::InvalidInput {
                reason: format!("cached artifact for {package} is empty"),
            });
        }
    }
    Ok(())
}

fn canonical_artifacts(artifacts: &[MaterializationArtifact]) -> Vec<MaterializationArtifact> {
    let mut canonical = artifacts.to_vec();
    canonical.sort_by(|left, right| {
        let left_destination = destination_name(left);
        let right_destination = destination_name(right);
        left.package()
            .as_str()
            .cmp(right.package().as_str())
            .then_with(|| left_destination.cmp(&right_destination))
            .then_with(|| identity_key(&left.identity).cmp(&identity_key(&right.identity)))
    });
    canonical
}

fn destination_name(selected: &MaterializationArtifact) -> String {
    format!("{}_{}.tar.gz", selected.package(), selected.version)
}

fn materialize_files(
    contrib: &Path,
    artifacts: &[MaterializationArtifact],
) -> Result<Vec<MaterializationMethod>, MaterializationError> {
    ensure_directory(contrib, "create src/contrib directory")?;
    let mut methods = Vec::with_capacity(artifacts.len());
    for selected in artifacts {
        let destination = contrib.join(format!(
            "{}_{}.tar.gz",
            selected.package(),
            selected.version
        ));
        verify_cache_object(&selected.artifact)?;
        let partial = destination.with_file_name(format!(".partial.{}", unique_nonce()));
        let method = match clone_file(selected.artifact.path(), &partial) {
            Ok(()) => MaterializationMethod::Clone,
            Err(source) if clone_unsupported(&source) => {
                copy_file(selected.artifact.path(), &partial)?;
                MaterializationMethod::Copy
            }
            Err(source) => {
                let _ = fs::remove_file(&partial);
                return Err(io_error("clone cache object", &destination, source));
            }
        };
        if let Err(source) = fs::rename(&partial, &destination) {
            let _ = fs::remove_file(&partial);
            return Err(io_error(
                "publish repository artifact",
                &destination,
                source,
            ));
        }
        methods.push(method);
    }
    Ok(methods)
}

fn verify_cache_object(cached: &CachedArtifact) -> Result<(), MaterializationError> {
    if !is_regular_file(cached.path()) {
        return Err(MaterializationError::InvalidCacheObject {
            path: cached.path().to_path_buf(),
            reason: "cache object is not a regular file".to_owned(),
        });
    }
    let mut file = File::open(cached.path())
        .map_err(|source| io_error("open cache object", cached.path(), source))?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("read cache object", cached.path(), source))?;
        if read == 0 {
            break;
        }
        size = size.checked_add(read as u64).ok_or_else(|| {
            MaterializationError::InvalidCacheObject {
                path: cached.path().to_path_buf(),
                reason: "object size overflow".to_owned(),
            }
        })?;
        hasher.update(&buffer[..read]);
    }
    let actual = hex_lower(&hasher.finalize());
    if size != cached.size || actual != cached.sha256.as_str() {
        return Err(MaterializationError::InvalidCacheObject {
            path: cached.path().to_path_buf(),
            reason: format!(
                "expected {} bytes with SHA-256 {}, got {size} bytes with {actual}",
                cached.size, cached.sha256
            ),
        });
    }
    Ok(())
}

fn record_for(
    selected: &MaterializationArtifact,
    method: MaterializationMethod,
) -> MaterializationRecord {
    MaterializationRecord {
        identity: identity_key(&selected.identity),
        package: selected.package().to_string(),
        version: selected.version.to_string(),
        artifact_sha256: selected.artifact.sha256.to_string(),
        size: selected.artifact.size,
        destination: format!(
            "repository/src/contrib/{}_{}.tar.gz",
            selected.package(),
            selected.version
        ),
        method,
    }
}

fn validate_existing_state(
    state: &MaterializationState,
    artifacts: &[MaterializationArtifact],
    repository: &Path,
) -> Result<(), MaterializationError> {
    if state.schema_version != 1 || state.records.len() != artifacts.len() {
        return Err(MaterializationError::InvalidState {
            path: repository.to_path_buf(),
            reason: "state does not describe the requested artifact set".to_owned(),
        });
    }
    for selected in artifacts {
        let destination = repository.join("src").join("contrib").join(format!(
            "{}_{}.tar.gz",
            selected.package(),
            selected.version
        ));
        let expected_identity = identity_key(&selected.identity);
        let Some(record) = state.records.iter().find(|record| {
            record.identity == expected_identity
                && record.artifact_sha256 == selected.artifact.sha256.to_string()
        }) else {
            return Err(MaterializationError::ExistingConflict { path: destination });
        };
        if record.destination
            != format!(
                "repository/src/contrib/{}_{}.tar.gz",
                selected.package(),
                selected.version
            )
            || record.package != selected.package().to_string()
            || record.version != selected.version.to_string()
            || record.size != selected.artifact.size
        {
            return Err(MaterializationError::ExistingConflict { path: destination });
        }
        verify_cache_object(&selected.artifact)?;
        if !fs::symlink_metadata(&destination)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
            || hash_file(&destination)? != selected.artifact.sha256.to_string()
        {
            return Err(MaterializationError::ExistingConflict { path: destination });
        }
    }
    Ok(())
}

fn read_state(path: &Path) -> Result<MaterializationState, MaterializationError> {
    let text = fs::read_to_string(path)
        .map_err(|source| io_error("read materialization state", path, source))?;
    toml::from_str(&text).map_err(|source| MaterializationError::InvalidState {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })
}

fn write_state_temp(path: &Path, state: &MaterializationState) -> Result<(), MaterializationError> {
    let encoded =
        toml::to_string_pretty(state).map_err(|source| MaterializationError::InvalidState {
            path: path.to_path_buf(),
            reason: source.to_string(),
        })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create materialization state temporary", path, source))?;
    if let Err(error) = (|| -> io::Result<()> {
        file.write_all(encoded.as_bytes())?;
        file.sync_all()
    })() {
        let _ = fs::remove_file(path);
        return Err(io_error(
            "write materialization state temporary",
            path,
            error,
        ));
    }
    Ok(())
}

fn write_transaction_temp(
    path: &Path,
    transaction: &MaterializationTransaction,
) -> Result<(), MaterializationError> {
    let encoded = toml::to_string_pretty(transaction).map_err(|source| {
        MaterializationError::InvalidState {
            path: path.to_path_buf(),
            reason: source.to_string(),
        }
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create transaction temporary", path, source))?;
    if let Err(error) = (|| -> io::Result<()> {
        file.write_all(encoded.as_bytes())?;
        file.sync_all()
    })() {
        let _ = fs::remove_file(path);
        return Err(io_error("write transaction temporary", path, error));
    }
    Ok(())
}

fn recover_transaction(
    nrr: &Path,
    state_path: &Path,
    transaction_path: &Path,
    repository: &Path,
    requested: &[MaterializationArtifact],
) -> Result<(), MaterializationError> {
    let state_temps = partial_paths(nrr, &format!(".{STATE_NAME}.partial."))?;
    let transaction_temps = partial_paths(nrr, &format!("{TRANSACTION_NAME}.partial."))?;
    let staging_paths = partial_paths(nrr, STAGING_PREFIX)?;
    let marker_exists = fs::symlink_metadata(transaction_path).is_ok();
    if !marker_exists {
        if reconstruct_orphan_transaction(
            nrr,
            &state_temps,
            &transaction_temps,
            &staging_paths,
            requested,
        )? {
            return recover_transaction(nrr, state_path, transaction_path, repository, requested);
        }
        return Ok(());
    }
    if !is_regular_file(transaction_path) {
        return Err(transaction_conflict(
            transaction_path,
            "transaction marker is not a regular file",
        ));
    }
    if !transaction_temps.is_empty() {
        return Err(transaction_conflict(
            transaction_path,
            "transaction marker has an ambiguous temporary sibling",
        ));
    }
    let transaction = read_transaction(transaction_path)?;
    if transaction.schema_version != 1 {
        return Err(transaction_conflict(
            transaction_path,
            "unsupported transaction schema",
        ));
    }
    if !records_match_requested(&transaction.records, requested) {
        return Err(transaction_conflict(
            transaction_path,
            "transaction records do not match the requested artifact set",
        ));
    }
    let state_temp = transaction_temp_path(nrr, &transaction.state_temp)
        .ok_or_else(|| transaction_conflict(transaction_path, "invalid state temporary path"))?;
    let staging = staging_path(nrr, &transaction.staging_dir)
        .ok_or_else(|| transaction_conflict(transaction_path, "invalid staging directory path"))?;
    if staging_paths.len() > 1 || (!staging_paths.is_empty() && staging_paths[0] != staging) {
        return Err(transaction_conflict(
            transaction_path,
            "staging directory does not match the transaction marker",
        ));
    }
    let repository_exists = fs::symlink_metadata(repository).is_ok();
    let staging_exists = fs::symlink_metadata(&staging).is_ok();
    if repository_exists && staging_exists {
        return Err(transaction_conflict(
            transaction_path,
            "both repository and transaction staging directories exist",
        ));
    }
    if !repository_exists && !staging_exists {
        return Err(transaction_conflict(
            &staging,
            "transaction staging directory is missing",
        ));
    }
    if state_path.exists() && !is_regular_file(state_path) {
        return Err(transaction_conflict(
            state_path,
            "committed state is not a regular file",
        ));
    }

    // Validate every transaction input before changing the repository name.
    // In particular, a corrupt or mismatched state temp must never allow a
    // valid-looking staging directory to become the published repository.
    let temporary_state = if state_path.exists() && state_temps.is_empty() {
        let committed_state = read_state(state_path)?;
        if committed_state.schema_version != 1
            || committed_state.records != transaction.records
            || !records_match_requested(&committed_state.records, requested)
        {
            return Err(transaction_conflict(
                state_path,
                "committed state differs from the transaction state",
            ));
        }
        None
    } else {
        if state_temps.len() != 1 || state_temps[0] != state_temp {
            return Err(transaction_conflict(
                transaction_path,
                "state temporary does not match the transaction marker",
            ));
        }
        if !is_regular_file(&state_temp) {
            return Err(transaction_conflict(
                &state_temp,
                "state temporary is not a regular file",
            ));
        }
        let temporary_state = read_state(&state_temp)?;
        if temporary_state.schema_version != 1
            || temporary_state.records != transaction.records
            || !records_match_requested(&temporary_state.records, requested)
        {
            return Err(transaction_conflict(
                &state_temp,
                "state temporary does not match the transaction marker or request",
            ));
        }
        if state_path.exists() {
            let committed_state = read_state(state_path)?;
            if committed_state != temporary_state {
                return Err(transaction_conflict(
                    state_path,
                    "committed state differs from the transaction state",
                ));
            }
        }
        Some(temporary_state)
    };

    if repository_exists {
        if !is_directory(repository) {
            return Err(transaction_conflict(
                repository,
                "published repository is not a directory",
            ));
        }
        validate_repository_contents(repository, &transaction.records)?;
    } else {
        if !is_directory(&staging) {
            return Err(transaction_conflict(
                &staging,
                "transaction staging path is not a directory",
            ));
        }
        validate_repository_contents(&staging, &transaction.records)?;
        // The marker binds this exact staging basename to the requested
        // records.  Only after strict validation is it safe to resume the
        // directory publication.
        fs::rename(&staging, repository)
            .map_err(|source| io_error("recover repository publication", repository, source))?;
        sync_directory(nrr).map_err(|error| MaterializationError::Cache {
            path: nrr.to_path_buf(),
            source: error,
        })?;
    }
    if temporary_state.is_some() {
        if state_path.exists() {
            fs::remove_file(&state_temp).map_err(|source| {
                io_error("remove recovered state temporary", &state_temp, source)
            })?;
        } else {
            // The repository is already durable.  Finish only the state rename,
            // then sync the parent directory before removing the marker.
            fs::rename(&state_temp, state_path)
                .map_err(|source| io_error("recover materialization state", state_path, source))?;
            sync_directory(nrr).map_err(|error| MaterializationError::Cache {
                path: nrr.to_path_buf(),
                source: error,
            })?;
        }
    }
    fs::remove_file(transaction_path)
        .map_err(|source| io_error("remove recovered transaction", transaction_path, source))?;
    sync_directory(nrr).map_err(|error| MaterializationError::Cache {
        path: nrr.to_path_buf(),
        source: error,
    })?;
    Ok(())
}

fn reconstruct_orphan_transaction(
    nrr: &Path,
    state_temps: &[PathBuf],
    transaction_temps: &[PathBuf],
    staging_paths: &[PathBuf],
    requested: &[MaterializationArtifact],
) -> Result<bool, MaterializationError> {
    if state_temps.is_empty() && transaction_temps.is_empty() && staging_paths.is_empty() {
        return Ok(false);
    }
    if state_temps.len() != 1 || staging_paths.len() != 1 || transaction_temps.len() > 1 {
        return Err(transaction_conflict(
            nrr,
            "orphaned transaction temporaries are ambiguous",
        ));
    }
    let state_temp = &state_temps[0];
    let staging = &staging_paths[0];
    if !is_regular_file(state_temp) || !is_directory(staging) {
        return Err(transaction_conflict(
            nrr,
            "orphaned transaction temporary has an unsafe filesystem type",
        ));
    }
    let state_name = state_temp
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| transaction_conflict(state_temp, "state temporary has an invalid name"))?;
    let staging_name = staging
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| transaction_conflict(staging, "staging temporary has an invalid name"))?;
    let state = read_state(state_temp).map_err(|error| {
        transaction_conflict(
            state_temp,
            format!("orphaned state temporary is invalid: {error}"),
        )
    })?;
    if state.schema_version != 1 || !records_match_requested(&state.records, requested) {
        return Err(transaction_conflict(
            state_temp,
            "orphaned state temporary does not match the requested artifact set",
        ));
    }
    let transaction = if let Some(transaction_temp) = transaction_temps.first() {
        if !is_regular_file(transaction_temp) {
            return Err(transaction_conflict(
                transaction_temp,
                "orphaned transaction temporary has an unsafe filesystem type",
            ));
        }
        let transaction = read_transaction(transaction_temp).map_err(|error| {
            transaction_conflict(
                transaction_temp,
                format!("orphaned transaction marker is invalid: {error}"),
            )
        })?;
        if transaction.schema_version != 1
            || transaction.state_temp != state_name
            || transaction.staging_dir != staging_name
            || transaction.records != state.records
            || !records_match_requested(&transaction.records, requested)
        {
            return Err(transaction_conflict(
                transaction_temp,
                "orphaned transaction temporary does not bind the validated siblings",
            ));
        }
        transaction
    } else {
        MaterializationTransaction {
            schema_version: 1,
            state_temp: state_name.to_owned(),
            staging_dir: staging_name.to_owned(),
            records: state.records.clone(),
        }
    };
    validate_repository_contents(staging, &transaction.records)?;

    let transaction_path = nrr.join(TRANSACTION_NAME);
    if let Some(transaction_temp) = transaction_temps.first() {
        fs::rename(transaction_temp, &transaction_path).map_err(|source| {
            io_error(
                "publish reconstructed materialization transaction",
                &transaction_path,
                source,
            )
        })?;
    } else {
        let transaction_temp = nrr.join(format!("{TRANSACTION_NAME}.partial.{}", unique_nonce()));
        write_transaction_temp(&transaction_temp, &transaction)?;
        fs::rename(&transaction_temp, &transaction_path).map_err(|source| {
            let _ = fs::remove_file(&transaction_temp);
            io_error(
                "publish reconstructed materialization transaction",
                &transaction_path,
                source,
            )
        })?;
    }
    sync_directory(nrr).map_err(|error| MaterializationError::Cache {
        path: nrr.to_path_buf(),
        source: error,
    })?;
    Ok(true)
}

fn partial_paths(directory: &Path, prefix: &str) -> Result<Vec<PathBuf>, MaterializationError> {
    let entries = fs::read_dir(directory)
        .map_err(|source| io_error("scan transaction directory", directory, source))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|source| io_error("read transaction directory", directory, source))?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(prefix))
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn transaction_temp_path(nrr: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || !name.starts_with(&format!(".{STATE_NAME}.partial."))
    {
        return None;
    }
    Some(nrr.join(name))
}

fn staging_path(nrr: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || !name.starts_with(STAGING_PREFIX)
    {
        return None;
    }
    Some(nrr.join(name))
}

fn read_transaction(path: &Path) -> Result<MaterializationTransaction, MaterializationError> {
    let text = fs::read_to_string(path)
        .map_err(|source| io_error("read materialization transaction", path, source))?;
    toml::from_str(&text).map_err(|source| MaterializationError::InvalidState {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })
}

fn records_match_requested(
    records: &[MaterializationRecord],
    requested: &[MaterializationArtifact],
) -> bool {
    let canonical = canonical_artifacts(requested);
    records.len() == canonical.len()
        && canonical.iter().zip(records).all(|(selected, record)| {
            record.identity == identity_key(&selected.identity)
                && record.package == selected.package().to_string()
                && record.version == selected.version.to_string()
                && record.artifact_sha256 == selected.artifact.sha256.to_string()
                && record.size == selected.artifact.size
                && record.destination
                    == format!(
                        "repository/src/contrib/{}_{}.tar.gz",
                        selected.package(),
                        selected.version
                    )
        })
}

fn validate_repository_contents(
    repository: &Path,
    records: &[MaterializationRecord],
) -> Result<(), MaterializationError> {
    let src = repository.join("src");
    let contrib = src.join("contrib");
    if !is_directory(&src) || !is_directory(&contrib) {
        return Err(transaction_conflict(
            repository,
            "repository layout is not src/contrib",
        ));
    }
    let root_entries = directory_names(repository)?;
    if root_entries != ["src".to_owned()].into_iter().collect() {
        return Err(transaction_conflict(
            repository,
            "repository contains unexpected top-level entries",
        ));
    }
    let src_entries = directory_names(&src)?;
    if src_entries != ["contrib".to_owned()].into_iter().collect() {
        return Err(transaction_conflict(
            &src,
            "repository src contains unexpected entries",
        ));
    }
    let expected: HashSet<String> = records
        .iter()
        .map(|record| {
            record
                .destination
                .strip_prefix("repository/src/contrib/")
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    let actual = directory_names(&contrib)?;
    if actual != expected {
        return Err(transaction_conflict(
            &contrib,
            "repository artifact destinations do not match the transaction",
        ));
    }
    for record in records {
        let Some(name) = record.destination.strip_prefix("repository/src/contrib/") else {
            return Err(transaction_conflict(
                &contrib,
                "transaction destination escapes src/contrib",
            ));
        };
        let path = contrib.join(name);
        if !is_regular_file(&path) {
            return Err(transaction_conflict(
                &path,
                "transaction destination is not a regular file",
            ));
        }
        let metadata = fs::metadata(&path)
            .map_err(|source| io_error("inspect recovered artifact", &path, source))?;
        if metadata.len() != record.size || hash_file(&path)? != record.artifact_sha256 {
            return Err(transaction_conflict(
                &path,
                "repository artifact digest or size differs from the transaction",
            ));
        }
    }
    Ok(())
}

fn directory_names(path: &Path) -> Result<HashSet<String>, MaterializationError> {
    let entries =
        fs::read_dir(path).map_err(|source| io_error("scan recovered repository", path, source))?;
    let mut names = HashSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read recovered repository", path, source))?;
        names.insert(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

fn is_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
}

fn transaction_conflict(path: &Path, reason: impl Into<String>) -> MaterializationError {
    MaterializationError::TransactionConflict {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn ensure_gitignore(nrr: &Path) -> Result<(), MaterializationError> {
    let path = nrr.join(GITIGNORE_NAME);
    if path.exists() {
        if !is_regular_file(&path) {
            return Err(MaterializationError::InvalidInput {
                reason: format!("{} is not a regular file", path.display()),
            });
        }
        let existing =
            fs::read(&path).map_err(|source| io_error("read .nrr/.gitignore", &path, source))?;
        if existing != GITIGNORE {
            return Err(MaterializationError::InvalidInput {
                reason: format!("{} must contain exactly `*\\n`", path.display()),
            });
        }
        return Ok(());
    }
    fs::write(&path, GITIGNORE)
        .map_err(|source| io_error("create .nrr/.gitignore", &path, source))?;
    Ok(())
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn ensure_directory(path: &Path, operation: &'static str) -> Result<(), MaterializationError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_dir() {
            return Err(MaterializationError::InvalidInput {
                reason: format!("{} is not a directory", path.display()),
            });
        }
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|source| io_error(operation, path, source))
}

fn valid_filename_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn hash_file(path: &Path) -> Result<String, MaterializationError> {
    let mut file =
        File::open(path).map_err(|source| io_error("open materialized artifact", path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("hash materialized artifact", path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn copy_file(source: &Path, destination: &Path) -> Result<(), MaterializationError> {
    fs::copy(source, destination)
        .map_err(|error| io_error("copy cache object", destination, error))?;
    make_writable(destination)?;
    File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error("sync copied artifact", destination, error))
}

fn clone_file(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        use std::os::raw::{c_int, c_ulong};
        let input = File::open(source)?;
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        // FICLONE is the Linux copy-on-write clone ioctl.  The source and
        // destination remain distinct inodes, so project mutation cannot
        // modify the cache object.
        const FICLONE: c_ulong = 0x4004_9409;
        unsafe extern "C" {
            fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        }
        let result = unsafe { ioctl(output.as_raw_fd(), FICLONE, input.as_raw_fd()) };
        if result != 0 {
            let error = io::Error::last_os_error();
            drop(output);
            let _ = fs::remove_file(destination);
            return Err(error);
        }
        output.sync_all()?;
        drop(output);
        make_writable_io(destination)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "reflink clone is unavailable on this target",
        ))
    }
}

fn make_writable(path: &Path) -> Result<(), MaterializationError> {
    make_writable_io(path)
        .map_err(|source| io_error("make materialized artifact writable", path, source))
}

fn make_writable_io(path: &Path) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Preserve the cache object's mode while granting only the owning
        // user write access to the project copy.
        permissions.set_mode(permissions.mode() | 0o200);
    }
    #[cfg(not(unix))]
    {
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
    }
    fs::set_permissions(path, permissions)
}

fn clone_unsupported(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Unsupported
            | io::ErrorKind::CrossesDevices
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::PermissionDenied
    )
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> MaterializationError {
    MaterializationError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn identity_key(identity: &ReleaseIdentity) -> String {
    let name = identity.name();
    match identity.provenance() {
        Provenance::RBasePackage { r_version } => {
            format!("r-base:{name}@{r_version}")
        }
        Provenance::RegistryRelease { namespace, version } => {
            format!("registry:{namespace}::{name}@{version}")
        }
        Provenance::GitCommit {
            repository,
            commit,
            subdirectory,
        } => format!(
            "git:{repository}@{commit}:{}::{name}",
            subdirectory
                .as_ref()
                .map_or_else(String::new, |value| value.to_string())
        ),
        Provenance::BioconductorRelease {
            namespace,
            release,
            version,
        } => format!("bioconductor:{namespace}:{release}::{name}@{version}"),
        Provenance::ImmutableSource { scheme, digest } => {
            format!("immutable:{scheme}:{digest}::{name}")
        }
    }
}
