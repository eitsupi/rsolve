//! Project-local repository materialization.
//!
//! This module intentionally accepts only selected package/artifact records and
//! verified cache handles.  It does not know how a selection was produced.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use rsolve_core::{
    DependencyRequirement, PackageName, Provenance, RPackageVersion, ReleaseIdentity,
    ReleaseMetadata, ReleasePublication,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::filesystem::{
    clone_file, clone_unsupported, copy_file, ensure_directory, ensure_gitignore, hash_file,
    io_error, is_regular_file, valid_filename_component,
};
use crate::packages::write_packages;
use crate::state::{read_state, write_state_temp, write_transaction_temp};
use crate::util::{hex_lower, sync_directory, unique_nonce};
use crate::{CacheError, CachedArtifact};

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
    pub metadata: ReleaseMetadata,
    pub publication: Option<ReleasePublication>,
    pub dependencies: Vec<DependencyRequirement>,
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
            metadata: ReleaseMetadata::default(),
            publication: None,
            dependencies: Vec::new(),
        }
    }

    pub fn with_metadata(
        mut self,
        metadata: ReleaseMetadata,
        dependencies: Vec<DependencyRequirement>,
    ) -> Self {
        self.metadata = metadata;
        self.dependencies = dependencies;
        self
    }

    /// Attach the first-class publication fact projected into PACKAGES.
    pub fn with_publication(mut self, publication: ReleasePublication) -> Self {
        self.publication = Some(publication);
        self
    }

    pub fn publication(&self) -> Option<&ReleasePublication> {
        self.publication.as_ref()
    }

    pub fn package(&self) -> &PackageName {
        self.identity.name()
    }
}

/// Alias used by orchestration code that calls the input a selected artifact.
pub type SelectedArtifact = MaterializationArtifact;

/// Input to [`materialize`].
pub struct MaterializationRequest<'a> {
    /// The project directory containing `.rsolve`.
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
    pub index_sha256: String,
    pub records: Vec<MaterializationRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MaterializationTransaction {
    pub(crate) schema_version: u32,
    pub(crate) index_sha256: String,
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
    #[error("failed to generate PACKAGES: {source}")]
    Packages {
        #[source]
        source: crate::PackagesError,
    },
    #[error("cache error while materializing {path}: {source}")]
    Cache {
        path: PathBuf,
        #[source]
        source: CacheError,
    },
}

/// Materialize selected cached source archives into `project/.rsolve`.
///
/// The repository is built in a sibling staging directory and renamed only
/// after all selected objects have been copied.  State is written through a
/// temporary file and committed after the repository.  A rerun with the same
/// state is a validated no-op; a different selection never overwrites an
/// existing project view.
pub fn materialize(
    request: MaterializationRequest<'_>,
) -> Result<MaterializationState, MaterializationError> {
    let rsolve = request.project_root.join(".rsolve");
    ensure_directory(&rsolve, "create .rsolve directory")?;
    ensure_gitignore(&rsolve)?;

    let lock_path = rsolve.join(LOCK_NAME);
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
    let state_path = rsolve.join(STATE_NAME);
    let transaction_path = rsolve.join(TRANSACTION_NAME);
    let repository = rsolve.join(REPOSITORY_NAME);

    crate::transaction::recover(
        &rsolve,
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
        let requested_packages = write_packages(request.artifacts)
            .map_err(|source| MaterializationError::Packages { source })?;
        let requested_index_sha256 = hex_lower(&Sha256::digest(&requested_packages));
        if requested_index_sha256 != state.index_sha256 {
            return Err(MaterializationError::ExistingConflict {
                path: repository.join("src").join("contrib").join("PACKAGES"),
            });
        }
        crate::transaction::validate_repository_contents(
            &repository,
            &state.records,
            &state.index_sha256,
        )?;
        return Ok(state);
    }
    if repository.exists() {
        return Err(MaterializationError::ExistingConflict { path: repository });
    }

    let artifacts = canonical_artifacts(request.artifacts);
    // Generate and validate the complete index before creating staging. This
    // keeps malformed metadata/dependencies from leaving filesystem residue.
    let packages =
        write_packages(&artifacts).map_err(|source| MaterializationError::Packages { source })?;
    let staging = rsolve.join(format!("{STAGING_PREFIX}{}", unique_nonce()));
    ensure_directory(&staging, "create repository staging directory")?;
    let contrib = staging.join("src").join("contrib");
    let methods = match materialize_files(&contrib, &artifacts) {
        Ok(methods) => methods,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    let packages_path = contrib.join("PACKAGES");
    if let Err(source) = fs::write(&packages_path, &packages) {
        let _ = fs::remove_dir_all(&staging);
        return Err(io_error("write PACKAGES", &packages_path, source));
    }
    if let Err(source) = File::open(&packages_path).and_then(|file| file.sync_all()) {
        let _ = fs::remove_dir_all(&staging);
        return Err(io_error("sync PACKAGES", &packages_path, source));
    }
    let index_sha256 = hex_lower(&Sha256::digest(&packages));
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
        schema_version: 2,
        index_sha256: index_sha256.clone(),
        records: artifacts
            .iter()
            .zip(methods)
            .map(|(selected, method)| record_for(selected, method))
            .collect(),
    };
    let state_temp = rsolve.join(format!(".{STATE_NAME}.partial.{}", unique_nonce()));
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
        schema_version: 2,
        index_sha256,
        state_temp: state_temp_name,
        staging_dir: staging
            .file_name()
            .and_then(|name| name.to_str())
            .expect("repository staging has an UTF-8 file name")
            .to_owned(),
        records: state.records.clone(),
    };
    let transaction_temp = rsolve.join(format!("{TRANSACTION_NAME}.partial.{}", unique_nonce()));
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
    match sync_directory(&rsolve).map_err(|error| MaterializationError::Cache {
        path: rsolve.clone(),
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
    sync_directory(&rsolve).map_err(|error| MaterializationError::Cache {
        path: rsolve.clone(),
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
    sync_directory(&rsolve).map_err(|error| MaterializationError::Cache {
        path: rsolve.clone(),
        source: error,
    })?;
    fs::remove_file(&transaction_path).map_err(|source| {
        io_error(
            "remove materialization transaction",
            &transaction_path,
            source,
        )
    })?;
    sync_directory(&rsolve).map_err(|error| MaterializationError::Cache {
        path: rsolve,
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

pub(super) fn canonical_artifacts(
    artifacts: &[MaterializationArtifact],
) -> Vec<MaterializationArtifact> {
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
        let method = match clone_file(selected.artifact.path(), &destination) {
            Ok(()) => MaterializationMethod::Clone,
            Err(source) if clone_unsupported(&source) => {
                match copy_file(selected.artifact.path(), &destination) {
                    Ok(()) => {}
                    Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(MaterializationError::DuplicateDestination {
                            path: destination,
                        });
                    }
                    Err(source) => {
                        return Err(io_error("copy cache object", &destination, source));
                    }
                }
                MaterializationMethod::Copy
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                return Err(MaterializationError::DuplicateDestination { path: destination });
            }
            Err(source) => {
                return Err(io_error("clone cache object", &destination, source));
            }
        };
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
    if state.schema_version != 2 || state.records.len() != artifacts.len() {
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

pub(super) fn identity_key(identity: &ReleaseIdentity) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unique_nonce;
    use rsolve_core::{PackageName, Sha256Digest, SourceScheme};

    #[test]
    fn destination_collision_preserves_existing_bytes() {
        let root = std::env::temp_dir().join(format!(
            "rsolve-materialization-collision-{}",
            unique_nonce()
        ));
        let contrib = root.join("src").join("contrib");
        fs::create_dir_all(&contrib).unwrap();
        let source = root.join("source.bin");
        let source_bytes = b"source bytes";
        fs::write(&source, source_bytes).unwrap();
        let digest = Sha256Digest::new(hex_lower(&Sha256::digest(source_bytes))).unwrap();
        let cached = crate::CachedArtifact {
            object_path: source,
            metadata_path: root.join("source.json"),
            sha256: digest.clone(),
            size: source_bytes.len() as u64,
            verification: crate::VerificationStrength::None,
        };
        let selected = MaterializationArtifact::new(
            ReleaseIdentity::new(
                PackageName::new("collision").unwrap(),
                Provenance::ImmutableSource {
                    scheme: SourceScheme::new("fixture").unwrap(),
                    digest,
                },
            ),
            RPackageVersion::parse("1.0.0").unwrap(),
            cached,
        );
        let destination = contrib.join("collision_1.0.0.tar.gz");
        fs::write(&destination, b"keep existing bytes").unwrap();

        let result = materialize_files(&contrib, std::slice::from_ref(&selected));
        assert!(matches!(
            result,
            Err(MaterializationError::DuplicateDestination { path }) if path == destination
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"keep existing bytes");
        fs::remove_dir_all(root).unwrap();
    }
}
