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
const LOCK_NAME: &str = "materialization.lock";
const REPOSITORY_NAME: &str = "repository";

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
    let repository = nrr.join(REPOSITORY_NAME);

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
    let staging = nrr.join(format!(".{REPOSITORY_NAME}.partial.{}", unique_nonce()));
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

    if let Err(source) = fs::rename(&staging, &repository) {
        let _ = fs::remove_file(&state_temp);
        let _ = fs::remove_dir_all(&staging);
        return Err(io_error("publish repository", &repository, source));
    }
    if let Err(source) = fs::rename(&state_temp, &state_path) {
        // No committed state means callers must not treat this repository as
        // complete.  It is safe to remove because repository did not exist at
        // the start of this operation.
        let _ = fs::remove_dir_all(&repository);
        let _ = fs::remove_file(&state_temp);
        return Err(io_error(
            "publish materialization state",
            &state_path,
            source,
        ));
    }
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
