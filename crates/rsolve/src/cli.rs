//! Testable command-line composition for the first lockfile command.

use clap::{Args, Parser, Subcommand};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use rsolve_core::{PackageName, PublicationDate, RPackageVersion, VersionConstraint};

use crate::metadata_cache::MetadataCache;
use crate::orchestration::{cran_registry_id, resolve_from_cran_with_store};
use crate::{
    EnvironmentId, Lockfile, Manifest, ManifestDependency, ManifestTarget, from_toml, to_toml,
};

const DEFAULT_CRAN_MIRROR: &str = "https://cloud.r-project.org";
const DEFAULT_OUTPUT: &str = "rsolve.lock";

/// The top-level command line.
#[derive(Clone, Debug, Parser)]
#[command(name = "rsolve", version, about = "Resolve R packages into a lockfile")]
pub struct CommandLine {
    #[command(subcommand)]
    pub command: Command,
}

/// Supported commands.
#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    /// Resolve explicit packages against CRAN and write a lockfile.
    Lock(LockCommand),
}

/// Arguments for `rsolve lock`.
#[derive(Clone, Debug, Args)]
pub struct LockCommand {
    /// Exact target R version.
    #[arg(long, value_name = "EXACT")]
    pub r_version: String,
    /// One direct package name. Repeat this flag for multiple packages.
    #[arg(long, value_name = "NAME", action = clap::ArgAction::Append, required = true)]
    pub package: Vec<String>,
    /// CRAN mirror base URL.
    #[arg(long, default_value = DEFAULT_CRAN_MIRROR)]
    pub cran_mirror: String,
    /// Fixed publication cutoff in YYYY-MM-DD form.
    #[arg(long)]
    pub publication_cutoff: Option<String>,
    /// Lockfile destination. Defaults to rsolve.lock.
    #[arg(long, default_value = DEFAULT_OUTPUT)]
    pub output: PathBuf,
    /// Metadata cache root. Defaults to the platform cache directory.
    #[arg(long, value_name = "ROOT")]
    pub metadata_cache: Option<PathBuf>,
    /// Resolve only from the current metadata snapshot without network access.
    #[arg(long)]
    pub offline: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CliError {
    Value(String),
    Operational(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Value(_) => 2,
            Self::Operational(_) => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(message) | Self::Operational(message) => formatter.write_str(message),
        }
    }
}

impl Error for CliError {}

/// Renderable output from a successful command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResult {
    pub summary: String,
    pub warnings: Vec<String>,
}

trait ResolutionBackend {
    fn resolve(
        &self,
        manifest: Manifest,
        mirror: &str,
        cutoff: Option<PublicationDate>,
        metadata_cache: &MetadataCache,
        offline: bool,
    ) -> Result<ResolvedData, CliError>;
}

struct CranBackend;

struct ResolvedData {
    resolution: rsolve_core::Resolution,
    warnings: Vec<String>,
}

impl ResolutionBackend for CranBackend {
    fn resolve(
        &self,
        manifest: Manifest,
        mirror: &str,
        cutoff: Option<PublicationDate>,
        metadata_cache: &MetadataCache,
        offline: bool,
    ) -> Result<ResolvedData, CliError> {
        let registry_id = cran_registry_id(mirror);
        let store = metadata_cache
            .open_store(registry_id)
            .map_err(|error| CliError::Operational(format!("metadata cache: {error}")))?;
        let outcome = if offline {
            crate::orchestration::resolve_from_cran_offline_with_store(manifest, cutoff, &store)
        } else {
            resolve_from_cran_with_store(manifest, mirror, cutoff, &store)
        }
        .map_err(|error| CliError::Operational(format!("resolution failed: {error}")))?;
        let warnings: Vec<String> = outcome
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| match diagnostic.status_detail() {
                rsolve_provider::cran::CranFastPathStatus::Available => None,
                status => Some(format!(
                    "CRAN refresh diagnostic at {}: {status:?}",
                    diagnostic.endpoint()
                )),
            })
            .collect();
        let mut warnings = warnings;
        warnings.extend(render_cache_warnings(outcome.cache_diagnostics()));
        Ok(ResolvedData {
            resolution: outcome.resolution().clone(),
            warnings,
        })
    }
}

fn render_cache_warnings(
    diagnostics: &[rsolve_provider::cran::CranSnapshotCacheDiagnostic],
) -> Vec<String> {
    diagnostics
        .iter()
        .filter(|diagnostic| {
            !matches!(
                diagnostic.status(),
                rsolve_provider::cran::CranSnapshotCacheStatus::Fresh
                    | rsolve_provider::cran::CranSnapshotCacheStatus::Missing
            )
        })
        .map(|diagnostic| {
            let sources = diagnostic.endpoints().collect::<Vec<_>>().join(", ");
            let age = diagnostic
                .age_seconds()
                .map(|seconds| format!("; age {seconds}s"))
                .unwrap_or_default();
            if sources.is_empty() {
                format!(
                    "CRAN snapshot cache {:?}{age}: {}",
                    diagnostic.status(),
                    diagnostic.diagnostic()
                )
            } else {
                format!(
                    "CRAN snapshot cache {:?}{age}; sources: {sources}: {}",
                    diagnostic.status(),
                    diagnostic.diagnostic()
                )
            }
        })
        .collect()
}

/// Execute a parsed command. Successful commands write no stdout.
pub fn run(command_line: CommandLine) -> Result<CommandResult, CliError> {
    match command_line.command {
        Command::Lock(command) => run_lock_with_backend(command, &CranBackend),
    }
}

fn run_lock_with_backend(
    command: LockCommand,
    backend: &dyn ResolutionBackend,
) -> Result<CommandResult, CliError> {
    let target_r = RPackageVersion::parse(&command.r_version)
        .map_err(|error| value_error(format!("invalid --r-version: {error}")))?;
    let package_names = command
        .package
        .iter()
        .map(|value| {
            PackageName::new(value)
                .map_err(|error| value_error(format!("invalid --package {value:?}: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cutoff = command
        .publication_cutoff
        .as_deref()
        .map(PublicationDate::parse)
        .transpose()
        .map_err(|error| value_error(format!("invalid --publication-cutoff: {error}")))?;
    let mirror = canonical_mirror(&command.cran_mirror)?;
    validate_output_path(&command.output)?;
    let target = ManifestTarget::new(target_r);
    let manifest = Manifest::new(
        VersionConstraint::unconstrained(),
        target,
        package_names
            .into_iter()
            .map(|name| ManifestDependency::new(name, VersionConstraint::unconstrained()))
            .collect(),
    )
    .map_err(|error| value_error(format!("invalid manifest: {error}")))?;

    let requested_package_count = command.package.len();
    let metadata_cache = MetadataCache::resolve(command.metadata_cache.as_deref())
        .map_err(|error| CliError::Operational(format!("metadata cache: {error}")))?;
    let resolved = backend.resolve(manifest, &mirror, cutoff, &metadata_cache, command.offline)?;
    let environment = EnvironmentId::new("default")
        .map_err(|error| CliError::Operational(format!("invalid environment: {error}")))?;
    let lock = Lockfile::from_resolution_with_publication_cutoff(
        &resolved.resolution,
        environment,
        cutoff,
    )
    .map_err(|error| CliError::Operational(format!("lock projection failed: {error}")))?;
    let serialized = to_toml(&lock)
        .map_err(|error| CliError::Operational(format!("lock serialization failed: {error}")))?;
    let reparsed = from_toml(&serialized)
        .map_err(|error| CliError::Operational(format!("lock round-trip failed: {error}")))?;
    if reparsed != lock {
        return Err(CliError::Operational(
            "lock round-trip changed the logical lock domain".into(),
        ));
    }
    let bytes = to_toml(&reparsed)
        .map_err(|error| CliError::Operational(format!("lock re-serialization failed: {error}")))?;

    let changed = write_lockfile(&command.output, bytes.as_bytes())?;
    let status = if changed { "updated" } else { "up-to-date" };
    Ok(CommandResult {
        summary: format!(
            "target R {}; {} direct package(s); output {}; {}",
            command.r_version,
            requested_package_count,
            command.output.display(),
            status
        ),
        warnings: resolved.warnings,
    })
}

fn canonical_mirror(input: &str) -> Result<Box<str>, CliError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(value_error("--cran-mirror must not be empty".into()));
    }
    let mut url = url::Url::parse(input)
        .map_err(|error| value_error(format!("invalid --cran-mirror: {error}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(value_error(
            "invalid --cran-mirror: mirror URL must not include userinfo".into(),
        ));
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(value_error(
            "invalid --cran-mirror: mirror must use HTTP or HTTPS".into(),
        ));
    }
    if url.host_str().is_none() || url.cannot_be_a_base() {
        return Err(value_error(
            "invalid --cran-mirror: mirror must include a host".into(),
        ));
    }
    if url.query().is_some() {
        return Err(value_error(
            "invalid --cran-mirror: mirror must not include a query".into(),
        ));
    }
    if url.fragment().is_some() {
        return Err(value_error(
            "invalid --cran-mirror: mirror must not include a fragment".into(),
        ));
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.to_string().trim_end_matches('/').into())
}

fn value_error(message: String) -> CliError {
    CliError::Value(message)
}

fn validate_output_path(path: &Path) -> Result<(), CliError> {
    if path.as_os_str().is_empty() {
        return Err(CliError::Value("--output must not be empty".into()));
    }
    if path.as_os_str() == "-" {
        return Err(CliError::Value("--output - is not supported".into()));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::metadata(parent).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            CliError::Value(format!(
                "output parent does not exist: {}",
                parent.display()
            ))
        } else {
            CliError::Operational(format!(
                "cannot inspect output parent {}: {error}",
                parent.display()
            ))
        }
    })?;
    if !parent_metadata.is_dir() {
        return Err(CliError::Value(format!(
            "output parent is not a directory: {}",
            parent.display()
        )));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::Value("--output has no file name".into()))?;
    if file_name.is_empty() || file_name == "." || file_name == ".." {
        return Err(CliError::Value("--output has no usable file name".into()));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CliError::Value(format!(
            "refusing symlink output {}",
            path.display()
        ))),
        Ok(metadata) if metadata.is_dir() => Err(CliError::Value(format!(
            "output is a directory: {}",
            path.display()
        ))),
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(CliError::Value(format!(
            "output is not a regular file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::Operational(format!(
            "cannot inspect output {}: {error}",
            path.display()
        ))),
    }
}

fn write_lockfile(path: &Path, bytes: &[u8]) -> Result<bool, CliError> {
    validate_output_path(path)?;
    match fs::read(path) {
        Ok(existing) => {
            if existing == bytes {
                return Ok(false);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CliError::Operational(format!(
                "cannot read existing output {}: {error}",
                path.display()
            )));
        }
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent).map_err(|error| {
        CliError::Operational(format!(
            "atomic lockfile write failed: create temp file: {error}"
        ))
    })?;
    temp.write_all(bytes)
        .and_then(|()| temp.flush())
        .and_then(|()| temp.as_file().sync_all())
        .map_err(|error| CliError::Operational(format!("atomic lockfile write failed: {error}")))?;
    // Re-check after the potentially slow write so a destination replaced by
    // a symlink or special file is rejected before the commit attempt.
    validate_output_path(path)?;
    commit_temp(temp, path, persist_temp)?;
    Ok(true)
}

fn persist_temp(temp: NamedTempFile, path: &Path) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        temp.persist(path)
            .map(|_| ())
            .map_err(|error| error.error.to_string())
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };

        let (file, temporary_path) = temp.keep().map_err(|error| error.error.to_string())?;
        drop(file);
        let source = temporary_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let destination = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            let _ = fs::remove_file(&temporary_path);
            return Err(error.to_string());
        }
        Ok(())
    }
}

fn commit_temp<F>(temp: NamedTempFile, path: &Path, commit: F) -> Result<(), CliError>
where
    F: FnOnce(NamedTempFile, &Path) -> Result<(), String>,
{
    commit(temp, path)
        .map_err(|error| CliError::Operational(format!("atomic lockfile write failed: {error}")))
}

#[cfg(test)]
mod tests;
