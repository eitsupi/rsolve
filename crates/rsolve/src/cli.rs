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
        let warnings = outcome
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
        Ok(ResolvedData {
            resolution: outcome.resolution().clone(),
            warnings,
        })
    }
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
mod tests {
    use super::*;
    use crate::resolve_with_loader_with_publication_cutoff;
    use clap::Parser;
    use rsolve_core::{
        CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, DependencyKind,
        DependencyRequirement, DependencySourceConstraint, PackageNamespace, PackageRelease,
        Provenance, RelationOp, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, SolverKey,
        VersionConstraint,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rsolve-cli-{label}-{nonce}"))
    }

    #[test]
    fn output_write_is_noop_for_identical_bytes() {
        let path = temp_path("noop");
        fs::write(&path, b"same").unwrap();
        assert!(!write_lockfile(&path, b"same").unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"same");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn output_write_replaces_atomically_and_preserves_on_invalid_target() {
        let path = temp_path("replace");
        fs::write(&path, b"old").unwrap();
        assert!(write_lockfile(&path, b"new").unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"new");
        fs::remove_file(&path).unwrap();

        let directory = temp_path("directory");
        fs::create_dir(&directory).unwrap();
        assert!(validate_output_path(&directory).is_err());
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn lock_arguments_parse_explicit_values() {
        let command = CommandLine::try_parse_from([
            "rsolve",
            "lock",
            "--r-version",
            "4.4.0",
            "--package",
            "Matrix",
            "--package",
            "stats",
            "--publication-cutoff",
            "2026-06-24",
            "--output",
            "custom.lock",
            "--metadata-cache",
            "custom-cache",
            "--offline",
        ])
        .unwrap();
        let Command::Lock(lock) = command.command;
        assert_eq!(lock.r_version, "4.4.0");
        assert_eq!(lock.package, vec!["Matrix".to_owned(), "stats".to_owned()]);
        assert_eq!(lock.publication_cutoff.as_deref(), Some("2026-06-24"));
        assert_eq!(lock.output, PathBuf::from("custom.lock"));
        assert_eq!(lock.metadata_cache, Some(PathBuf::from("custom-cache")));
        assert!(lock.offline);
        let defaults = CommandLine::try_parse_from([
            "rsolve",
            "lock",
            "--r-version",
            "4.4.0",
            "--package",
            "Matrix",
        ])
        .unwrap();
        let Command::Lock(defaults) = defaults.command;
        assert!(!defaults.offline);
        let multiple_values = CommandLine::try_parse_from([
            "rsolve",
            "lock",
            "--r-version",
            "4.4.0",
            "--package",
            "Matrix",
            "stats",
        ])
        .unwrap_err();
        assert_eq!(multiple_values.exit_code(), 2);
        for unsupported in ["--os", "--arch"] {
            let args = [
                "rsolve",
                "lock",
                "--r-version",
                "4.4.0",
                "--package",
                "Matrix",
                unsupported,
                "host-value",
            ];
            let error = CommandLine::try_parse_from(args).unwrap_err();
            assert_eq!(error.exit_code(), 2, "{unsupported}");
        }
    }

    #[test]
    fn invalid_output_forms_are_value_errors() {
        assert!(matches!(
            validate_output_path(Path::new("")),
            Err(CliError::Value(message)) if message.contains("empty")
        ));
        assert!(matches!(
            validate_output_path(Path::new("/")),
            Err(CliError::Value(message)) if message.contains("file name")
        ));
        assert_eq!(
            validate_output_path(Path::new("-")),
            Err(CliError::Value("--output - is not supported".into()))
        );
        let directory = temp_path("directory-value");
        fs::create_dir(&directory).unwrap();
        assert!(matches!(
            validate_output_path(&directory),
            Err(CliError::Value(message)) if message.contains("directory")
        ));
        fs::remove_dir(directory).unwrap();
        let parent_file = temp_path("file-parent");
        fs::write(&parent_file, b"not a directory").unwrap();
        assert!(matches!(
            validate_output_path(&parent_file.join("lock")),
            Err(CliError::Value(message)) if message.contains("parent")
        ));
        fs::remove_file(parent_file).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_output_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let target = temp_path("symlink-target");
        let link = temp_path("symlink");
        fs::write(&target, b"old").unwrap();
        symlink(&target, &link).unwrap();
        assert!(matches!(
            validate_output_path(&link),
            Err(CliError::Value(message)) if message.contains("symlink")
        ));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(write_lockfile(&link, b"new").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"old");
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
    }

    #[test]
    fn failed_atomic_write_cleans_temp_and_keeps_existing_bytes() {
        let directory = temp_path("failure-parent");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("nested").join("lock");
        assert!(write_lockfile(&path, b"new").is_err());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn commit_failure_preserves_existing_bytes_and_owned_temp_cleanup() {
        let directory = temp_path("commit-failure");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("lock");
        fs::write(&path, b"old").unwrap();
        let parent = path.parent().unwrap();
        let temp = NamedTempFile::new_in(parent).unwrap();
        let result = commit_temp(temp, &path, |_temp, _destination| {
            Err("injected failure".into())
        });
        let Err(CliError::Operational(message)) = result else {
            panic!("expected injected commit failure");
        };
        assert_eq!(
            message.matches("atomic lockfile write failed:").count(),
            1,
            "commit failure must have one stable error prefix"
        );
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!(fs::read_dir(parent).unwrap().count(), 1);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn mirror_and_output_validation_happen_before_resolution() {
        let command = LockCommand {
            r_version: "4.4.0".into(),
            package: vec!["Matrix".into()],
            cran_mirror: "https://user:password@example.test".into(),
            publication_cutoff: None,
            output: temp_path("missing-parent").join("parent").join("lock"),
            metadata_cache: None,
            offline: false,
        };
        let result = run_lock_with_backend(command, &PanicBackend);
        assert!(matches!(result, Err(CliError::Value(message)) if message.contains("userinfo")));
    }

    #[test]
    fn mirror_validation_canonicalizes_and_rejects_unsafe_forms() {
        assert_eq!(
            canonical_mirror(" https://example.test/cran/// ")
                .unwrap()
                .as_ref(),
            "https://example.test/cran"
        );
        for value in [
            "ftp://example.test",
            "https://?missing-host",
            "https://example.test/?token=secret",
            "https://example.test/#fragment",
            "https://user@example.test",
            "https://:password@example.test",
        ] {
            assert!(canonical_mirror(value).is_err(), "{value}");
        }
    }

    #[test]
    fn invalid_values_and_duplicate_packages_fail_before_resolution() {
        let valid_output = temp_path("invalid-values");
        for (label, command, expected) in [
            (
                "r-version",
                matrix_command("not-a-version", valid_output.clone()),
                "r-version",
            ),
            (
                "publication-cutoff",
                LockCommand {
                    publication_cutoff: Some("2026-02-29".into()),
                    ..matrix_command("4.4.0", valid_output.clone())
                },
                "publication-cutoff",
            ),
            (
                "duplicate",
                LockCommand {
                    package: vec!["Matrix".into(), "Matrix".into()],
                    ..matrix_command("4.4.0", valid_output.clone())
                },
                "duplicate",
            ),
        ] {
            let result = run_lock_with_backend(command, &PanicBackend);
            assert!(
                matches!(result, Err(CliError::Value(message)) if message.contains(expected)),
                "{label}"
            );
        }
    }

    #[test]
    fn help_and_invalid_arguments_have_expected_exit_codes() {
        let help = CommandLine::try_parse_from(["rsolve", "--help"]).unwrap_err();
        assert_eq!(help.exit_code(), 0);
        let invalid = CommandLine::try_parse_from(["rsolve", "lock"]).unwrap_err();
        assert_eq!(invalid.exit_code(), 2);
    }

    struct PanicBackend;

    impl ResolutionBackend for PanicBackend {
        fn resolve(
            &self,
            _manifest: Manifest,
            _mirror: &str,
            _cutoff: Option<PublicationDate>,
            _metadata_cache: &MetadataCache,
            _offline: bool,
        ) -> Result<ResolvedData, CliError> {
            panic!("resolution must not be called after validation failure")
        }
    }

    struct MatrixLoader {
        releases: Vec<PackageRelease>,
    }

    impl CandidateLoader for MatrixLoader {
        fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            match package {
                SolverKey::InstalledName(name) => Ok(self
                    .releases
                    .iter()
                    .filter(|release| release.identity().name() == name)
                    .cloned()
                    .collect()),
                _ => Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    "hermetic Matrix loader has no candidates for this subject",
                )),
            }
        }
    }

    fn matrix_release(version: &str, r_constraint: Option<&str>) -> PackageRelease {
        let matrix = PackageName::new("Matrix").unwrap();
        let version = RPackageVersion::parse(version).unwrap();
        let mut dependencies = vec![DependencyRequirement::new(
            DependencyKind::Imports,
            PackageName::new("lattice").unwrap(),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )];
        if let Some(constraint) = r_constraint {
            dependencies.push(DependencyRequirement::new(
                DependencyKind::Depends,
                PackageName::new("R").unwrap(),
                DependencySourceConstraint::Any,
                VersionConstraint::from_clause(
                    RelationOp::Ge,
                    RPackageVersion::parse(constraint).unwrap(),
                ),
            ));
        }
        PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                matrix.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: matrix,
            observed_version: version,
            metadata: ReleaseMetadata::new(std::collections::BTreeMap::new()).unwrap(),
            publication: None,
            dependencies,
            distributions: Vec::new(),
        })
        .unwrap()
    }

    fn lattice_release() -> PackageRelease {
        let name = PackageName::new("lattice").unwrap();
        let version = RPackageVersion::parse("0.22-6").unwrap();
        PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                name.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: name,
            observed_version: version,
            metadata: ReleaseMetadata::new(std::collections::BTreeMap::new()).unwrap(),
            publication: None,
            dependencies: Vec::new(),
            distributions: Vec::new(),
        })
        .unwrap()
    }

    struct MatrixBackend;

    impl ResolutionBackend for MatrixBackend {
        fn resolve(
            &self,
            manifest: Manifest,
            _mirror: &str,
            cutoff: Option<PublicationDate>,
            _metadata_cache: &MetadataCache,
            _offline: bool,
        ) -> Result<ResolvedData, CliError> {
            let loader = MatrixLoader {
                releases: vec![
                    matrix_release("1.6-5", None),
                    matrix_release("1.7-0", Some("4.4")),
                    lattice_release(),
                ],
            };
            let resolution = resolve_with_loader_with_publication_cutoff(manifest, &loader, cutoff)
                .map_err(|error| CliError::Operational(error.to_string()))?;
            Ok(ResolvedData {
                resolution,
                warnings: Vec::new(),
            })
        }
    }

    struct ModeBackend<'a> {
        mode: &'a std::cell::Cell<Option<bool>>,
    }

    impl ResolutionBackend for ModeBackend<'_> {
        fn resolve(
            &self,
            manifest: Manifest,
            mirror: &str,
            cutoff: Option<PublicationDate>,
            metadata_cache: &MetadataCache,
            offline: bool,
        ) -> Result<ResolvedData, CliError> {
            self.mode.set(Some(offline));
            MatrixBackend.resolve(manifest, mirror, cutoff, metadata_cache, offline)
        }
    }

    fn matrix_command(r_version: &str, output: PathBuf) -> LockCommand {
        LockCommand {
            r_version: r_version.into(),
            package: vec!["Matrix".into()],
            cran_mirror: DEFAULT_CRAN_MIRROR.into(),
            publication_cutoff: None,
            output,
            metadata_cache: Some(temp_path("matrix-metadata-cache")),
            offline: false,
        }
    }

    #[test]
    fn cli_passes_explicit_online_and_offline_modes_to_backend() {
        for offline in [false, true] {
            let mode = std::cell::Cell::new(None);
            let backend = ModeBackend { mode: &mode };
            let output = temp_path(if offline {
                "offline-mode"
            } else {
                "online-mode"
            });
            let mut command = matrix_command("4.4.0", output.clone());
            command.offline = offline;
            run_lock_with_backend(command, &backend).unwrap();
            assert_eq!(mode.get(), Some(offline));
            fs::remove_file(output).unwrap();
        }
    }

    #[test]
    fn hermetic_matrix_versions_produce_distinct_canonical_locks() {
        let first = temp_path("matrix-4-3");
        let second = temp_path("matrix-4-4");
        let repeat = temp_path("matrix-4-4-repeat");
        let first_result =
            run_lock_with_backend(matrix_command("4.3.3", first.clone()), &MatrixBackend).unwrap();
        let second_result =
            run_lock_with_backend(matrix_command("4.4.0", second.clone()), &MatrixBackend).unwrap();
        run_lock_with_backend(matrix_command("4.4.0", repeat.clone()), &MatrixBackend).unwrap();
        assert!(first_result.summary.contains("target R 4.3.3"));
        assert!(second_result.summary.contains("target R 4.4.0"));
        let first_bytes = fs::read(&first).unwrap();
        let second_bytes = fs::read(&second).unwrap();
        let repeat_bytes = fs::read(&repeat).unwrap();
        assert_ne!(first_bytes, second_bytes);
        assert_eq!(second_bytes, repeat_bytes);
        let first_lock = from_toml(std::str::from_utf8(&first_bytes).unwrap()).unwrap();
        let second_lock = from_toml(std::str::from_utf8(&second_bytes).unwrap()).unwrap();
        assert_eq!(
            first_lock.resolutions[0].packages[0]
                .identity
                .name()
                .as_str(),
            "Matrix"
        );
        assert_eq!(
            second_lock.resolutions[0].packages[0]
                .identity
                .name()
                .as_str(),
            "Matrix"
        );
        assert_eq!(
            first_lock.resolutions[0].packages[0].version,
            RPackageVersion::parse("1.6-5").unwrap()
        );
        assert_eq!(
            second_lock.resolutions[0].packages[0].version,
            RPackageVersion::parse("1.7-0").unwrap()
        );
        assert_eq!(
            first_lock.resolutions[0].target.r_version,
            RPackageVersion::parse("4.3.3").unwrap()
        );
        assert_eq!(
            second_lock.resolutions[0].target.r_version,
            RPackageVersion::parse("4.4.0").unwrap()
        );
        let matrix = second_lock.resolutions[0]
            .packages
            .iter()
            .find(|package| package.identity.name().as_str() == "Matrix")
            .unwrap();
        assert_eq!(
            matrix.dependencies,
            vec![PackageName::new("lattice").unwrap()]
        );
        assert_eq!(second_lock.resolutions[0].packages.len(), 2);
        assert!(
            second_lock.resolutions[0]
                .packages
                .iter()
                .all(|package| package.metadata_sha256.as_str().len() == 64)
        );
        assert!(
            second_bytes
                .windows(b"source = { kind = \"registry\", namespace = \"cran\" }".len())
                .any(|window| window == b"source = { kind = \"registry\", namespace = \"cran\" }")
        );
        assert_eq!(
            second_lock,
            from_toml(&to_toml(&second_lock).unwrap()).unwrap()
        );
        fs::remove_file(first).unwrap();
        fs::remove_file(second).unwrap();
        fs::remove_file(repeat).unwrap();
    }

    #[test]
    fn resolution_failure_preserves_existing_lockfile() {
        let path = temp_path("resolution-failure");
        fs::write(&path, b"existing").unwrap();
        let command = matrix_command("4.4.0", path.clone());
        struct FailingBackend;
        impl ResolutionBackend for FailingBackend {
            fn resolve(
                &self,
                _manifest: Manifest,
                _mirror: &str,
                _cutoff: Option<PublicationDate>,
                _metadata_cache: &MetadataCache,
                _offline: bool,
            ) -> Result<ResolvedData, CliError> {
                Err(CliError::Operational("injected resolution failure".into()))
            }
        }
        assert!(run_lock_with_backend(command, &FailingBackend).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"existing");
        fs::remove_file(path).unwrap();
    }
}
