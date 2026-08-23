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
fn cache_warning_renderer_filters_fresh_and_missing_but_reports_stale_sources() {
    use rsolve_provider::cran::{CranSnapshotCacheDiagnostic, CranSnapshotCacheStatus};
    let diagnostics = vec![
        CranSnapshotCacheDiagnostic::new(
            CranSnapshotCacheStatus::Fresh,
            Some(10),
            ["https://fresh.example"],
            "fresh",
        ),
        CranSnapshotCacheDiagnostic::new(
            CranSnapshotCacheStatus::Missing,
            None,
            std::iter::empty::<&str>(),
            "missing",
        ),
        CranSnapshotCacheDiagnostic::new(
            CranSnapshotCacheStatus::Stale,
            Some(7200),
            ["https://z.example", "https://a.example"],
            "stale",
        ),
    ];
    let warnings = render_cache_warnings(&diagnostics);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("age 7200s"));
    assert!(warnings[0].contains("https://a.example, https://z.example"));
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
