use super::*;
use crate::resolve_with_loader_with_publication_cutoff;
use clap::Parser;
use rsolve_core::{
    CandidateAvailability, CandidateCurrentness, CandidateLoadError, CandidateLoadErrorCategory,
    CandidateLoader, DeclaredDependency, DependencyKind, DependencySourceConstraint,
    PackageNamespace, PackageRelease, PreparedCandidate, Provenance, RegistryId, RelationOp,
    ReleaseIdentity, ReleaseMetadata, ReleaseObservation, RepositoryId, RepositoryOccurrence,
    RepositoryRank, SolverKey, VersionConstraint,
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
fn metrics_report_is_explicit_and_versioned() {
    let output = temp_path("metrics-lock");
    let report = temp_path("metrics-report");
    assert!(!report.exists());
    let mut command = matrix_command("4.4.0", output.clone());
    let without =
        run_lock_with_backend(matrix_command("4.4.0", output.clone()), &MatrixBackend).unwrap();
    assert!(!report.exists());
    let lock_without = fs::read(&output).unwrap();
    fs::remove_file(&output).unwrap();
    command.metrics_output = Some(report.clone());
    let result = run_lock_with_backend(command, &MatrixBackend).unwrap();
    let encoded = fs::read_to_string(&report).unwrap();
    let json: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert!(json["lock_byte_count"].as_u64().unwrap() > 0);
    assert!(json["metrics"]["phases"]["lock_projection_ns"].is_number());
    assert_eq!(json["metrics"]["phases"]["solve_ns"], 0);
    assert_eq!(
        json["metrics"]["phases"]["refresh_acquisition_ns"],
        serde_json::Value::Null
    );
    assert_eq!(json["metrics"]["loader_lookup_calls"], 0);
    assert_eq!(
        json["metrics"]["provider_refresh"],
        serde_json::json!({
            "http_attempts": 7,
            "successful_response_body_bytes": 11,
            "statuses": {
                "status_200": 1,
                "status_304": 2,
                "status_404": 3,
                "status_410": 4,
                "other": 5
            },
            "current_index": {"requests": 6, "successful_body_bytes": 7},
            "archive_history": {"requests": 8, "successful_body_bytes": 9},
            "allpackages": {"requests": 10, "successful_body_bytes": 11},
            "package_local_index": {"requests": 12, "successful_body_bytes": 13},
            "tarball_description": {"requests": 14, "successful_body_bytes": 15},
            "raw_cache_hits": 16,
            "raw_cache_misses": 17,
            "raw_cache_corrupt": 18,
            "projection_reuses": 19,
            "projection_builds": 20,
            "projection_rebuilds": 21,
            "package_history_lookups": 22,
            "allpackages_adoptions": 23,
            "package_local_fallbacks": 24,
            "quarantined_releases": 25,
            "coverage_gaps": 26,
            "coverage_conflicts": 27
        })
    );
    assert_eq!(result.summary, without.summary);
    assert_eq!(result.warnings, without.warnings);
    assert_eq!(fs::read(&output).unwrap(), lock_without);
    fs::remove_file(output).unwrap();
    fs::remove_file(report).unwrap();
}

#[test]
fn metrics_output_replaces_existing_report_and_noop_lock_write_is_absent() {
    let output = temp_path("metrics-noop-lock");
    let report = temp_path("metrics-noop-report");
    fs::write(&report, b"stale report").unwrap();
    let mut command = matrix_command("4.4.0", output.clone());
    command.metrics_output = Some(report.clone());
    run_lock_with_backend(command.clone(), &MatrixBackend).unwrap();
    assert_ne!(fs::read(&report).unwrap(), b"stale report");
    run_lock_with_backend(command, &MatrixBackend).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(
        json["metrics"]["phases"]["atomic_lock_write_ns"],
        serde_json::Value::Null
    );
    fs::remove_file(output).unwrap();
    fs::remove_file(report).unwrap();
}

#[cfg(unix)]
#[test]
fn metrics_output_symlink_is_rejected_without_touching_target() {
    use std::os::unix::fs::symlink;
    let output = temp_path("metrics-symlink-lock");
    let target = temp_path("metrics-symlink-target");
    let report = temp_path("metrics-symlink-report");
    fs::write(&target, b"keep").unwrap();
    symlink(&target, &report).unwrap();
    let mut command = matrix_command("4.4.0", output.clone());
    command.metrics_output = Some(report.clone());
    let result = run_lock_with_backend(command, &MatrixBackend);
    assert!(matches!(result, Err(CliError::Value(message)) if message.contains("symlink")));
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    fs::remove_file(report).unwrap();
    fs::remove_file(target).unwrap();
}

#[cfg(unix)]
#[test]
fn metrics_output_hardlink_alias_is_rejected_without_touching_lock() {
    let output = temp_path("metrics-hardlink-lock");
    let report = temp_path("metrics-hardlink-report");
    let lock_bytes = b"pre-existing lock bytes";
    fs::write(&output, lock_bytes).unwrap();
    fs::hard_link(&output, &report).unwrap();

    let mut command = matrix_command("4.4.0", output.clone());
    command.metrics_output = Some(report.clone());
    let result = run_lock_with_backend(command, &MatrixBackend);
    assert!(matches!(
        result,
        Err(CliError::Value(message)) if message.contains("must differ")
    ));
    assert_eq!(fs::read(&output).unwrap(), lock_bytes);
    assert_eq!(fs::read(&report).unwrap(), lock_bytes);
    fs::remove_file(output).unwrap();
    fs::remove_file(report).unwrap();
}

#[test]
fn metrics_overflow_rejects_report_before_lock_write() {
    let output = temp_path("metrics-overflow-lock");
    let report = temp_path("metrics-overflow-report");
    let mut command = matrix_command("4.4.0", output.clone());
    command.metrics_output = Some(report.clone());
    let result = run_lock_with_backend(command, &OverflowBackend);
    assert!(
        matches!(result, Err(CliError::Operational(message)) if message.contains("metrics overflow"))
    );
    assert!(!output.exists());
    assert!(!report.exists());
}

#[test]
fn metrics_output_rejects_equivalent_lock_destination() {
    let output = temp_path("metrics-collision");
    let parent = output.parent().unwrap();
    let mut command = matrix_command("4.4.0", output.clone());
    command.metrics_output = Some(parent.join(".").join(output.file_name().unwrap()));
    let result = run_lock_with_backend(command, &MatrixBackend);
    assert!(matches!(result, Err(CliError::Value(message)) if message.contains("must differ")));
}

#[test]
fn metrics_output_case_variant_follows_filesystem_publication_contract() {
    let directory = temp_path("case-identity");
    fs::create_dir(&directory).unwrap();
    let output = directory.join("lock.toml");
    let metrics = directory.join("LOCK.TOML");
    let probe = directory.join("probe-case-variant-unique");
    let probe_variant = directory.join("PROBE-CASE-VARIANT-UNIQUE");
    fs::write(&probe, b"probe").unwrap();
    let case_sensitive = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_variant)
    {
        Ok(file) => {
            drop(file);
            fs::remove_file(&probe_variant).unwrap();
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => panic!("unexpected case-variant probe error: {error}"),
    };
    fs::remove_file(&probe).unwrap();
    assert!(!output.exists());
    assert!(!metrics.exists());
    let mut command = matrix_command("4.4.0", output.clone());
    command.metrics_output = Some(metrics.clone());
    let result = run_lock_with_backend(command, &MatrixBackend);
    if case_sensitive {
        assert!(result.is_ok());
        assert!(output.exists());
        assert!(metrics.exists());
    } else {
        assert!(matches!(result, Err(CliError::Value(message)) if message.contains("must differ")));
        assert!(output.exists());
        assert!(metrics.exists());
        let lock_bytes = fs::read(&output).unwrap();
        assert_eq!(lock_bytes, fs::read(&metrics).unwrap());
        assert!(from_toml(std::str::from_utf8(&lock_bytes).unwrap()).is_ok());
        assert!(serde_json::from_slice::<serde_json::Value>(&lock_bytes).is_err());
    }
    fs::remove_file(output).unwrap();
    if metrics.exists() {
        fs::remove_file(metrics).unwrap();
    }
    fs::remove_dir(directory).unwrap();
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
fn terminal_progress_reports_semantic_phases_without_request_noise() {
    use crate::progress::ProgressEvent;
    use rsolve_provider::cran::CranRefreshProgress;

    let mut renderer = TerminalProgress { writer: Vec::new() };
    renderer.render(ProgressEvent::Cran(
        CranRefreshProgress::CurrentIndexStarted,
    ));
    renderer.render(ProgressEvent::Cran(
        CranRefreshProgress::CurrentIndexCompleted { packages: 42 },
    ));
    renderer.render(ProgressEvent::Cran(CranRefreshProgress::AllPackagesStarted));
    renderer.render(ProgressEvent::Cran(
        CranRefreshProgress::AllPackagesProjected,
    ));
    renderer.render(ProgressEvent::Cran(
        CranRefreshProgress::AllPackagesQualified { reused: true },
    ));
    renderer.render(ProgressEvent::ResolveCompleted { packages: 7 });
    let output = String::from_utf8(renderer.writer).unwrap();
    assert_eq!(
        output,
        "CRAN: refreshing current index\n\
    CRAN: current index ready (42 packages)\n\
    CRAN: acquiring ALLPACKAGES feed\n\
    CRAN: ALLPACKAGES projection ready\n\
    CRAN: ALLPACKAGES qualification reused\n\
    resolved (7 packages)\n"
    );
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
    assert_eq!(lock.output, Some(PathBuf::from("custom.lock")));
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
fn manifest_input_is_explicit_and_conflicts_with_legacy_packages() {
    let parsed = CommandLine::try_parse_from([
        "rsolve",
        "lock",
        "--r-version",
        "4.4.0",
        "--manifest",
        "project.toml",
        "--environment",
        "ci",
    ])
    .unwrap();
    let Command::Lock(lock) = parsed.command;
    assert_eq!(lock.manifest, Some(PathBuf::from("project.toml")));
    assert_eq!(lock.environment.as_deref(), Some("ci"));
    assert!(lock.package.is_empty());

    let conflict = CommandLine::try_parse_from([
        "rsolve",
        "lock",
        "--r-version",
        "4.4.0",
        "--manifest",
        "project.toml",
        "--package",
        "Matrix",
    ])
    .unwrap_err();
    assert_eq!(conflict.exit_code(), 2);

    let discovered =
        CommandLine::try_parse_from(["rsolve", "lock", "--r-version", "4.4.0"]).unwrap();
    let Command::Lock(discovered) = discovered.command;
    assert!(discovered.manifest.is_none());
    assert!(discovered.package.is_empty());

    let discovered_environment = CommandLine::try_parse_from([
        "rsolve",
        "lock",
        "--r-version",
        "4.4.0",
        "--environment",
        "ci",
    ])
    .unwrap();
    let Command::Lock(discovered_environment) = discovered_environment.command;
    assert_eq!(discovered_environment.environment.as_deref(), Some("ci"));

    let package_environment = CommandLine::try_parse_from([
        "rsolve",
        "lock",
        "--r-version",
        "4.4.0",
        "--package",
        "Matrix",
        "--environment",
        "ci",
    ])
    .unwrap_err();
    assert_eq!(package_environment.exit_code(), 2);
}

#[test]
fn environment_selection_uses_explicit_then_variable_then_default() {
    assert_eq!(
        select_environment(Some("ci"), Some("test")),
        ("ci", "--environment")
    );
    assert_eq!(
        select_environment(None, Some("test")),
        ("test", "RSOLVE_ENVIRONMENT")
    );
    assert_eq!(select_environment(None, None), ("default", "default"));
    let called = std::cell::Cell::new(false);
    let value = environment_variable_for(Some("ci"), || {
        called.set(true);
        Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
            "ignored",
        )))
    })
    .unwrap();
    assert_eq!(value, None);
    assert!(!called.get());
}

#[test]
fn discovered_manifest_uses_nearest_parent_and_rejects_explicit_mirror() {
    let directory = tempfile::tempdir().unwrap();
    let nested = directory.path().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(
        directory.path().join("rsolve.toml"),
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.test'\nregistry='cran'\n[dependencies]\nMatrix='*'\n",
    )
    .unwrap();
    let command = LockCommand {
        r_version: "4.4.0".into(),
        manifest: None,
        environment: None,
        package: Vec::new(),
        cran_mirror: None,
        publication_cutoff: None,
        output: None,
        metadata_cache: Some(nested.join("cache")),
        offline: false,
        refresh_metadata: false,
        metrics_output: None,
    };
    let result = run_manifest_lock_with_backend_progress_at(
        command,
        RPackageVersion::parse("4.4.0").unwrap(),
        &MatrixBackend,
        None,
        &nested,
        None,
    )
    .unwrap();
    assert!(result.summary.contains("rsolve.toml"));
    assert!(directory.path().join("rsolve.lock").is_file());
    assert!(!nested.join("rsolve.lock").exists());

    let mut explicit_mirror = matrix_command("4.4.0", nested.join("mirror.lock"));
    explicit_mirror.manifest = Some(directory.path().join("rsolve.toml"));
    explicit_mirror.package.clear();
    let error = run_lock_with_backend(explicit_mirror, &PanicBackend).unwrap_err();
    assert!(matches!(error, CliError::Value(message) if message.contains("--cran-mirror")));
}

#[test]
fn manifest_without_repositories_supports_provider_free_resolution() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("rsolve.toml");
    fs::write(&manifest, "[rsolve]\nschema=1\n[r]\nversion='*'\n").unwrap();
    let command = LockCommand {
        r_version: "4.4.0".into(),
        manifest: Some(manifest),
        environment: None,
        package: Vec::new(),
        cran_mirror: None,
        publication_cutoff: None,
        output: None,
        metadata_cache: Some(directory.path().join("cache")),
        offline: false,
        refresh_metadata: false,
        metrics_output: None,
    };
    run_lock_with_backend(command, &MatrixBackend).unwrap();
}

#[test]
fn cli_repository_validation_treats_qualified_r_base_as_remote() {
    let root = crate::manifest::ComposedRootIntent {
        name: PackageName::new("stats").unwrap(),
        constraint: VersionConstraint::unconstrained(),
        source: crate::manifest::ManifestSource::Registry {
            repository: Some(RepositoryId::new("mirror").unwrap()),
        },
        expansion: rsolve_core::RootExpansionPolicy::HardOnly,
    };
    let composed = ComposedEnvironment {
        environment: EnvironmentId::new("default").unwrap(),
        r_requirement: VersionConstraint::unconstrained(),
        published_before: None,
        target: rsolve_core::ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        repositories: Vec::new(),
        roots: vec![root],
        locked: rsolve_core::LockedIdentities::new(),
    };
    let error = validate_composed_repository_selection(&composed).unwrap_err();
    assert!(matches!(error, CliError::Value(message) if message.contains("one repository")));

    let mut runtime_root = composed.roots[0].clone();
    runtime_root.source = crate::manifest::ManifestSource::Registry { repository: None };
    let runtime_composed = ComposedEnvironment {
        roots: vec![runtime_root],
        ..composed
    };
    assert!(validate_composed_repository_selection(&runtime_composed).is_ok());
}

#[test]
fn manifest_direct_source_fails_before_backend() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("rsolve.toml");
    fs::write(
        &manifest,
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.test'\nregistry='cran'\n[dependencies]\nfoo={url='https://example.test/foo.tar.gz'}\n",
    )
    .unwrap();
    let command = LockCommand {
        r_version: "4.4.0".into(),
        manifest: Some(manifest),
        environment: None,
        package: Vec::new(),
        cran_mirror: None,
        publication_cutoff: None,
        output: None,
        metadata_cache: Some(directory.path().join("cache")),
        offline: false,
        refresh_metadata: false,
        metrics_output: None,
    };
    let result = run_lock_with_backend(command, &PanicBackend);
    assert!(
        matches!(result, Err(CliError::Value(message)) if message.contains("requires acquisition"))
    );
}

#[test]
fn manifest_explicit_output_is_rejected_before_backend() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("rsolve.toml");
    fs::write(
        &manifest,
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\n",
    )
    .unwrap();
    let command = LockCommand {
        r_version: "4.4.0".into(),
        manifest: Some(manifest),
        environment: None,
        package: Vec::new(),
        cran_mirror: None,
        publication_cutoff: None,
        output: Some(directory.path().join("custom.lock")),
        metadata_cache: Some(directory.path().join("cache")),
        offline: false,
        refresh_metadata: false,
        metrics_output: None,
    };
    let error = run_lock_with_backend(command, &PanicBackend).unwrap_err();
    assert!(matches!(error, CliError::Value(message) if message.contains("--output")));
}

#[test]
fn manifest_environment_is_projected_into_lock() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("rsolve.toml");
    fs::write(
        &manifest,
        "[rsolve]\nschema=1\n[r]\nversion='>= 4.0, < 5.0'\n[resolution]\npublished-before='2026-06-24'\n[[repositories]]\nid='cran'\nurl='https://example.test'\nregistry='cran'\n[groups.ci.dependencies]\nMatrix='*'\n[environments]\nci=['ci']\n",
    )
    .unwrap();
    let command = LockCommand {
        r_version: "4.4.0".into(),
        manifest: Some(manifest),
        environment: Some("ci".into()),
        package: Vec::new(),
        cran_mirror: None,
        publication_cutoff: None,
        output: None,
        metadata_cache: Some(directory.path().join("cache")),
        offline: false,
        refresh_metadata: false,
        metrics_output: None,
    };
    run_lock_with_backend(command, &MatrixBackend).unwrap();
    let lock =
        from_toml(&fs::read_to_string(directory.path().join("rsolve.ci.lock")).unwrap()).unwrap();
    let resolution = lock.single_resolution().unwrap();
    assert_eq!(resolution.environment.as_str(), "ci");
    assert_eq!(
        resolution.publication_cutoff,
        Some(PublicationDate::parse("2026-06-24").unwrap())
    );
}

#[test]
fn manifest_default_and_named_outputs_are_independent() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("rsolve.toml");
    fs::write(
        &manifest,
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.test'\nregistry='cran'\n[dependencies]\nMatrix='*'\n[groups.test.dependencies]\nlattice='*'\n[environments]\ntest=['test']\n",
    )
    .unwrap();
    let mut default_command = LockCommand {
        r_version: "4.4.0".into(),
        manifest: Some(manifest.clone()),
        environment: None,
        package: Vec::new(),
        cran_mirror: None,
        publication_cutoff: None,
        output: None,
        metadata_cache: Some(directory.path().join("cache")),
        offline: false,
        refresh_metadata: false,
        metrics_output: None,
    };
    run_lock_with_backend(default_command.clone(), &MatrixBackend).unwrap();
    default_command.environment = Some("test".into());
    run_lock_with_backend(default_command, &MatrixBackend).unwrap();

    let default_lock =
        from_toml(&fs::read_to_string(directory.path().join("rsolve.lock")).unwrap()).unwrap();
    let named_lock =
        from_toml(&fs::read_to_string(directory.path().join("rsolve.test.lock")).unwrap()).unwrap();
    assert_eq!(
        default_lock
            .single_resolution()
            .unwrap()
            .environment
            .as_str(),
        "default"
    );
    assert_eq!(
        named_lock.single_resolution().unwrap().environment.as_str(),
        "test"
    );
    assert!(!directory.path().join("rsolve.default.lock").exists());
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
    let result = commit_temp(
        temp,
        &path,
        |_temp, _destination| Err("injected failure".into()),
        "lockfile",
    );
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
        manifest: None,
        environment: None,
        package: vec!["Matrix".into()],
        cran_mirror: Some("https://user:password@example.test".into()),
        publication_cutoff: None,
        output: Some(temp_path("missing-parent").join("parent").join("lock")),
        metadata_cache: None,
        offline: false,
        refresh_metadata: false,
        metrics_output: None,
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
        "https://example.test/cran///"
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
    assert!(matches!(
        canonical_mirror("https://example.test:0"),
        Err(CliError::Value(message)) if message.contains("port zero")
    ));
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
        _refresh_metadata: bool,
    ) -> Result<ResolvedData, CliError> {
        panic!("resolution must not be called after validation failure")
    }
}

struct MatrixLoader {
    releases: Vec<PackageRelease>,
}

impl CandidateLoader for MatrixLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PreparedCandidate>, CandidateLoadError> {
        match package {
            SolverKey::InstalledName(name) => Ok(self
                .releases
                .iter()
                .filter(|release| release.identity().name() == name)
                .cloned()
                .map(|release| {
                    let occurrence = RepositoryOccurrence::new(
                        RepositoryId::new("cran").unwrap(),
                        RegistryId::new("cran").unwrap(),
                        CandidateAvailability::Available,
                        CandidateCurrentness::Current,
                        RepositoryRank::new(0),
                        release.distributions().to_vec(),
                    )
                    .unwrap();
                    PreparedCandidate::new(
                        release,
                        rsolve_core::NonRepositoryExposure::None,
                        vec![occurrence],
                    )
                    .unwrap()
                })
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
    let mut dependencies = vec![
        DeclaredDependency::from_parts(
            DependencyKind::Imports,
            PackageName::new("lattice").unwrap(),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )
        .unwrap(),
    ];
    if let Some(constraint) = r_constraint {
        dependencies.push(
            DeclaredDependency::from_parts(
                DependencyKind::Depends,
                PackageName::new("R").unwrap(),
                DependencySourceConstraint::Any,
                VersionConstraint::from_clause(
                    RelationOp::Ge,
                    RPackageVersion::parse(constraint).unwrap(),
                ),
            )
            .unwrap(),
        );
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
        declared_dependencies: dependencies,
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
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap()
}

struct MatrixBackend;

struct OverflowBackend;

impl ResolutionBackend for OverflowBackend {
    fn resolve(
        &self,
        manifest: Manifest,
        mirror: &str,
        cutoff: Option<PublicationDate>,
        metadata_cache: &MetadataCache,
        offline: bool,
        refresh_metadata: bool,
    ) -> Result<ResolvedData, CliError> {
        let mut data = MatrixBackend.resolve(
            manifest,
            mirror,
            cutoff,
            metadata_cache,
            offline,
            refresh_metadata,
        )?;
        data.metrics.metrics_overflow = true;
        Ok(data)
    }
}

impl ResolutionBackend for MatrixBackend {
    fn resolve(
        &self,
        manifest: Manifest,
        _mirror: &str,
        cutoff: Option<PublicationDate>,
        _metadata_cache: &MetadataCache,
        _offline: bool,
        _refresh_metadata: bool,
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
        let mut metrics = ResolutionMetrics::default();
        metrics.phases.solve_ns = Some(0);
        metrics.phases.prepared_loader_lookup_ns = Some(0);
        metrics.provider_refresh = Some(rsolve_provider::cran::CranRefreshMetrics {
            http_attempts: 7,
            successful_response_body_bytes: 11,
            statuses: rsolve_provider::cran::CranRefreshStatusMetrics {
                status_200: 1,
                status_304: 2,
                status_404: 3,
                status_410: 4,
                other: 5,
            },
            current_index: rsolve_provider::cran::CranRefreshSourceMetrics {
                requests: 6,
                successful_body_bytes: 7,
            },
            archive_history: rsolve_provider::cran::CranRefreshSourceMetrics {
                requests: 8,
                successful_body_bytes: 9,
            },
            allpackages: rsolve_provider::cran::CranRefreshSourceMetrics {
                requests: 10,
                successful_body_bytes: 11,
            },
            package_local_index: rsolve_provider::cran::CranRefreshSourceMetrics {
                requests: 12,
                successful_body_bytes: 13,
            },
            tarball_description: rsolve_provider::cran::CranRefreshSourceMetrics {
                requests: 14,
                successful_body_bytes: 15,
            },
            raw_cache_hits: 16,
            raw_cache_misses: 17,
            raw_cache_corrupt: 18,
            projection_reuses: 19,
            projection_builds: 20,
            projection_rebuilds: 21,
            package_history_lookups: 22,
            allpackages_adoptions: 23,
            package_local_fallbacks: 24,
            quarantined_releases: 25,
            coverage_gaps: 26,
            coverage_conflicts: 27,
        });
        Ok(ResolvedData {
            resolution,
            warnings: Vec::new(),
            metrics,
        })
    }

    fn resolve_composed(
        &self,
        composed: ComposedEnvironment,
        metadata_cache: &MetadataCache,
        offline: bool,
        refresh_metadata: bool,
        _progress: Option<ProgressCallback>,
    ) -> Result<ResolvedData, CliError> {
        let manifest = Manifest::new(
            composed.r_requirement.clone(),
            ManifestTarget::new(composed.target.r_version.clone()),
            composed
                .roots
                .into_iter()
                .map(|root| ManifestDependency::new(root.name, root.constraint))
                .collect(),
        )
        .map_err(|error| CliError::Value(error.to_string()))?;
        self.resolve(
            manifest,
            DEFAULT_CRAN_MIRROR,
            None,
            metadata_cache,
            offline,
            refresh_metadata,
        )
    }
}

struct ModeBackend<'a> {
    mode: &'a std::cell::Cell<Option<(bool, bool)>>,
}

impl ResolutionBackend for ModeBackend<'_> {
    fn resolve(
        &self,
        manifest: Manifest,
        mirror: &str,
        cutoff: Option<PublicationDate>,
        metadata_cache: &MetadataCache,
        offline: bool,
        refresh_metadata: bool,
    ) -> Result<ResolvedData, CliError> {
        self.mode.set(Some((offline, refresh_metadata)));
        MatrixBackend.resolve(
            manifest,
            mirror,
            cutoff,
            metadata_cache,
            offline,
            refresh_metadata,
        )
    }
}

fn matrix_command(r_version: &str, output: PathBuf) -> LockCommand {
    LockCommand {
        r_version: r_version.into(),
        manifest: None,
        environment: None,
        package: vec!["Matrix".into()],
        cran_mirror: Some(DEFAULT_CRAN_MIRROR.into()),
        publication_cutoff: None,
        output: Some(output),
        metadata_cache: Some(temp_path("matrix-metadata-cache")),
        offline: false,
        refresh_metadata: false,
        metrics_output: None,
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
        assert_eq!(mode.get(), Some((offline, false)));
        fs::remove_file(output).unwrap();
    }
}

#[test]
fn cli_parses_and_forwards_refresh_metadata_and_rejects_offline_conflict() {
    let parsed = CommandLine::try_parse_from([
        "rsolve",
        "lock",
        "--r-version",
        "4.4.0",
        "--package",
        "Matrix",
        "--refresh-metadata",
    ])
    .unwrap();
    let Command::Lock(lock) = parsed.command;
    assert!(lock.refresh_metadata);
    assert!(!lock.offline);

    let conflict = CommandLine::try_parse_from([
        "rsolve",
        "lock",
        "--r-version",
        "4.4.0",
        "--package",
        "Matrix",
        "--offline",
        "--refresh-metadata",
    ])
    .unwrap_err();
    assert_eq!(conflict.exit_code(), 2);

    let mode = std::cell::Cell::new(None);
    let backend = ModeBackend { mode: &mode };
    let output = temp_path("refresh-mode");
    let mut command = matrix_command("4.4.0", output.clone());
    command.refresh_metadata = true;
    run_lock_with_backend(command, &backend).unwrap();
    assert_eq!(mode.get(), Some((false, true)));
    fs::remove_file(output).unwrap();
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
        vec![crate::LockedDependencyEdge {
            kind: rsolve_core::EffectiveDependencyKind::Imports,
            package: PackageName::new("lattice").unwrap(),
        }]
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
            _refresh_metadata: bool,
        ) -> Result<ResolvedData, CliError> {
            Err(CliError::Operational("injected resolution failure".into()))
        }
    }
    assert!(run_lock_with_backend(command, &FailingBackend).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"existing");
    fs::remove_file(path).unwrap();
}
