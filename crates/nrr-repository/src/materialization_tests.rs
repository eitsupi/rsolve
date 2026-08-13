use crate::materialization::MaterializationTransaction;
use crate::*;
use flate2::{Compression, write::GzEncoder};
use nrr_core::{
    BioconductorRelease, DependencyKind, DependencyRequirement, DependencySourceConstraint,
    PackageName, PackageNamespace, Provenance, RPackageVersion, RelationOp, ReleaseIdentity,
    ReleaseMetadata, UpstreamChecksum, VersionConstraint,
};
use sha2::Digest;
use std::fs::OpenOptions;
use std::io::Cursor;
use std::io::Write;
use tar::{Builder, Header};

fn temporary_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "nrr-repository-{label}-{}-{}",
        std::process::id(),
        unique_nonce()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn artifact(checksums: Vec<UpstreamChecksum>, size: Option<u64>) -> SourceArtifact {
    SourceArtifact {
        locator: nrr_core::ArtifactLocator::new("fixture://source/example").unwrap(),
        upstream_checksums: checksums,
        size,
    }
}

fn archive_bytes() -> Vec<u8> {
    archive_bytes_with("fixture source\n", "example/DESCRIPTION")
}

fn archive_bytes_with(contents: &str, name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    let encoder = GzEncoder::new(&mut encoded, Compression::default());
    let mut builder = Builder::new(encoder);
    let contents = contents.as_bytes();
    let mut header = Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, name, contents).unwrap();
    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap();
    encoded
}

#[test]
fn packages_are_deterministic_and_preserve_folded_metadata_and_dependencies() {
    let cache = CachedArtifact {
        object_path: PathBuf::from("/tmp/object"),
        metadata_path: PathBuf::from("/tmp/metadata"),
        sha256: nrr_core::Sha256Digest::new("a".repeat(64)).unwrap(),
        size: 1,
        verification: VerificationStrength::None,
    };
    let version = RPackageVersion::parse("0.1.0").unwrap();
    let identity = ReleaseIdentity::new(
        PackageName::new("middle").unwrap(),
        Provenance::ImmutableSource {
            scheme: nrr_core::SourceScheme::new("fixture").unwrap(),
            digest: cache.sha256.clone(),
        },
    );
    let dependency = DependencyRequirement::new(
        DependencyKind::Imports,
        PackageName::new("leaf").unwrap(),
        DependencySourceConstraint::Any,
        VersionConstraint::from_clause(RelationOp::Ge, RPackageVersion::parse("0.1.0").unwrap()),
    );
    let metadata = ReleaseMetadata::from_pairs([
        ("Description", "UTF-8 summary\nwith a continuation"),
        ("Encoding", "UTF-8"),
        ("priority", "recommended"),
        ("license_is_foss", "yes"),
    ])
    .unwrap();
    let middle = MaterializationArtifact::new(identity, version, cache)
        .with_metadata(metadata, vec![dependency]);
    let bytes = packages::write_packages(std::slice::from_ref(&middle)).unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        "Package: middle\nVersion: 0.1.0\nPriority: recommended\nImports: leaf (>= 0.1.0)\nLicense_is_FOSS: yes\nDescription: UTF-8 summary\n with a continuation\nEncoding: UTF-8\n"
    );
}

#[test]
fn packages_reject_multiple_version_clauses_for_one_dependency() {
    let cache = CachedArtifact {
        object_path: PathBuf::from("/tmp/object"),
        metadata_path: PathBuf::from("/tmp/metadata"),
        sha256: nrr_core::Sha256Digest::new("a".repeat(64)).unwrap(),
        size: 1,
        verification: VerificationStrength::None,
    };
    let identity = ReleaseIdentity::new(
        PackageName::new("middle").unwrap(),
        Provenance::ImmutableSource {
            scheme: nrr_core::SourceScheme::new("fixture").unwrap(),
            digest: cache.sha256.clone(),
        },
    );
    let dependency = DependencyRequirement::new(
        DependencyKind::Imports,
        PackageName::new("leaf").unwrap(),
        DependencySourceConstraint::Any,
        VersionConstraint::new(vec![
            nrr_core::VersionClause::new(RelationOp::Ge, RPackageVersion::parse("0.1.0").unwrap()),
            nrr_core::VersionClause::new(RelationOp::Lt, RPackageVersion::parse("0.2.0").unwrap()),
        ]),
    );
    let middle =
        MaterializationArtifact::new(identity, RPackageVersion::parse("0.1.0").unwrap(), cache)
            .with_metadata(
                ReleaseMetadata::from_pairs([("License", "MIT")]).unwrap(),
                vec![dependency],
            );
    assert!(matches!(
        packages::write_packages(&[middle]),
        Err(PackagesError::UnsupportedConstraint { .. })
    ));

    let not_equal = DependencyRequirement::new(
        DependencyKind::Imports,
        PackageName::new("leaf").unwrap(),
        DependencySourceConstraint::Any,
        VersionConstraint::from_clause(RelationOp::Ne, RPackageVersion::parse("0.1.0").unwrap()),
    );
    let middle = MaterializationArtifact::new(
        ReleaseIdentity::new(
            PackageName::new("middle").unwrap(),
            Provenance::ImmutableSource {
                scheme: nrr_core::SourceScheme::new("fixture").unwrap(),
                digest: nrr_core::Sha256Digest::new("b".repeat(64)).unwrap(),
            },
        ),
        RPackageVersion::parse("0.1.0").unwrap(),
        CachedArtifact {
            object_path: PathBuf::from("/tmp/object-2"),
            metadata_path: PathBuf::from("/tmp/metadata-2"),
            sha256: nrr_core::Sha256Digest::new("b".repeat(64)).unwrap(),
            size: 1,
            verification: VerificationStrength::None,
        },
    )
    .with_metadata(
        ReleaseMetadata::from_pairs([("License", "MIT")]).unwrap(),
        vec![not_equal],
    );
    assert!(matches!(
        packages::write_packages(&[middle]),
        Err(PackagesError::UnsupportedConstraint { .. })
    ));
}

#[test]
fn packages_accept_supported_slash_and_hyphen_metadata_names() {
    let cache = CachedArtifact {
        object_path: PathBuf::from("/tmp/object"),
        metadata_path: PathBuf::from("/tmp/metadata"),
        sha256: nrr_core::Sha256Digest::new("a".repeat(64)).unwrap(),
        size: 1,
        verification: VerificationStrength::None,
    };
    let selected = MaterializationArtifact::new(
        ReleaseIdentity::new(
            PackageName::new("fixture").unwrap(),
            Provenance::ImmutableSource {
                scheme: nrr_core::SourceScheme::new("fixture").unwrap(),
                digest: cache.sha256.clone(),
            },
        ),
        RPackageVersion::parse("1.0.0").unwrap(),
        cache,
    )
    .with_metadata(
        ReleaseMetadata::from_pairs([
            ("Config/Needs/website", "https://example.invalid"),
            ("X-CRAN-Comment", "fixture metadata"),
        ])
        .unwrap(),
        vec![],
    );
    let output = String::from_utf8(packages::write_packages(&[selected]).unwrap()).unwrap();
    assert!(output.contains("Config/Needs/website: https://example.invalid\n"));
    assert!(output.contains("X-CRAN-Comment: fixture metadata\n"));
}

#[test]
fn packages_reject_invalid_field_names_and_canonical_duplicate_checksums() {
    let cache = CachedArtifact {
        object_path: PathBuf::from("/tmp/object"),
        metadata_path: PathBuf::from("/tmp/metadata"),
        sha256: nrr_core::Sha256Digest::new("a".repeat(64)).unwrap(),
        size: 1,
        verification: VerificationStrength::None,
    };
    let identity = ReleaseIdentity::new(
        PackageName::new("fixture").unwrap(),
        Provenance::ImmutableSource {
            scheme: nrr_core::SourceScheme::new("fixture").unwrap(),
            digest: cache.sha256.clone(),
        },
    );
    for field in ["", "Bad:Name", " Bad", "Bad\nName", "_bad", "Bad?Name"] {
        let selected = MaterializationArtifact::new(
            identity.clone(),
            RPackageVersion::parse("1.0.0").unwrap(),
            cache.clone(),
        )
        .with_metadata(
            ReleaseMetadata::from_pairs([(field, "value")]).unwrap(),
            vec![],
        );
        assert!(matches!(
            packages::write_packages(&[selected]),
            Err(PackagesError::InvalidFieldName { .. })
        ));
    }
    let duplicate =
        MaterializationArtifact::new(identity, RPackageVersion::parse("1.0.0").unwrap(), cache)
            .with_metadata(
                ReleaseMetadata::from_pairs([("SHA256", "one"), ("SHA256SUM", "two")]).unwrap(),
                vec![],
            );
    assert!(matches!(
        packages::write_packages(&[duplicate]),
        Err(PackagesError::DuplicateField { .. })
    ));
}

#[test]
fn rejects_legacy_materialization_schema() {
    let cache_root = temporary_root("materialize-schema-cache");
    let project_root = temporary_root("materialize-schema-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let selected = registry_selected("schema", "1.0.0", cached);
    materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();
    let state_path = project_root.join(".nrr/materialization.toml");
    let mut state = fs::read_to_string(&state_path).unwrap();
    state = state.replacen("schema_version = 2", "schema_version = 1", 1);
    fs::write(&state_path, state).unwrap();
    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            std::slice::from_ref(&selected),
        )),
        Err(MaterializationError::InvalidState { .. })
    ));
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

fn registry_selected(
    package: &str,
    version: &str,
    cached: CachedArtifact,
) -> MaterializationArtifact {
    let version = RPackageVersion::parse(version).unwrap();
    MaterializationArtifact::new(
        ReleaseIdentity::new(
            PackageName::new(package).unwrap(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        ),
        version,
        cached,
    )
}

#[test]
fn rejects_provenance_version_mismatches() {
    let cache_root = temporary_root("materialize-version-mismatch-cache");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let selected_version = RPackageVersion::parse("2.0.0").unwrap();
    let provenance_version = RPackageVersion::parse("1.0.0").unwrap();
    let identities = [
        (
            "registry",
            PackageName::new("registrypkg").unwrap(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: provenance_version.clone(),
            },
        ),
        (
            "bioconductor",
            PackageName::new("biocpkg").unwrap(),
            Provenance::BioconductorRelease {
                namespace: PackageNamespace::new("bioc").unwrap(),
                release: BioconductorRelease::new("3.20").unwrap(),
                version: provenance_version.clone(),
            },
        ),
        (
            "r-base",
            PackageName::new("R").unwrap(),
            Provenance::RBasePackage {
                r_version: provenance_version,
            },
        ),
    ];
    for (label, package, provenance) in identities {
        let project_root = temporary_root(&format!("materialize-version-mismatch-{label}"));
        let selected = MaterializationArtifact::new(
            ReleaseIdentity::new(package, provenance),
            selected_version.clone(),
            cached.clone(),
        );
        assert!(matches!(
            materialize(MaterializationRequest::new(
                &project_root,
                std::slice::from_ref(&selected),
            )),
            Err(MaterializationError::ProvenanceVersionMismatch { .. })
        ));
        fs::remove_dir_all(project_root).unwrap();
    }
    fs::remove_dir_all(cache_root).unwrap();
}

#[test]
fn canonicalizes_set_order_for_state_and_reruns() {
    let cache_root = temporary_root("materialize-order-cache");
    let first_project = temporary_root("materialize-order-first");
    let second_project = temporary_root("materialize-order-second");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let alpha = registry_selected("alpha", "1.0.0", cached.clone());
    let zeta = registry_selected("zeta", "2.0.0", cached);
    let reverse = [zeta.clone(), alpha.clone()];
    let forward = [alpha, zeta];

    let reverse_state = materialize(MaterializationRequest::new(&first_project, &reverse)).unwrap();
    let forward_state =
        materialize(MaterializationRequest::new(&second_project, &forward)).unwrap();
    assert_eq!(reverse_state, forward_state);
    assert_eq!(
        fs::read(first_project.join(".nrr/materialization.toml")).unwrap(),
        fs::read(second_project.join(".nrr/materialization.toml")).unwrap()
    );

    let rerun = materialize(MaterializationRequest::new(&first_project, &forward)).unwrap();
    assert_eq!(rerun, reverse_state);

    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(first_project).unwrap();
    fs::remove_dir_all(second_project).unwrap();
}

#[test]
fn recovers_repository_published_before_state_rename() {
    let cache_root = temporary_root("materialize-recovery-cache");
    let project_root = temporary_root("materialize-recovery-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let selected = registry_selected("recovery", "1.0.0", cached);
    let expected = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();

    // Model process exit after repository rename but before state rename:
    // move the committed state back to its durable temporary name and create
    // the same marker that production writes before publishing repository.
    let nrr = project_root.join(".nrr");
    let state_path = nrr.join("materialization.toml");
    let state_temp_name = ".materialization.toml.partial.crash";
    let state_temp = nrr.join(state_temp_name);
    let state_bytes = fs::read(&state_path).unwrap();
    fs::rename(&state_path, &state_temp).unwrap();
    let mut marker: toml::Value =
        toml::from_str(std::str::from_utf8(&state_bytes).unwrap()).unwrap();
    marker.as_table_mut().unwrap().insert(
        "state_temp".to_owned(),
        toml::Value::String(state_temp_name.to_owned()),
    );
    marker.as_table_mut().unwrap().insert(
        "staging_dir".to_owned(),
        toml::Value::String(".repository.partial.crash".to_owned()),
    );
    fs::write(
        nrr.join(".materialization.transaction.toml"),
        toml::to_string_pretty(&marker).unwrap(),
    )
    .unwrap();

    let recovered = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();
    assert_eq!(recovered, expected);
    assert!(state_path.is_file());
    assert!(!state_temp.exists());
    assert!(!nrr.join(".materialization.transaction.toml").exists());
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

#[test]
fn recovers_marker_before_repository_rename() {
    let cache_root = temporary_root("materialize-staging-recovery-cache");
    let project_root = temporary_root("materialize-staging-recovery-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let selected = registry_selected("stagingrecovery", "1.0.0", cached);
    let expected = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();

    let nrr = project_root.join(".nrr");
    let repository = nrr.join("repository");
    let staging_name = ".repository.partial.crash";
    let staging = nrr.join(staging_name);
    let state_path = nrr.join("materialization.toml");
    let state_temp_name = ".materialization.toml.partial.crash";
    let state_temp = nrr.join(state_temp_name);
    let state_bytes = fs::read(&state_path).unwrap();
    fs::rename(&repository, &staging).unwrap();
    fs::rename(&state_path, &state_temp).unwrap();
    let mut marker: toml::Value =
        toml::from_str(std::str::from_utf8(&state_bytes).unwrap()).unwrap();
    marker.as_table_mut().unwrap().insert(
        "state_temp".to_owned(),
        toml::Value::String(state_temp_name.to_owned()),
    );
    marker.as_table_mut().unwrap().insert(
        "staging_dir".to_owned(),
        toml::Value::String(staging_name.to_owned()),
    );
    fs::write(
        nrr.join(".materialization.transaction.toml"),
        toml::to_string_pretty(&marker).unwrap(),
    )
    .unwrap();

    let recovered = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();
    assert_eq!(recovered, expected);
    assert!(repository.is_dir());
    assert!(!staging.exists());
    assert!(!state_temp.exists());
    assert!(!nrr.join(".materialization.transaction.toml").exists());
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

#[test]
fn rejects_invalid_state_before_publishing_staging() {
    let cache_root = temporary_root("materialize-invalid-state-cache");
    let project_root = temporary_root("materialize-invalid-state-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let selected = registry_selected("invalidstate", "1.0.0", cached);
    materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();

    let nrr = project_root.join(".nrr");
    let repository = nrr.join("repository");
    let staging_name = ".repository.partial.crash";
    let staging = nrr.join(staging_name);
    let state_path = nrr.join("materialization.toml");
    let state_temp_name = ".materialization.toml.partial.crash";
    let state_temp = nrr.join(state_temp_name);
    let state_bytes = fs::read(&state_path).unwrap();
    fs::rename(&repository, &staging).unwrap();
    fs::rename(&state_path, &state_temp).unwrap();
    let mut marker: toml::Value =
        toml::from_str(std::str::from_utf8(&state_bytes).unwrap()).unwrap();
    marker.as_table_mut().unwrap().insert(
        "state_temp".to_owned(),
        toml::Value::String(state_temp_name.to_owned()),
    );
    marker.as_table_mut().unwrap().insert(
        "staging_dir".to_owned(),
        toml::Value::String(staging_name.to_owned()),
    );
    fs::write(
        nrr.join(".materialization.transaction.toml"),
        toml::to_string_pretty(&marker).unwrap(),
    )
    .unwrap();
    fs::write(&state_temp, "schema_version = 1\nrecords = []\n").unwrap();

    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            std::slice::from_ref(&selected),
        )),
        Err(MaterializationError::TransactionConflict { .. })
    ));
    assert!(staging.is_dir());
    assert!(!repository.exists());
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

#[test]
fn recovers_valid_pre_marker_orphan_without_transaction_temp() {
    let cache_root = temporary_root("materialize-orphan-cleanup-cache");
    let project_root = temporary_root("materialize-orphan-cleanup-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let selected = registry_selected("orphan", "1.0.0", cached);
    materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();

    let nrr = project_root.join(".nrr");
    let repository = nrr.join("repository");
    let staging_name = ".repository.partial.orphan";
    let staging = nrr.join(staging_name);
    let state_path = nrr.join("materialization.toml");
    let state_temp_name = ".materialization.toml.partial.orphan";
    let state_temp = nrr.join(state_temp_name);
    let transaction_temp = nrr.join(".materialization.transaction.toml.partial.orphan");
    let state_bytes = fs::read(&state_path).unwrap();
    fs::rename(&repository, &staging).unwrap();
    fs::rename(&state_path, &state_temp).unwrap();
    let state: MaterializationState =
        toml::from_str(std::str::from_utf8(&state_bytes).unwrap()).unwrap();
    let transaction = MaterializationTransaction {
        schema_version: 2,
        index_sha256: state.index_sha256.clone(),
        state_temp: state_temp_name.to_owned(),
        staging_dir: staging_name.to_owned(),
        records: state.records.clone(),
    };
    fs::write(
        &transaction_temp,
        toml::to_string_pretty(&transaction).unwrap(),
    )
    .unwrap();
    // Model the marker rename being non-durable: state temp and staging remain
    // valid, but the transaction temp itself is absent.
    fs::remove_file(&transaction_temp).unwrap();

    let retried = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();
    assert_eq!(retried.records(), state.records());
    assert!(!state_temp.exists());
    assert!(!transaction_temp.exists());
    assert!(!staging.exists());
    assert!(nrr.join("repository").is_dir());
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

#[cfg(unix)]
#[test]
fn does_not_remove_symlink_or_ambiguous_pre_marker_temps() {
    use std::os::unix::fs::symlink;

    let cache_root = temporary_root("materialize-orphan-safety-cache");
    let project_root = temporary_root("materialize-orphan-safety-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let selected = registry_selected("unsafeorphan", "1.0.0", cached);
    let nrr = project_root.join(".nrr");
    fs::create_dir_all(&nrr).unwrap();
    let target = temporary_root("materialize-orphan-symlink-target");
    let state_link = nrr.join(".materialization.toml.partial.symlink");
    symlink(&target, &state_link).unwrap();
    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            std::slice::from_ref(&selected),
        )),
        Err(MaterializationError::TransactionConflict { .. })
    ));
    assert!(state_link.exists());
    fs::remove_file(state_link).unwrap();
    fs::remove_dir_all(target).unwrap();

    fs::write(nrr.join(".materialization.toml.partial.a"), b"").unwrap();
    fs::write(nrr.join(".materialization.toml.partial.b"), b"").unwrap();
    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            std::slice::from_ref(&selected),
        )),
        Err(MaterializationError::TransactionConflict { .. })
    ));
    assert!(nrr.join(".materialization.toml.partial.a").exists());
    assert!(nrr.join(".materialization.toml.partial.b").exists());
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

#[test]
fn materializes_with_local_gitignore_state_and_independent_bytes() {
    let cache_root = temporary_root("materialize-cache");
    let project_root = temporary_root("materialize-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes.clone()),
    )
    .unwrap();
    let version = RPackageVersion::parse("1.2-3").unwrap();
    let identity = ReleaseIdentity::new(
        PackageName::new("example").unwrap(),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version.clone(),
        },
    );
    let selected = MaterializationArtifact::new(identity, version, cached.clone());
    let state = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();
    assert_eq!(
        fs::read(project_root.join(".nrr/.gitignore")).unwrap(),
        b"*\n"
    );
    assert_eq!(state.records().len(), 1);
    assert!(matches!(
        state.records()[0].method,
        MaterializationMethod::Clone | MaterializationMethod::Copy
    ));
    let destination = project_root.join(".nrr/repository/src/contrib/example_1.2-3.tar.gz");
    assert_eq!(fs::read(&destination).unwrap(), bytes);
    let packages = project_root.join(".nrr/repository/src/contrib/PACKAGES");
    assert!(packages.is_file());
    assert!(!packages.with_extension("gz").exists());
    assert!(!packages.with_extension("rds").exists());
    assert_eq!(
        state.index_sha256,
        hex_lower(&sha2::Sha256::digest(fs::read(&packages).unwrap()))
    );
    let rerun = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();
    assert_eq!(rerun, state);

    let mut output = OpenOptions::new().write(true).open(&destination).unwrap();
    output.write_all(b"changed project view").unwrap();
    assert_eq!(fs::read(cached.path()).unwrap(), archive_bytes());

    let rerun = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ));
    assert!(matches!(
        rerun,
        Err(MaterializationError::ExistingConflict { .. })
    ));
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

#[test]
fn materialization_rejects_duplicate_packages_and_existing_repository() {
    let cache_root = temporary_root("materialize-duplicate-cache");
    let project_root = temporary_root("materialize-duplicate-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let package = PackageName::new("example").unwrap();
    let first_version = RPackageVersion::parse("1.0.0").unwrap();
    let second_version = RPackageVersion::parse("2.0.0").unwrap();
    let first = MaterializationArtifact::new(
        ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: first_version.clone(),
            },
        ),
        first_version,
        cached.clone(),
    );
    let second = MaterializationArtifact::new(
        ReleaseIdentity::new(
            package,
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: second_version.clone(),
            },
        ),
        second_version,
        cached,
    );
    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            &[first.clone(), second],
        )),
        Err(MaterializationError::DuplicatePackage { .. })
    ));
    fs::create_dir_all(project_root.join(".nrr/repository")).unwrap();
    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            std::slice::from_ref(&first),
        )),
        Err(MaterializationError::ExistingConflict { .. })
    ));
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

#[test]
fn interrupted_transaction_rejects_changed_packages_metadata_before_publish() {
    let cache_root = temporary_root("materialize-index-mismatch-cache");
    let project_root = temporary_root("materialize-index-mismatch-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let base = registry_selected("indexmismatch", "1.0.0", cached);
    let original = base.clone().with_metadata(
        ReleaseMetadata::from_pairs([("Description", "old metadata")]).unwrap(),
        vec![],
    );
    materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&original),
    ))
    .unwrap();

    let nrr = project_root.join(".nrr");
    let repository = nrr.join("repository");
    let staging = nrr.join(".repository.partial.index-mismatch");
    let state_path = nrr.join("materialization.toml");
    let state_temp = nrr.join(".materialization.toml.partial.index-mismatch");
    let state_bytes = fs::read(&state_path).unwrap();
    fs::rename(&repository, &staging).unwrap();
    fs::rename(&state_path, &state_temp).unwrap();
    let mut marker: toml::Value =
        toml::from_str(std::str::from_utf8(&state_bytes).unwrap()).unwrap();
    marker.as_table_mut().unwrap().insert(
        "state_temp".to_owned(),
        toml::Value::String(".materialization.toml.partial.index-mismatch".to_owned()),
    );
    marker.as_table_mut().unwrap().insert(
        "staging_dir".to_owned(),
        toml::Value::String(".repository.partial.index-mismatch".to_owned()),
    );
    fs::write(
        nrr.join(".materialization.transaction.toml"),
        toml::to_string_pretty(&marker).unwrap(),
    )
    .unwrap();

    let changed = base.with_metadata(
        ReleaseMetadata::from_pairs([("Description", "new metadata")]).unwrap(),
        vec![],
    );
    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            std::slice::from_ref(&changed),
        )),
        Err(MaterializationError::TransactionConflict { .. })
    ));
    assert!(staging.is_dir());
    assert!(!repository.exists());
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

#[test]
fn invalid_packages_metadata_leaves_no_staging_and_retry_succeeds() {
    let cache_root = temporary_root("materialize-invalid-packages-cache");
    let project_root = temporary_root("materialize-invalid-packages-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let base = registry_selected("invalidpackages", "1.0.0", cached);
    let invalid = base.clone().with_metadata(
        ReleaseMetadata::from_pairs([("Description", "bad\rvalue")]).unwrap(),
        vec![],
    );
    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            std::slice::from_ref(&invalid),
        )),
        Err(MaterializationError::Packages { .. })
    ));
    let nrr = project_root.join(".nrr");
    assert!(!nrr.join("repository").exists());
    assert!(!nrr.join("materialization.toml").exists());
    assert!(!nrr.join(".materialization.transaction.toml").exists());
    assert_eq!(
        fs::read_dir(&nrr)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".repository.partial."))
            .count(),
        0
    );

    let corrected = base.with_metadata(
        ReleaseMetadata::from_pairs([("Description", "corrected value")]).unwrap(),
        vec![],
    );
    assert!(materialize(MaterializationRequest::new(&project_root, &[corrected])).is_ok());
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}
