use super::*;

#[test]
fn canonical_constructor_accepts_each_provenance_variant() {
    let registry = identity(Provenance::RegistryRelease {
        namespace: PackageNamespace::new("cran").unwrap(),
        version: version("1.6-5"),
    });
    let git = identity(Provenance::GitCommit {
        repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
        commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
        subdirectory: None,
    });
    let bioc = identity(Provenance::BioconductorRelease {
        namespace: PackageNamespace::new("bioc").unwrap(),
        release: BioconductorRelease::new("3.20").unwrap(),
        version: version("1.2.3"),
    });
    let immutable = identity(Provenance::ImmutableSource {
        scheme: SourceScheme::new("sha256").unwrap(),
        digest: Sha256Digest::new("a".repeat(64)).unwrap(),
    });

    for (release_identity, release_version) in [
        (registry, "1.6-5"),
        (git, "1.0.0"),
        (bioc, "1.2.3"),
        (immutable, "9.9.9"),
    ] {
        let release = PackageRelease::try_from(observation(
            release_identity.clone(),
            release_version,
            source_distribution("source"),
        ))
        .unwrap();
        assert_eq!(release.identity(), &release_identity);
        assert_eq!(release.version().as_str(), release_version);
    }
}

#[test]
fn canonical_constructor_rejects_name_and_coordinate_mismatches() {
    let registry_identity = identity(Provenance::RegistryRelease {
        namespace: PackageNamespace::new("cran").unwrap(),
        version: version("1.6-5"),
    });
    let mut wrong_name = observation(registry_identity.clone(), "1.6-5", source_distribution("a"));
    wrong_name.observed_package = package("Other");
    assert!(matches!(
        PackageRelease::try_from(wrong_name),
        Err(PackageReleaseError::ConflictingMetadata { .. })
    ));

    let wrong_version = observation(registry_identity, "1.6-6", source_distribution("b"));
    assert!(matches!(
        PackageRelease::try_from(wrong_version),
        Err(PackageReleaseError::ConflictingMetadata {
            field: "provenance version"
        })
    ));

    let bioc_identity = identity(Provenance::BioconductorRelease {
        namespace: PackageNamespace::new("bioc").unwrap(),
        release: BioconductorRelease::new("3.20").unwrap(),
        version: version("1.2.3"),
    });
    assert!(matches!(
        PackageRelease::try_from(observation(
            bioc_identity,
            "1.2.4",
            source_distribution("c")
        )),
        Err(PackageReleaseError::ConflictingMetadata { .. })
    ));

    let git_identity = identity(Provenance::GitCommit {
        repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
        commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
        subdirectory: None,
    });
    let mut git_wrong_name = observation(git_identity, "1.0.0", source_distribution("d"));
    git_wrong_name.observed_package = package("Other");
    assert!(matches!(
        PackageRelease::try_from(git_wrong_name),
        Err(PackageReleaseError::ConflictingMetadata {
            field: "package name"
        })
    ));

    let immutable_identity = identity(Provenance::ImmutableSource {
        scheme: SourceScheme::new("sha256").unwrap(),
        digest: Sha256Digest::new("b".repeat(64)).unwrap(),
    });
    let mut immutable_wrong_name =
        observation(immutable_identity, "1.0.0", source_distribution("e"));
    immutable_wrong_name.observed_package = package("Other");
    assert!(matches!(
        PackageRelease::try_from(immutable_wrong_name),
        Err(PackageReleaseError::ConflictingMetadata {
            field: "package name"
        })
    ));
}

#[test]
fn canonical_constructor_preserves_dependencies_as_first_class_data() {
    let matrix = package("Matrix");
    let dependency = DeclaredDependency::from_parts(
        DependencyKind::Depends,
        package("R"),
        DependencySourceConstraint::Any,
        VersionConstraint::from_clause(RelationOp::Ge, version("4.4.0")),
    )
    .unwrap();
    let release = PackageRelease::try_from(ReleaseObservation {
        identity: identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        }),
        observed_package: matrix,
        observed_version: version("1.6-5"),
        metadata: ReleaseMetadata::default(),
        publication: None,
        declared_dependencies: vec![dependency.clone()],
        distributions: vec![],
    })
    .unwrap();
    assert_eq!(release.declared_dependencies(), &[dependency]);
}

#[test]
fn canonical_constructor_rejects_exact_dependency_name_mismatch() {
    let release_identity = identity(Provenance::RegistryRelease {
        namespace: PackageNamespace::new("cran").unwrap(),
        version: version("1.6-5"),
    });
    let result = crate::PackageRequirement::new(
        package("Other"),
        DependencySourceConstraint::Exact(release_identity),
        VersionConstraint::unconstrained(),
    );
    assert!(matches!(
        result,
        Err(crate::PackageRequirementError::ExactIdentityNameMismatch { .. })
    ));
}

#[test]
fn r_base_provenance_requires_target_version_match() {
    let package = package("methods");
    let target = version("4.4.0");
    let identity = ReleaseIdentity::new(
        package.clone(),
        Provenance::RBasePackage {
            r_version: target.clone(),
        },
    );
    let release = PackageRelease::try_from(ReleaseObservation {
        identity: identity.clone(),
        observed_package: package.clone(),
        observed_version: target.clone(),
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap();
    assert!(release.is_r_base_package());
    assert!(identity.provenance().is_r_base_package());

    let mismatch = PackageRelease::try_from(ReleaseObservation {
        identity,
        observed_package: package,
        observed_version: version("4.3.0"),
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    });
    assert!(matches!(
        mismatch,
        Err(PackageReleaseError::ConflictingMetadata {
            field: "provenance version"
        })
    ));
}
