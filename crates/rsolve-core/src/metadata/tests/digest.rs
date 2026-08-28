use super::*;

#[test]
fn metadata_digest_is_canonical_and_excludes_distribution_facts() {
    let provenance = Provenance::RegistryRelease {
        namespace: PackageNamespace::new("cran").unwrap(),
        version: version("1.0"),
    };
    let mut first = observation(
        identity(provenance.clone()),
        "1.0",
        source_distribution("a"),
    );
    first.declared_dependencies = vec![
        digest_dependency("lattice", DependencyKind::Imports),
        digest_dependency("R", DependencyKind::Depends),
    ];
    let mut reversed = first.clone();
    reversed.declared_dependencies.reverse();
    reversed.distributions = vec![source_distribution("different-artifact")];
    let first_release = PackageRelease::try_from(first).unwrap();
    let reversed_release = PackageRelease::try_from(reversed).unwrap();
    assert_eq!(
        first_release.metadata_digest(),
        reversed_release.metadata_digest()
    );

    let mut changed = observation(identity(provenance), "1.0", source_distribution("a"));
    changed.declared_dependencies = vec![digest_dependency("lattice", DependencyKind::Suggests)];
    assert_ne!(
        first_release.metadata_digest(),
        PackageRelease::try_from(changed).unwrap().metadata_digest()
    );
}

#[test]
fn metadata_digest_uses_semantic_versions_and_logical_sources() {
    let dependency = DeclaredDependency::from_parts(
        DependencyKind::Imports,
        package("lattice"),
        DependencySourceConstraint::Any,
        VersionConstraint::from_clause(RelationOp::Ge, version("1.0-0")),
    )
    .unwrap();
    let equivalent_identity = identity(Provenance::RegistryRelease {
        namespace: PackageNamespace::new("cran").unwrap(),
        version: version("1.6.5"),
    });
    let mut equivalent = observation(
        equivalent_identity,
        "1.6.5",
        source_distribution("equivalent"),
    );
    equivalent.declared_dependencies = vec![dependency.clone()];

    let raw_spelling_identity = identity(Provenance::RegistryRelease {
        namespace: PackageNamespace::new("cran").unwrap(),
        version: version("01.6-5.0"),
    });
    let mut raw_spelling = observation(
        raw_spelling_identity,
        "01.6-5.0",
        source_distribution("different-artifact"),
    );
    raw_spelling.declared_dependencies = vec![
        DeclaredDependency::from_parts(
            DependencyKind::Imports,
            package("lattice"),
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(RelationOp::Ge, version("1.0.0")),
        )
        .unwrap(),
    ];
    let equivalent_release = PackageRelease::try_from(equivalent).unwrap();
    let raw_spelling_release = PackageRelease::try_from(raw_spelling).unwrap();
    assert_eq!(
        equivalent_release.metadata_digest(),
        raw_spelling_release.metadata_digest()
    );

    let mut duplicate = observation(
        identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6.5"),
        }),
        "1.6.5",
        source_distribution("duplicate"),
    );
    duplicate.declared_dependencies = vec![dependency.clone(), dependency];
    assert_eq!(
        equivalent_release.metadata_digest(),
        PackageRelease::try_from(duplicate)
            .unwrap()
            .metadata_digest()
    );

    let namespace_changed = PackageRelease::try_from(observation(
        identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("other").unwrap(),
            version: version("1.6.5"),
        }),
        "1.6.5",
        source_distribution("namespace"),
    ))
    .unwrap();
    assert_ne!(
        equivalent_release.metadata_digest(),
        namespace_changed.metadata_digest()
    );

    let git_identity = |commit: &str| {
        identity(Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new(commit).unwrap(),
            subdirectory: None,
        })
    };
    let git_release = PackageRelease::try_from(observation(
        git_identity("abcdef0123456789abcdef0123456789abcdef01"),
        "1.0.0",
        source_distribution("git-a"),
    ))
    .unwrap();
    let changed_git_release = PackageRelease::try_from(observation(
        git_identity("1234567890abcdef1234567890abcdef12345678"),
        "1.0.0",
        source_distribution("git-b"),
    ))
    .unwrap();
    assert_ne!(
        git_release.metadata_digest(),
        changed_git_release.metadata_digest()
    );

    let source_changed = PackageRelease::try_from(observation(
        identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6.5"),
        }),
        "1.6.5",
        source_distribution("source-change"),
    ))
    .unwrap();
    let mut source_observation = observation(
        identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6.5"),
        }),
        "1.6.5",
        source_distribution("source-change"),
    );
    source_observation.declared_dependencies = vec![
        DeclaredDependency::from_parts(
            DependencyKind::Imports,
            package("lattice"),
            DependencySourceConstraint::Registry {
                namespace: PackageNamespace::new("cran").unwrap(),
            },
            VersionConstraint::from_clause(RelationOp::Gt, version("1.0.0")),
        )
        .unwrap(),
    ];
    let changed_dependency = PackageRelease::try_from(source_observation).unwrap();
    assert_ne!(
        source_changed.metadata_digest(),
        changed_dependency.metadata_digest()
    );

    let dependency_variant = |source, op, dependency_version| {
        let mut observation = observation(
            identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.6.5"),
            }),
            "1.6.5",
            source_distribution("dependency-variant"),
        );
        observation.declared_dependencies = vec![
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                package("lattice"),
                source,
                VersionConstraint::from_clause(op, version(dependency_version)),
            )
            .unwrap(),
        ];
        PackageRelease::try_from(observation).unwrap()
    };
    assert_ne!(
        equivalent_release.metadata_digest(),
        dependency_variant(
            DependencySourceConstraint::Registry {
                namespace: PackageNamespace::new("cran").unwrap(),
            },
            RelationOp::Ge,
            "1.0.0",
        )
        .metadata_digest()
    );
    assert_ne!(
        equivalent_release.metadata_digest(),
        dependency_variant(DependencySourceConstraint::Any, RelationOp::Gt, "1.0.0")
            .metadata_digest()
    );
    assert_ne!(
        equivalent_release.metadata_digest(),
        dependency_variant(DependencySourceConstraint::Any, RelationOp::Ge, "1.1.0")
            .metadata_digest()
    );
}

#[test]
fn metadata_digest_changes_for_coordinate_version_but_not_publication() {
    let base_identity = identity(Provenance::RegistryRelease {
        namespace: PackageNamespace::new("cran").unwrap(),
        version: version("1.0"),
    });
    let base = PackageRelease::try_from(observation(
        base_identity.clone(),
        "1.0",
        source_distribution("base"),
    ))
    .unwrap();

    let mut published = observation(base_identity.clone(), "1.0", source_distribution("base"));
    published.publication = Some(ReleasePublication::new(
        PublicationDate::parse("2026-01-01").unwrap(),
    ));
    let published_release = PackageRelease::try_from(published).unwrap();
    assert_eq!(base.metadata_digest(), published_release.metadata_digest());

    let mut published_later = observation(base_identity, "1.0", source_distribution("base"));
    published_later.publication = Some(ReleasePublication::new(
        PublicationDate::parse("2026-02-01").unwrap(),
    ));
    assert_eq!(
        published_release.metadata_digest(),
        PackageRelease::try_from(published_later)
            .unwrap()
            .metadata_digest()
    );

    let changed_version = PackageRelease::try_from(observation(
        identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.1"),
        }),
        "1.1",
        source_distribution("base"),
    ))
    .unwrap();
    assert_ne!(base.metadata_digest(), changed_version.metadata_digest());

    let other_name = ReleaseIdentity::new(
        package("Other"),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.0"),
        },
    );
    let other =
        PackageRelease::try_from(observation(other_name, "1.0", source_distribution("base")))
            .unwrap();
    assert_ne!(base.metadata_digest(), other.metadata_digest());
}

#[test]
fn metadata_rejects_dependency_and_identity_fields() {
    let mut fields = BTreeMap::new();
    fields.insert("Depends".to_owned(), "R (>= 4.4)".to_owned());
    assert!(matches!(
        ReleaseMetadata::new(fields),
        Err(ReleaseMetadataError::ReservedField { .. })
    ));
}
