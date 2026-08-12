use super::*;
use crate::lock::LockedDistributionRef;

fn version(value: &str) -> RPackageVersion {
    RPackageVersion::parse(value).unwrap()
}

fn package(value: &str) -> PackageName {
    PackageName::new(value).unwrap()
}

fn identity(name: &str, provenance: Provenance) -> ReleaseIdentity {
    ReleaseIdentity::new(package(name), provenance)
}

fn distribution(channel: &str, snapshot: Option<&str>) -> LockedDistributionRef {
    LockedDistributionRef {
        registry: RegistryId::new("cran").unwrap(),
        channel: DistributionChannel::new(channel).unwrap(),
        snapshot: snapshot.map(|value| SnapshotId::new(value).unwrap()),
    }
}

fn dependency(
    kind: DependencyKind,
    name: &str,
    source: DependencySourceConstraint,
    op: RelationOp,
) -> LockedDependencyEdge {
    LockedDependencyEdge {
        kind,
        name: package(name),
        source,
        constraint: VersionConstraint::new(vec![VersionClause::new(op, version("1.0"))]),
    }
}

fn package_record(name: &str, provenance: Provenance) -> LockedPackage {
    LockedPackage {
        identity: identity(name, provenance),
        version: version("1.0"),
        published_version_spelling: None,
        distributions: vec![distribution("source", Some("snapshot-1"))],
        dependencies: vec![
            dependency(
                DependencyKind::Depends,
                "dep.any",
                DependencySourceConstraint::Any,
                RelationOp::Ge,
            ),
            dependency(
                DependencyKind::Imports,
                "dep.registry",
                DependencySourceConstraint::Registry {
                    namespace: nrr_core::PackageNamespace::new("cran").unwrap(),
                },
                RelationOp::Eq,
            ),
            dependency(
                DependencyKind::LinkingTo,
                "dep.bioc",
                DependencySourceConstraint::Bioconductor {
                    namespace: nrr_core::PackageNamespace::new("bioc").unwrap(),
                    release: nrr_core::BioconductorRelease::new("3.20").unwrap(),
                },
                RelationOp::Le,
            ),
            dependency(
                DependencyKind::Suggests,
                "dep.git",
                DependencySourceConstraint::Git {
                    repository: nrr_core::NormalizedGitUrl::new("https://example.test/repo")
                        .unwrap(),
                },
                RelationOp::Ne,
            ),
            dependency(
                DependencyKind::Enhances,
                "dep.exact",
                DependencySourceConstraint::Exact(identity(
                    "dep.exact",
                    Provenance::ImmutableSource {
                        scheme: SourceScheme::new("sha256").unwrap(),
                        digest: Sha256Digest::new("b".repeat(64)).unwrap(),
                    },
                )),
                RelationOp::Lt,
            ),
        ],
        metadata_sha256: Some(Sha256Digest::new("a".repeat(64)).unwrap()),
    }
}

fn logical_lock() -> Lockfile {
    Lockfile::new(vec![LockedResolution {
        target: nrr_core::ResolutionTarget::new(
            version("4.4.0"),
            nrr_core::Target::new("linux", "x86_64"),
        ),
        environment: EnvironmentId::new("default").unwrap(),
        packages: vec![
            package_record(
                "registry",
                Provenance::RegistryRelease {
                    namespace: nrr_core::PackageNamespace::new("cran").unwrap(),
                    version: version("1.0"),
                },
            ),
            package_record(
                "bioc",
                Provenance::BioconductorRelease {
                    namespace: nrr_core::PackageNamespace::new("bioc").unwrap(),
                    release: nrr_core::BioconductorRelease::new("3.20").unwrap(),
                    version: version("1.0"),
                },
            ),
            package_record(
                "git",
                Provenance::GitCommit {
                    repository: nrr_core::NormalizedGitUrl::new("https://example.test/repo")
                        .unwrap(),
                    commit: nrr_core::GitCommitId::new("0123456789abcdef0123456789abcdef01234567")
                        .unwrap(),
                    subdirectory: Some(RepositorySubdir::new("sub/pkg").unwrap()),
                },
            ),
            package_record(
                "immutable",
                Provenance::ImmutableSource {
                    scheme: SourceScheme::new("sha256").unwrap(),
                    digest: Sha256Digest::new("c".repeat(64)).unwrap(),
                },
            ),
        ],
    }])
    .unwrap()
}

#[test]
fn all_logical_provenance_and_source_constraints_round_trip() {
    let lock = logical_lock();
    let text = to_toml(&lock).unwrap();
    let decoded = from_toml(&text).unwrap();
    assert_eq!(decoded, lock);
    assert!(text.contains("schema-version = 1"));
    assert!(text.contains("linking-to"));
}

#[test]
fn identity_encoding_is_canonical_and_lossless() {
    for package in &logical_lock().resolutions[0].packages {
        let encoded = encode_identity(&package.identity).unwrap();
        assert_eq!(decode_identity(&encoded).unwrap(), package.identity);
    }
    for (value, expected) in [
        ("registry:cran::registry@1.0.0", "noncanonical version"),
        ("registry:cran::registry%2E@1.0", "over-escaped unreserved"),
        ("registry:cran::registry%2e@1.0", "lowercase percent hex"),
        (
            "git:https%3A%2F%2FEXAMPLE.test%2Frepo@0123456789abcdef0123456789abcdef01234567::git",
            "non-normalized URL",
        ),
        (
            "git:https%3A%2F%2Fexample.test%2Frepo@0123::git",
            "abbreviated commit",
        ),
    ] {
        assert!(
            matches!(
                decode_identity(value),
                Err(LockWireError::NonCanonicalIdentity(_))
                    | Err(LockWireError::InvalidIdentity(_))
            ),
            "{expected}"
        );
    }
}

#[test]
fn canonical_version_fields_have_one_wire_spelling() {
    let make_lock = |package_version: &str, clause_version: &str, r_version: &str| {
        Lockfile::new(vec![LockedResolution {
            target: nrr_core::ResolutionTarget::new(
                version(r_version),
                nrr_core::Target::new("linux", "x86_64"),
            ),
            environment: EnvironmentId::new("default").unwrap(),
            packages: vec![LockedPackage {
                identity: identity(
                    "spellings",
                    Provenance::RegistryRelease {
                        namespace: nrr_core::PackageNamespace::new("cran").unwrap(),
                        version: version(package_version),
                    },
                ),
                version: version(package_version),
                published_version_spelling: None,
                distributions: Vec::new(),
                dependencies: vec![LockedDependencyEdge {
                    kind: DependencyKind::Depends,
                    name: package("dep"),
                    source: DependencySourceConstraint::Any,
                    constraint: VersionConstraint::new(vec![VersionClause::new(
                        RelationOp::Ge,
                        version(clause_version),
                    )]),
                }],
                metadata_sha256: None,
            }],
        }])
        .unwrap()
    };
    let canonical = make_lock("1.6.5", "1.0", "4.4");
    let alternate = make_lock("1.6-5", "1.0.0", "4.4.0");
    let leading_zero = make_lock("01.6.5", "01.0", "04.4");
    assert_eq!(to_toml(&canonical).unwrap(), to_toml(&alternate).unwrap());
    assert_eq!(
        to_toml(&canonical).unwrap(),
        to_toml(&leading_zero).unwrap()
    );
    let text = to_toml(&canonical).unwrap();
    assert!(matches!(
        from_toml(&text.replace("r-version = \"4.4\"", "r-version = \"4.4.0\"")),
        Err(LockWireError::NonCanonicalVersion { field, .. }) if field == "r-version"
    ));
    assert!(matches!(
        from_toml(&text.replace("version = \"1.6.5\"", "version = \"1.6.5.0\"")),
        Err(LockWireError::NonCanonicalVersion { field, .. }) if field == "version"
    ));
    assert!(matches!(
        from_toml(&text.replace("version = \"1.6.5\"", "version = \"01.6.5\"")),
        Err(LockWireError::NonCanonicalVersion { field, .. }) if field == "version"
    ));
    assert!(matches!(
        from_toml(&text.replace("op = \"ge\"\nversion = \"1.0\"", "op = \"ge\"\nversion = \"1.0.0\"")),
        Err(LockWireError::NonCanonicalVersion { field, .. })
            if field == "dependency.clauses.version"
    ));
}

#[test]
fn one_component_target_r_version_round_trips() {
    let lock = Lockfile::new(vec![LockedResolution {
        target: nrr_core::ResolutionTarget::new(
            RPackageVersion::parse_bare("4").unwrap(),
            nrr_core::Target::new("linux", "x86_64"),
        ),
        environment: EnvironmentId::new("default").unwrap(),
        packages: Vec::new(),
    }])
    .unwrap();
    let text = to_toml(&lock).unwrap();
    assert!(text.contains("r-version = \"4\""));
    assert_eq!(from_toml(&text).unwrap(), lock);
}

#[test]
fn resolution_projection_wire_output_excludes_artifact_facts() {
    let name = package("artifactless");
    let release_version = version("1.0");
    let release = nrr_core::PackageRelease::try_from(nrr_core::ReleaseObservation {
        identity: identity(
            "artifactless",
            Provenance::RegistryRelease {
                namespace: nrr_core::PackageNamespace::new("cran").unwrap(),
                version: release_version.clone(),
            },
        ),
        observed_package: name,
        observed_version: release_version,
        metadata: nrr_core::ReleaseMetadata::default(),
        dependencies: Vec::new(),
        distributions: vec![nrr_core::Distribution {
            registry: RegistryId::new("cran").unwrap(),
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: None,
            artifacts: vec![nrr_core::Artifact::Source(nrr_core::SourceArtifact {
                locator: nrr_core::ArtifactLocator::new("/machine/secret.tar.gz").unwrap(),
                upstream_checksums: vec![nrr_core::UpstreamChecksum::Md5("deadbeef".into())],
                size: Some(4242),
            })],
            observed_metadata: nrr_core::DistributionMetadata::default(),
        }],
    })
    .unwrap();
    let resolution = nrr_core::Resolution::new(
        nrr_core::ResolutionTarget::new(version("4.4"), nrr_core::Target::new("linux", "x86_64")),
        vec![nrr_core::ResolvedPackage::new(
            nrr_core::SolverKey::InstalledName(package("artifactless")),
            release,
        )],
    );
    let lock =
        Lockfile::from_resolution(&resolution, EnvironmentId::new("default").unwrap()).unwrap();
    let text = to_toml(&lock).unwrap();
    for forbidden in ["/machine/secret.tar.gz", "deadbeef", "4242"] {
        assert!(!text.contains(forbidden));
    }
}

#[test]
fn reader_enforces_schema_and_exactly_one_resolution() {
    let empty = "schema-version = 1\nschema-revision = 0\nresolutions = []\n";
    assert!(matches!(
        from_toml(empty),
        Err(LockWireError::Domain(
            LockError::UnsupportedResolutionCount { found: 0 }
        ))
    ));
    let two = "schema-version = 1\nschema-revision = 0\n\n[[resolutions]]\nenvironment = \"default\"\nr-version = \"4.4\"\nos = \"linux\"\narch = \"x86_64\"\npackages = []\n\n[[resolutions]]\nenvironment = \"other\"\nr-version = \"4.4\"\nos = \"linux\"\narch = \"x86_64\"\npackages = []\n";
    assert!(matches!(
        from_toml(two),
        Err(LockWireError::Domain(
            LockError::UnsupportedResolutionCount { found: 2 }
        ))
    ));
    assert!(matches!(
        from_toml("schema-version = 2\nschema-revision = 0\nresolutions = []\n"),
        Err(LockWireError::UnsupportedSchema { .. })
    ));
}

#[test]
fn unknown_and_machine_local_fields_are_rejected_and_not_emitted() {
    let unknown =
        "schema-version = 1\nschema-revision = 0\nartifact-url = \"/tmp/a\"\nresolutions = []\n";
    assert!(matches!(from_toml(unknown), Err(LockWireError::Parse(_))));
    let forbidden = "schema-version = 1\nschema-revision = 0\n\n[[resolutions]]\nenvironment = \"default\"\nr-version = \"4.4\"\nos = \"linux\"\narch = \"x86_64\"\n\n[[resolutions.packages]]\nidentity = \"registry:cran::foo@1.0\"\nversion = \"1.0\"\ndistributions = []\ndependencies = []\nartifact-url = \"/tmp/a\"\n";
    assert!(matches!(from_toml(forbidden), Err(LockWireError::Parse(_))));
    let text = to_toml(&logical_lock()).unwrap();
    for forbidden in [
        "artifact-url",
        "cache-path",
        "link-method",
        "artifact-sha256",
        "size",
    ] {
        assert!(!text.contains(forbidden));
    }
}

#[test]
fn reversed_logical_input_has_identical_wire_bytes() {
    let first = logical_lock();
    let mut resolution = first.resolutions[0].clone();
    resolution.packages.reverse();
    for package in &mut resolution.packages {
        package.dependencies.reverse();
        package.distributions.reverse();
    }
    let second = Lockfile::new(vec![resolution]).unwrap();
    assert_eq!(to_toml(&first).unwrap(), to_toml(&second).unwrap());
}
