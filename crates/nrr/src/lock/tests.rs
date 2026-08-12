use super::*;
use nrr_core::{
    Artifact, ArtifactLocator, DistributionMetadata, PackageNamespace, RelationOp, ReleaseMetadata,
    ReleaseObservation, SourceArtifact, UpstreamChecksum,
};
use std::collections::BTreeMap;

fn version(value: &str) -> RPackageVersion {
    RPackageVersion::parse(value).unwrap()
}

fn package(value: &str) -> PackageName {
    PackageName::new(value).unwrap()
}

fn release(name: &str, spelling: &str) -> PackageRelease {
    let name = package(name);
    let version = version(spelling);
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
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap()
}

fn target() -> ResolutionTarget {
    ResolutionTarget::new(version("4.4.0"), nrr_core::Target::new("linux", "x86_64"))
}

fn environment() -> EnvironmentId {
    EnvironmentId::new("default").unwrap()
}

#[test]
fn v1_requires_exactly_one_resolution() {
    assert_eq!(
        Lockfile::new(Vec::new()),
        Err(LockError::UnsupportedResolutionCount { found: 0 })
    );
    let empty = LockedResolution {
        target: target(),
        environment: environment(),
        packages: Vec::new(),
    };
    assert_eq!(
        Lockfile::new(vec![empty.clone(), empty]),
        Err(LockError::UnsupportedResolutionCount { found: 2 })
    );
}

#[test]
fn reader_rejects_registry_record_version_mismatch() {
    let identity = ReleaseIdentity::new(
        package("mismatch"),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.0.0"),
        },
    );
    let package = LockedPackage {
        identity,
        version: version("2.0.0"),
        published_version_spelling: None,
        distributions: Vec::new(),
        dependencies: Vec::new(),
        metadata_sha256: None,
    };
    assert!(matches!(
        Lockfile::new(vec![LockedResolution {
            target: target(),
            environment: environment(),
            packages: vec![package],
        }]),
        Err(LockError::ConflictingMetadata { identity }) if identity.contains("mismatch")
    ));
}

#[test]
fn normalization_is_independent_of_package_edge_and_distribution_input_order() {
    let alpha = package("alpha");
    let beta = package("beta");
    let dependency = |name: &PackageName, kind| LockedDependencyEdge {
        kind,
        name: name.clone(),
        source: DependencySourceConstraint::Any,
        constraint: VersionConstraint::unconstrained(),
    };
    let distribution = |channel: &str| LockedDistributionRef {
        registry: RegistryId::new("cran").unwrap(),
        channel: DistributionChannel::new(channel).unwrap(),
        snapshot: None,
    };
    let make = |name: PackageName| LockedPackage {
        identity: ReleaseIdentity::new(
            name,
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.0.0"),
            },
        ),
        version: version("1.0.0"),
        published_version_spelling: None,
        distributions: vec![distribution("source"), distribution("archive")],
        dependencies: vec![
            dependency(&beta, DependencyKind::Suggests),
            dependency(&alpha, DependencyKind::Depends),
        ],
        metadata_sha256: None,
    };
    let mut reversed = make(alpha.clone());
    reversed.distributions.reverse();
    reversed.dependencies.reverse();
    let ordered = make(alpha.clone());
    let first = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        packages: vec![ordered, make(beta.clone())],
    }])
    .unwrap();
    let second = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        packages: vec![make(beta.clone()), reversed],
    }])
    .unwrap();
    assert_eq!(first, second);
}

#[test]
fn projection_is_sorted_and_keeps_logical_fields_only() {
    let mut first = release("zeta", "1.6-5");
    let second = release("alpha", "2.0.0");
    let dependency = DependencyRequirement::new(
        DependencyKind::Depends,
        package("alpha"),
        DependencySourceConstraint::Any,
        VersionConstraint::from_clause(RelationOp::Ge, version("1.0")),
    );
    first = PackageRelease::try_from(ReleaseObservation {
        identity: first.identity().clone(),
        observed_package: first.identity().name().clone(),
        observed_version: first.version().clone(),
        metadata: first.metadata().clone(),
        dependencies: vec![dependency],
        distributions: vec![Distribution {
            registry: RegistryId::new("cran").unwrap(),
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: Some(SnapshotId::new("2026-01").unwrap()),
            artifacts: vec![Artifact::Source(SourceArtifact {
                locator: ArtifactLocator::new("/machine/private.tar.gz").unwrap(),
                upstream_checksums: vec![UpstreamChecksum::Md5("deadbeef".into())],
                size: Some(123),
            })],
            observed_metadata: DistributionMetadata::default(),
        }],
    })
    .unwrap()
    .with_metadata_digest(Sha256Digest::new("a".repeat(64)).unwrap());
    let resolution = Resolution::new(
        target(),
        vec![
            nrr_core::ResolvedPackage::new(
                SolverKey::InstalledName(second.identity().name().clone()),
                second,
            ),
            nrr_core::ResolvedPackage::new(
                SolverKey::InstalledName(first.identity().name().clone()),
                first,
            ),
        ],
    );
    let lock = Lockfile::from_resolution(&resolution, environment()).unwrap();
    let packages = &lock.single_resolution().unwrap().packages;
    assert_eq!(packages[0].identity.name().as_str(), "alpha");
    assert_eq!(packages[1].identity.name().as_str(), "zeta");
    let zeta = &packages[1];
    assert_eq!(zeta.published_version_spelling.as_deref(), Some("1.6-5"));
    assert_eq!(zeta.dependencies.len(), 1);
    assert_eq!(zeta.distributions.len(), 1);
    assert_eq!(
        zeta.metadata_sha256.as_ref().unwrap().as_str(),
        &"a".repeat(64)
    );
    assert_eq!(zeta.distributions[0].registry.as_str(), "cran");
    // These fields exist only on `Distribution`, never on the lock ref.
    assert!(!format!("{:?}", zeta.distributions[0]).contains("machine/private"));
    assert!(!format!("{:?}", zeta.distributions[0]).contains("deadbeef"));
}

#[test]
fn canonical_version_preserves_two_components_for_published_spelling() {
    let two = LockedPackage::from_release(&release("two", "1.0"));
    let three = LockedPackage::from_release(&release("three", "1.0.0"));
    let zero = LockedPackage::from_release(&release("zero", "0.0"));
    assert_eq!(two.published_version_spelling, None);
    assert_eq!(three.published_version_spelling.as_deref(), Some("1.0.0"));
    assert_eq!(zero.published_version_spelling, None);
}

#[test]
fn downstream_projection_revalidates_mutated_public_lock_state() {
    let name = package("mutable");
    let resolution = Resolution::new(
        target(),
        vec![nrr_core::ResolvedPackage::new(
            SolverKey::InstalledName(name.clone()),
            release("mutable", "1.0.0"),
        )],
    );
    let mut lock = Lockfile::from_resolution(&resolution, environment()).unwrap();
    lock.resolutions[0].packages[0].version = version("2.0.0");
    assert!(matches!(
        lock.locked_identities(),
        Err(LockError::ConflictingMetadata { identity }) if identity.contains("mutable")
    ));
    assert!(matches!(
        lock.resolution_request(
            Manifest::new(
                VersionConstraint::unconstrained(),
                crate::manifest::ManifestTarget::new(version("4.4.0"), "linux", "x86_64",).unwrap(),
                vec![crate::manifest::ManifestDependency::new(
                    name,
                    VersionConstraint::unconstrained(),
                )],
            )
            .unwrap(),
            &environment(),
        ),
        Err(LockError::ConflictingMetadata { .. })
    ));
}

#[test]
fn conflicting_repeated_identity_is_rejected_before_lock_state() {
    let identity_release = release("same", "1.0.0");
    let identity = identity_release.identity().clone();
    let other = identity_release
        .clone()
        .with_metadata_digest(Sha256Digest::new("b".repeat(64)).unwrap());
    let resolution = Resolution::new(
        target(),
        vec![
            nrr_core::ResolvedPackage::new(
                SolverKey::InstalledName(package("same")),
                identity_release,
            ),
            nrr_core::ResolvedPackage::new(SolverKey::InstalledName(package("same")), other),
        ],
    );
    assert!(matches!(
        Lockfile::from_resolution(&resolution, environment()),
        Err(LockError::ConflictingMetadata { identity: value }) if value.contains("same")
    ));
    assert_eq!(identity.name().as_str(), "same");
}

#[test]
fn distinct_identities_with_one_installed_name_are_rejected() {
    let name = package("collision");
    let version = version("1.0.0");
    let first = PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            name.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        ),
        observed_package: name.clone(),
        observed_version: version.clone(),
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap();
    let second = PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            name.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("other").unwrap(),
                version: version.clone(),
            },
        ),
        observed_package: name.clone(),
        observed_version: version,
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap();
    let resolution = Resolution::new(
        target(),
        vec![
            nrr_core::ResolvedPackage::new(SolverKey::InstalledName(name.clone()), first.clone()),
            nrr_core::ResolvedPackage::new(SolverKey::InstalledName(name), second.clone()),
        ],
    );
    assert!(matches!(
        Lockfile::from_resolution(&resolution, environment()),
        Err(LockError::InstalledNameConflict { .. })
    ));
    let first_lock = LockedPackage {
        identity: first.identity().clone(),
        version: first.version().clone(),
        published_version_spelling: None,
        distributions: Vec::new(),
        dependencies: Vec::new(),
        metadata_sha256: None,
    };
    let second_lock = LockedPackage {
        identity: second.identity().clone(),
        version: second.version().clone(),
        published_version_spelling: None,
        distributions: Vec::new(),
        dependencies: Vec::new(),
        metadata_sha256: None,
    };
    assert!(matches!(
        Lockfile::new(vec![LockedResolution {
            target: target(),
            environment: environment(),
            packages: vec![first_lock, second_lock],
        }]),
        Err(LockError::InstalledNameConflict { .. })
    ));
}

#[test]
fn registry_and_bioconductor_locks_retain_exact_and_source_keys() {
    let registry = ReleaseIdentity::new(
        package("registry.pin"),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.0.0"),
        },
    );
    let bioconductor = ReleaseIdentity::new(
        package("bioc.pin"),
        Provenance::BioconductorRelease {
            namespace: PackageNamespace::new("bioc").unwrap(),
            release: nrr_core::BioconductorRelease::new("3.20").unwrap(),
            version: version("2.0.0"),
        },
    );
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        packages: vec![
            LockedPackage {
                identity: registry.clone(),
                version: version("1.0.0"),
                published_version_spelling: None,
                distributions: Vec::new(),
                dependencies: Vec::new(),
                metadata_sha256: None,
            },
            LockedPackage {
                identity: bioconductor.clone(),
                version: version("2.0.0"),
                published_version_spelling: None,
                distributions: Vec::new(),
                dependencies: Vec::new(),
                metadata_sha256: None,
            },
        ],
    }])
    .unwrap();
    let identities = lock.locked_identities().unwrap();

    assert_eq!(
        identities.get(&SolverKey::InstalledName(registry.name().clone())),
        Some(&registry)
    );
    assert_eq!(
        identities.get(&SolverKey::Registry {
            namespace: PackageNamespace::new("cran").unwrap(),
            name: registry.name().clone(),
        }),
        Some(&registry)
    );
    assert_eq!(
        identities.get(&SolverKey::Exact(registry.clone())),
        Some(&registry)
    );

    assert_eq!(
        identities.get(&SolverKey::InstalledName(bioconductor.name().clone())),
        Some(&bioconductor)
    );
    assert_eq!(
        identities.get(&SolverKey::Bioconductor {
            namespace: PackageNamespace::new("bioc").unwrap(),
            release: nrr_core::BioconductorRelease::new("3.20").unwrap(),
            name: bioconductor.name().clone(),
        }),
        Some(&bioconductor)
    );
    assert_eq!(
        identities.get(&SolverKey::Exact(bioconductor.clone())),
        Some(&bioconductor)
    );
}
