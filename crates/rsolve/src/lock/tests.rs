use super::*;
use rsolve_core::{
    Artifact, ArtifactLocator, DeclaredDependency, DependencySourceConstraint, Distribution,
    DistributionChannel, DistributionMetadata, EffectiveDependencyKind, PackageNamespace,
    PackageRequirement, RegistryId, RelationOp, ReleaseMetadata, ReleaseObservation,
    ResolvedDependencyEdge, SnapshotId, SourceArtifact, UpstreamChecksum, VersionConstraint,
};
use std::collections::BTreeMap;

fn version(value: &str) -> RPackageVersion {
    RPackageVersion::parse(value).unwrap()
}

#[test]
fn canonical_lock_basename_uses_reserved_default_name() {
    assert_eq!(
        canonical_lock_basename(&EnvironmentId::new("default").unwrap()),
        "rsolve.lock"
    );
    assert_eq!(
        canonical_lock_basename(&EnvironmentId::new("test").unwrap()),
        "rsolve.test.lock"
    );
}

fn package(value: &str) -> PackageName {
    PackageName::new(value).unwrap()
}

fn edge(value: &str) -> LockedDependencyEdge {
    LockedDependencyEdge {
        kind: EffectiveDependencyKind::Depends,
        package: package(value),
    }
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
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap()
}

fn target() -> ResolutionTarget {
    ResolutionTarget::new(version("4.4.0"))
}

fn environment() -> EnvironmentId {
    EnvironmentId::new("default").unwrap()
}

fn manifest_for(name: &str, constraint: VersionConstraint) -> Manifest {
    Manifest::new(
        VersionConstraint::from_clause(RelationOp::Ge, version("4.0")),
        crate::manifest::ManifestTarget::new(target().r_version),
        vec![crate::manifest::ManifestDependency::new(
            package(name),
            constraint,
        )],
    )
    .unwrap()
}

fn digest() -> Sha256Digest {
    Sha256Digest::new("0".repeat(64)).unwrap()
}

fn composed_repository(id: &str) -> crate::manifest::RepositorySpec {
    crate::manifest::RepositorySpec::new(
        rsolve_core::RepositoryId::new(id).unwrap(),
        crate::manifest::RegistrySpec::Cran,
        crate::manifest::Endpoint::new("https://example.org/cran").unwrap(),
    )
    .unwrap()
}

fn composed_environment(
    repositories: Vec<crate::manifest::RepositorySpec>,
    roots: Vec<crate::manifest::ComposedRootIntent>,
) -> crate::manifest::ComposedEnvironment {
    crate::manifest::ComposedEnvironment {
        environment: environment(),
        r_requirement: VersionConstraint::unconstrained(),
        published_before: None,
        target: target(),
        repositories,
        roots,
        locked: rsolve_core::LockedIdentities::new(),
    }
}

fn composed_root(
    name: &str,
    source: crate::manifest::ManifestSource,
) -> crate::manifest::ComposedRootIntent {
    crate::manifest::ComposedRootIntent {
        name: package(name),
        constraint: VersionConstraint::unconstrained(),
        source,
        expansion: rsolve_core::RootExpansionPolicy::HardOnly,
    }
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
        publication_cutoff: None,
        packages: Vec::new(),
    };
    assert_eq!(
        Lockfile::new(vec![empty.clone(), empty]),
        Err(LockError::UnsupportedResolutionCount { found: 2 })
    );
}

#[test]
fn composed_consumption_accepts_configured_visible_repository() {
    let repository = rsolve_core::RepositoryId::new("main").unwrap();
    let mut locked = LockedPackage::from_release(&release("root", "1.0.0"));
    locked.visible_repository_ids = vec![repository.clone()];
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![locked.clone()],
    }])
    .unwrap();
    let composed = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(repository),
            },
        )],
    );
    assert!(lock.consume_composed_environment(&composed).is_ok());
}

#[test]
fn composed_consumption_rejects_unknown_visible_repository_and_root_mismatch() {
    let unknown = rsolve_core::RepositoryId::new("unknown").unwrap();
    let mut locked = LockedPackage::from_release(&release("root", "1.0.0"));
    locked.visible_repository_ids = vec![unknown.clone()];
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![locked.clone()],
    }])
    .unwrap();
    let composed = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(rsolve_core::RepositoryId::new("main").unwrap()),
            },
        )],
    );
    assert!(matches!(
        lock.consume_composed_environment(&composed),
        Err(LockError::UnknownVisibleRepository { repository, .. }) if repository == "unknown"
    ));

    locked.visible_repository_ids = vec![rsolve_core::RepositoryId::new("other").unwrap()];
    let mismatch_lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![locked],
    }])
    .unwrap();
    let mismatch = composed_environment(
        vec![composed_repository("main"), composed_repository("other")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(rsolve_core::RepositoryId::new("main").unwrap()),
            },
        )],
    );
    assert!(matches!(
        mismatch_lock.consume_composed_environment(&mismatch),
        Err(LockError::RootRepositoryNotVisible { repository, .. }) if repository == "main"
    ));
}

#[test]
fn composed_consumption_neutral_and_direct_roots_do_not_require_visibility() {
    let locked = LockedPackage::from_release(&release("root", "1.0.0"));
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![locked],
    }])
    .unwrap();
    let neutral = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry { repository: None },
        )],
    );
    assert!(lock.consume_composed_environment(&neutral).is_ok());
    let direct = composed_environment(
        Vec::new(),
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Url {
                url: crate::manifest::DirectUrl::parse("https://example.org/root.tar.gz").unwrap(),
                sha256: None,
            },
        )],
    );
    assert!(lock.consume_composed_environment(&direct).is_ok());
}

#[test]
fn composed_consumption_applies_r_base_overlay_only_to_unqualified_roots() {
    let empty_lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: Vec::new(),
    }])
    .unwrap();
    let unqualified = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "stats",
            crate::manifest::ManifestSource::Registry { repository: None },
        )],
    );
    assert!(
        empty_lock
            .consume_composed_environment(&unqualified)
            .is_ok()
    );

    let qualified = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "stats",
            crate::manifest::ManifestSource::Registry {
                repository: Some(rsolve_core::RepositoryId::new("main").unwrap()),
            },
        )],
    );
    assert!(matches!(
        empty_lock.consume_composed_environment(&qualified),
        Err(LockError::DirectRootMissing { name }) if name == "stats"
    ));

    let direct = composed_environment(
        Vec::new(),
        vec![composed_root(
            "stats",
            crate::manifest::ManifestSource::Url {
                url: crate::manifest::DirectUrl::parse("https://example.org/stats.tar.gz").unwrap(),
                sha256: None,
            },
        )],
    );
    assert!(matches!(
        empty_lock.consume_composed_environment(&direct),
        Err(LockError::DirectRootMissing { name }) if name == "stats"
    ));
}

#[test]
fn composed_consumption_requires_matching_publication_cutoff() {
    let cutoff = PublicationDate::parse("2026-08-01").unwrap();
    let other_cutoff = PublicationDate::parse("2026-08-02").unwrap();
    let lock_with_cutoff = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: Some(cutoff),
        packages: vec![LockedPackage::from_release(&release("root", "1.0.0"))],
    }])
    .unwrap();
    let mut composed = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry { repository: None },
        )],
    );
    assert!(matches!(
        lock_with_cutoff.consume_composed_environment(&composed),
        Err(LockError::PublicationCutoffMismatch {
            lock: Some(lock),
            composed: None,
        }) if lock == "2026-08-01"
    ));
    composed.published_before = Some(other_cutoff);
    assert!(matches!(
        lock_with_cutoff.consume_composed_environment(&composed),
        Err(LockError::PublicationCutoffMismatch {
            lock: Some(lock),
            composed: Some(composed),
        }) if lock == "2026-08-01" && composed == "2026-08-02"
    ));
    composed.published_before = Some(cutoff);
    assert!(
        lock_with_cutoff
            .consume_composed_environment(&composed)
            .is_ok()
    );

    let lock_without_cutoff = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![LockedPackage::from_release(&release("root", "1.0.0"))],
    }])
    .unwrap();
    assert!(matches!(
        lock_without_cutoff.consume_composed_environment(&composed),
        Err(LockError::PublicationCutoffMismatch {
            lock: None,
            composed: Some(composed),
        }) if composed == "2026-08-01"
    ));
}

#[test]
fn composed_consumption_checks_transitive_visible_repositories() {
    let main = rsolve_core::RepositoryId::new("main").unwrap();
    let unknown = rsolve_core::RepositoryId::new("unknown").unwrap();
    let mut root = LockedPackage::from_release(&release("root", "1.0.0"));
    root.dependencies = vec![edge("child")];
    root.visible_repository_ids = vec![main];
    let mut child = LockedPackage::from_release(&release("child", "1.0.0"));
    child.visible_repository_ids = vec![unknown];
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![root, child],
    }])
    .unwrap();
    let composed = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(rsolve_core::RepositoryId::new("main").unwrap()),
            },
        )],
    );
    assert!(matches!(
        lock.consume_composed_environment(&composed),
        Err(LockError::UnknownVisibleRepository { package, repository })
            if package == "child" && repository == "unknown"
    ));
}

#[test]
fn composed_consumption_rejects_visible_repositories_out_of_manifest_order() {
    let first = rsolve_core::RepositoryId::new("first").unwrap();
    let second = rsolve_core::RepositoryId::new("second").unwrap();
    let mut locked = LockedPackage::from_release(&release("root", "1.0.0"));
    locked.visible_repository_ids = vec![second.clone(), first.clone()];
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![locked],
    }])
    .unwrap();
    let composed = composed_environment(
        vec![composed_repository("first"), composed_repository("second")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(first),
            },
        )],
    );
    assert!(matches!(
        lock.consume_composed_environment(&composed),
        Err(LockError::VisibleRepositoryOrderMismatch { package }) if package == "root"
    ));
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
        dependencies: Vec::new(),
        visible_repository_ids: Vec::new(),
        metadata_sha256: digest(),
    };
    assert!(matches!(
        Lockfile::new(vec![LockedResolution {
            target: target(),
            environment: environment(),
            publication_cutoff: None,
            packages: vec![package],
        }]),
        Err(LockError::ConflictingMetadata { identity }) if identity.contains("mismatch")
    ));
}

#[test]
fn normalization_is_independent_of_package_edge_and_distribution_input_order() {
    let alpha = package("alpha");
    let beta = package("beta");
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
        dependencies: vec![edge("beta"), edge("alpha")],
        visible_repository_ids: Vec::new(),
        metadata_sha256: digest(),
    };
    let mut reversed = make(alpha.clone());
    reversed.dependencies.reverse();
    let ordered = make(alpha.clone());
    let first = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![ordered, make(beta.clone())],
    }])
    .unwrap();
    let second = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![make(beta.clone()), reversed],
    }])
    .unwrap();
    assert_eq!(first, second);
}

#[test]
fn projection_is_sorted_and_keeps_logical_fields_only() {
    let mut first = release("zeta", "1.6-5");
    let second = release("alpha", "2.0.0");
    let dependency = DeclaredDependency::from_parts(
        DependencyKind::Depends,
        package("alpha"),
        DependencySourceConstraint::Any,
        VersionConstraint::from_clause(RelationOp::Ge, version("1.0")),
    )
    .unwrap();
    first = PackageRelease::try_from(ReleaseObservation {
        identity: first.identity().clone(),
        observed_package: first.identity().name().clone(),
        observed_version: first.version().clone(),
        metadata: first.metadata().clone(),
        publication: first.publication().copied(),
        declared_dependencies: vec![dependency.clone()],
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
    .unwrap();
    let resolution = Resolution::new(
        target(),
        vec![
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(second.identity().name().clone()),
                second,
                Vec::new(),
                Vec::new(),
            ),
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(first.identity().name().clone()),
                first,
                vec![ResolvedDependencyEdge {
                    kind: EffectiveDependencyKind::Depends,
                    package: dependency.package,
                }],
                Vec::new(),
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
    assert!(!zeta.metadata_sha256.as_str().is_empty());
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
fn projection_preserves_effective_dependency_reasons_and_visibility() {
    let root = release("root", "1.0.0");
    let selected_dependency = release("selected", "1.0.0");
    let declared_only = release("declared", "1.0.0");
    let effective = ResolvedDependencyEdge {
        kind: EffectiveDependencyKind::Depends,
        package: PackageRequirement::new(
            package("selected"),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )
        .unwrap(),
    };
    let resolution = Resolution::new(
        target(),
        vec![
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(package("root")),
                root,
                vec![effective],
                vec![
                    rsolve_core::RepositoryId::new("secondary").unwrap(),
                    rsolve_core::RepositoryId::new("primary").unwrap(),
                ],
            ),
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(package("selected")),
                selected_dependency,
                Vec::new(),
                Vec::new(),
            ),
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(package("declared")),
                declared_only,
                Vec::new(),
                Vec::new(),
            ),
        ],
    );
    let lock = Lockfile::from_resolution(&resolution, environment()).unwrap();
    let root_lock = lock
        .single_resolution()
        .unwrap()
        .packages
        .iter()
        .find(|package| package.identity.name().as_str() == "root")
        .unwrap();
    assert_eq!(root_lock.dependencies, vec![edge("selected")]);
    assert_eq!(
        root_lock.visible_repository_ids,
        vec![
            rsolve_core::RepositoryId::new("secondary").unwrap(),
            rsolve_core::RepositoryId::new("primary").unwrap(),
        ]
    );

    let promoted = Resolution::new(
        target(),
        vec![
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(package("root")),
                release("root", "1.0.0"),
                vec![
                    ResolvedDependencyEdge {
                        kind: EffectiveDependencyKind::Depends,
                        package: PackageRequirement::new(
                            package("selected"),
                            DependencySourceConstraint::Any,
                            VersionConstraint::unconstrained(),
                        )
                        .unwrap(),
                    },
                    ResolvedDependencyEdge {
                        kind: EffectiveDependencyKind::PromotedSuggests,
                        package: PackageRequirement::new(
                            package("selected"),
                            DependencySourceConstraint::Any,
                            VersionConstraint::unconstrained(),
                        )
                        .unwrap(),
                    },
                ],
                Vec::new(),
            ),
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(package("selected")),
                release("selected", "1.0.0"),
                Vec::new(),
                Vec::new(),
            ),
        ],
    );
    let promoted_lock = Lockfile::from_resolution(&promoted, environment()).unwrap();
    assert_eq!(
        promoted_lock.single_resolution().unwrap().packages[0].dependencies,
        vec![
            LockedDependencyEdge {
                kind: EffectiveDependencyKind::Depends,
                package: package("selected"),
            },
            LockedDependencyEdge {
                kind: EffectiveDependencyKind::PromotedSuggests,
                package: package("selected"),
            },
        ]
    );
}

#[test]
fn downstream_projection_revalidates_mutated_public_lock_state() {
    let name = package("mutable");
    let resolution = Resolution::new(
        target(),
        vec![rsolve_core::ResolvedPackage::new(
            SolverKey::InstalledName(name.clone()),
            release("mutable", "1.0.0"),
            Vec::new(),
            Vec::new(),
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
                crate::manifest::ManifestTarget::new(version("4.4.0")),
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
fn publication_cutoff_is_reconstructed_from_lock() {
    let cutoff = rsolve_core::PublicationDate::parse("2026-06-24").unwrap();
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: Some(cutoff),
        packages: Vec::new(),
    }])
    .unwrap();
    let request = lock
        .resolution_request(
            Manifest::new(
                VersionConstraint::unconstrained(),
                crate::manifest::ManifestTarget::new(version("4.4.0")),
                Vec::new(),
            )
            .unwrap(),
            &environment(),
        )
        .unwrap();
    assert_eq!(
        request.publication_cutoff.map(|cutoff| cutoff.date()),
        Some(rsolve_core::PublicationCutoff::new(cutoff).date())
    );
}

#[test]
fn consume_locked_graph_preserves_locked_records_without_a_loader() {
    let root = release("root", "1.0.0");
    let dependency = release("dependency", "2.0.0");
    let mut root_package = LockedPackage::from_release(&root);
    root_package.dependencies = vec![edge("dependency")];
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![root_package, LockedPackage::from_release(&dependency)],
    }])
    .unwrap();
    let before = lock.clone();

    let graph = lock
        .consume_locked_graph(
            manifest_for("root", VersionConstraint::unconstrained()),
            &environment(),
        )
        .unwrap();

    assert_eq!(lock, before);
    assert_eq!(graph.target(), &target());
    assert_eq!(graph.environment(), &environment());
    assert_eq!(graph.packages(), lock.single_resolution().unwrap().packages);
    let root_package = graph
        .packages()
        .iter()
        .find(|locked| locked.identity.name() == &package("root"))
        .unwrap();
    assert_eq!(root_package.dependencies, vec![edge("dependency")]);
}

#[test]
fn consume_locked_graph_rejects_root_and_r_constraint_mismatches() {
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![LockedPackage::from_release(&release("root", "1.0.0"))],
    }])
    .unwrap();
    assert!(matches!(
        lock.consume_locked_graph(
            manifest_for("missing", VersionConstraint::unconstrained()),
            &environment(),
        ),
        Err(LockError::DirectRootMissing { name }) if name == "missing"
    ));
    assert!(matches!(
        lock.consume_locked_graph(
            manifest_for("root", VersionConstraint::from_clause(RelationOp::Ge, version("2.0"))),
            &environment(),
        ),
        Err(LockError::DirectRootVersionMismatch { name }) if name == "root"
    ));
    let r_mismatch = Manifest::new(
        VersionConstraint::from_clause(RelationOp::Ge, version("5.0")),
        crate::manifest::ManifestTarget::new(target().r_version),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        lock.consume_locked_graph(r_mismatch, &environment()),
        Err(LockError::RRequirementMismatch)
    );
    let other_environment = EnvironmentId::new("other").unwrap();
    assert!(matches!(
        lock.consume_locked_graph(
            manifest_for("root", VersionConstraint::unconstrained()),
            &other_environment,
        ),
        Err(LockError::EnvironmentMismatch { .. })
    ));
    let target_mismatch = Manifest::new(
        VersionConstraint::from_clause(RelationOp::Ge, version("4.0")),
        crate::manifest::ManifestTarget::new(version("4.5.0")),
        vec![crate::manifest::ManifestDependency::new(
            package("root"),
            VersionConstraint::unconstrained(),
        )],
    )
    .unwrap();
    assert_eq!(
        lock.consume_locked_graph(target_mismatch, &environment()),
        Err(LockError::TargetMismatch)
    );
}

#[test]
fn consume_locked_graph_checks_base_root_against_target_r_version() {
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: Vec::new(),
    }])
    .unwrap();
    let exact_target = manifest_for(
        "methods",
        VersionConstraint::from_clause(RelationOp::Eq, version("4.4.0")),
    );
    assert!(
        lock.consume_locked_graph(exact_target, &environment())
            .is_ok()
    );
    let wrong_target = manifest_for(
        "methods",
        VersionConstraint::from_clause(RelationOp::Eq, version("4.3.0")),
    );
    assert!(matches!(
        lock.consume_locked_graph(wrong_target, &environment()),
        Err(LockError::DirectRootVersionMismatch { name }) if name == "methods"
    ));
}

#[test]
fn consume_locked_graph_rejects_unreachable_locked_packages() {
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![
            LockedPackage::from_release(&release("root", "1.0.0")),
            LockedPackage::from_release(&release("extra", "1.0.0")),
        ],
    }])
    .unwrap();
    assert!(matches!(
        lock.consume_locked_graph(
            manifest_for("root", VersionConstraint::unconstrained()),
            &environment(),
        ),
        Err(LockError::UnreachablePackage { package }) if package == "extra"
    ));
}

#[test]
fn conflicting_repeated_identity_is_rejected_before_lock_state() {
    let identity_release = release("same", "1.0.0");
    let identity = identity_release.identity().clone();
    let first = LockedPackage::from_release(&identity_release);
    let mut second = first.clone();
    second.metadata_sha256 = Sha256Digest::new("f".repeat(64)).unwrap();
    assert!(
        Lockfile::new(vec![LockedResolution {
            target: target(),
            environment: environment(),
            publication_cutoff: None,
            packages: vec![first, second],
        }])
        .is_err()
    );
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
        publication: None,
        declared_dependencies: Vec::new(),
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
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap();
    let resolution = Resolution::new(
        target(),
        vec![
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(name.clone()),
                first.clone(),
                Vec::new(),
                Vec::new(),
            ),
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(name),
                second.clone(),
                Vec::new(),
                Vec::new(),
            ),
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
        dependencies: Vec::new(),
        visible_repository_ids: Vec::new(),
        metadata_sha256: digest(),
    };
    let second_lock = LockedPackage {
        identity: second.identity().clone(),
        version: second.version().clone(),
        published_version_spelling: None,
        dependencies: Vec::new(),
        visible_repository_ids: Vec::new(),
        metadata_sha256: digest(),
    };
    assert!(matches!(
        Lockfile::new(vec![LockedResolution {
            target: target(),
            environment: environment(),
            publication_cutoff: None,
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
            release: rsolve_core::BioconductorRelease::new("3.20").unwrap(),
            version: version("2.0.0"),
        },
    );
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![
            LockedPackage {
                identity: registry.clone(),
                version: version("1.0.0"),
                published_version_spelling: None,
                dependencies: Vec::new(),
                visible_repository_ids: Vec::new(),
                metadata_sha256: digest(),
            },
            LockedPackage {
                identity: bioconductor.clone(),
                version: version("2.0.0"),
                published_version_spelling: None,
                dependencies: Vec::new(),
                visible_repository_ids: Vec::new(),
                metadata_sha256: digest(),
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
            release: rsolve_core::BioconductorRelease::new("3.20").unwrap(),
            name: bioconductor.name().clone(),
        }),
        Some(&bioconductor)
    );
    assert_eq!(
        identities.get(&SolverKey::Exact(bioconductor.clone())),
        Some(&bioconductor)
    );
}

#[test]
fn visible_repository_ids_restore_repository_solver_keys_in_order() {
    let repository = rsolve_core::RepositoryId::new("mirror").unwrap();
    let locked = LockedPackage {
        identity: ReleaseIdentity::new(
            package("scoped"),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.0.0"),
            },
        ),
        version: version("1.0.0"),
        published_version_spelling: None,
        dependencies: Vec::new(),
        visible_repository_ids: vec![repository.clone()],
        metadata_sha256: digest(),
    };
    let lock = Lockfile::new(vec![LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff: None,
        packages: vec![locked],
    }])
    .unwrap();
    let identities = lock.locked_identities().unwrap();
    assert_eq!(
        identities.get(&SolverKey::Repository {
            repository,
            name: package("scoped"),
        }),
        Some(&ReleaseIdentity::new(
            package("scoped"),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.0.0"),
            },
        ))
    );
}
