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
    Sha256Digest::new("1".repeat(64)).unwrap()
}

fn locked_resolution(
    packages: Vec<LockedPackage>,
    publication_cutoff: Option<PublicationDate>,
) -> LockedResolution {
    LockedResolution {
        target: target(),
        environment: environment(),
        publication_cutoff,
        packages,
    }
}

fn lockfile(
    packages: Vec<LockedPackage>,
    publication_cutoff: Option<PublicationDate>,
) -> Result<Lockfile, LockError> {
    Lockfile::new(
        digest(),
        VersionConstraint::unconstrained(),
        locked_resolution(packages, publication_cutoff),
    )
}

fn lockfile_for_composed(
    packages: Vec<LockedPackage>,
    composed: &crate::manifest::ComposedEnvironment,
) -> Result<Lockfile, LockError> {
    Lockfile::new(
        composed.resolution_intent_digest().unwrap(),
        composed.r_requirement.clone(),
        LockedResolution {
            target: composed.target.clone(),
            environment: composed.environment.clone(),
            publication_cutoff: composed.published_before,
            packages,
        },
    )
}

fn lockfile_for_manifest(
    packages: Vec<LockedPackage>,
    manifest: &Manifest,
    publication_cutoff: Option<PublicationDate>,
) -> Result<Lockfile, LockError> {
    Lockfile::new(
        digest(),
        manifest.r_requirement.clone(),
        LockedResolution {
            target: target(),
            environment: environment(),
            publication_cutoff,
            packages,
        },
    )
}

fn resolution_for_packages(
    packages: Vec<(PackageRelease, Vec<rsolve_core::RepositoryId>)>,
) -> Resolution {
    Resolution::new(
        target(),
        packages
            .into_iter()
            .map(|(release, visible_repository_ids)| {
                ResolvedPackage::new(
                    SolverKey::InstalledName(release.identity().name().clone()),
                    release,
                    Vec::new(),
                    visible_repository_ids,
                )
            })
            .collect(),
    )
}

fn project(resolution: &Resolution) -> Result<Lockfile, LockError> {
    Lockfile::from_resolution_with_applicability(
        resolution,
        environment(),
        None,
        digest(),
        VersionConstraint::unconstrained(),
    )
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
fn direct_git_projection_retains_requested_intent_and_rejects_tampering() {
    let url = rsolve_core::NormalizedGitUrl::new("https://example.test/repo").unwrap();
    let commit = rsolve_core::GitCommitId::new("0123456789012345678901234567890123456789").unwrap();
    let name = package("gitpkg");
    let source = crate::manifest::ManifestSource::Git {
        url: url.clone(),
        selector: crate::manifest::GitSelector::Branch("main".into()),
        subdirectory: Some("pkg".into()),
    };
    let composed = composed_environment(Vec::new(), vec![composed_root("gitpkg", source)]);
    let version = version("1.2.0");
    let identity = ReleaseIdentity::new(
        name.clone(),
        Provenance::GitCommit {
            repository: url,
            commit,
            subdirectory: Some(rsolve_core::RepositorySubdir::new("pkg").unwrap()),
        },
    );
    let release = PackageRelease::try_from(ReleaseObservation {
        identity,
        observed_package: name,
        observed_version: version,
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap();
    let resolution = resolution_for_packages(vec![(release, Vec::new())]);
    let lock = Lockfile::from_resolution_with_composed_environment(&resolution, &composed).unwrap();
    let requested = lock.resolution.packages[0]
        .requested_git_source
        .as_ref()
        .unwrap();
    assert!(
        matches!(requested.selector, LockedGitSelector::Branch(ref value) if value.as_ref() == "main")
    );
    assert_eq!(requested.subdirectory.as_ref().unwrap().as_str(), "pkg");
    assert!(lock.resolution.packages[0].requested_git_source.is_some());
    let generic_lock = Lockfile::from_resolution_with_applicability(
        &resolution,
        environment(),
        None,
        digest(),
        VersionConstraint::unconstrained(),
    )
    .unwrap();
    assert!(
        generic_lock.resolution.packages[0]
            .requested_git_source
            .is_none()
    );

    let mut tampered = lock.clone();
    tampered.resolution.packages[0]
        .requested_git_source
        .as_mut()
        .unwrap()
        .selector = LockedGitSelector::Tag("release".into());
    assert!(matches!(
        tampered.consume_composed_environment(&composed),
        Err(LockError::ResolutionIntentMismatch { .. })
    ));
}

#[test]
fn direct_resolution_container_round_trips_empty_packages() {
    let lock = lockfile(Vec::new(), None).unwrap();
    assert_eq!(lock.resolution.packages, Vec::<LockedPackage>::new());
}

#[test]
fn constructor_rejects_r_requirement_incompatible_with_target() {
    let error = Lockfile::new(
        digest(),
        VersionConstraint::from_clause(RelationOp::Ge, version("5.0")),
        locked_resolution(Vec::new(), None),
    )
    .unwrap_err();
    assert_eq!(error, LockError::RRequirementMismatch);
}

#[test]
fn composed_consumption_accepts_configured_visible_repository() {
    let repository = rsolve_core::RepositoryId::new("main").unwrap();
    let mut locked = LockedPackage::from_release(&release("root", "1.0.0"));
    locked.visible_repository_ids = vec![repository.clone()];
    let composed = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(repository),
            },
        )],
    );
    let lock = lockfile_for_composed(vec![locked.clone()], &composed).unwrap();
    assert!(lock.consume_composed_environment(&composed).is_ok());
}

#[test]
fn composed_consumption_rejects_locked_visibility_outside_allowlist() {
    let repository = rsolve_core::RepositoryId::new("main").unwrap();
    let spec = crate::manifest::RepositorySpec::new_with_packages(
        repository.clone(),
        crate::manifest::RegistrySpec::Cran,
        crate::manifest::Endpoint::new("https://example.org/cran").unwrap(),
        Some(vec![package("other")]),
    )
    .unwrap();
    let mut locked = LockedPackage::from_release(&release("root", "1.0.0"));
    locked.visible_repository_ids = vec![repository.clone()];
    let composed = composed_environment(
        vec![spec],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(repository),
            },
        )],
    );
    let lock = lockfile_for_composed(vec![locked], &composed).unwrap();
    assert!(matches!(
        lock.consume_composed_environment(&composed),
        Err(LockError::VisibleRepositoryPackageNotAllowed { .. })
    ));
}

#[test]
fn composed_projection_validates_applicability_before_returning() {
    let repository = rsolve_core::RepositoryId::new("main").unwrap();
    let mut valid_root = composed_root(
        "root",
        crate::manifest::ManifestSource::Registry {
            repository: Some(repository.clone()),
        },
    );
    let composed =
        composed_environment(vec![composed_repository("main")], vec![valid_root.clone()]);
    let valid_resolution =
        resolution_for_packages(vec![(release("root", "1.0.0"), vec![repository.clone()])]);
    assert!(
        Lockfile::from_resolution_with_composed_environment(&valid_resolution, &composed).is_ok()
    );

    let missing = resolution_for_packages(Vec::new());
    assert!(matches!(
        Lockfile::from_resolution_with_composed_environment(&missing, &composed),
        Err(LockError::DirectRootMissing { name }) if name == "root"
    ));

    valid_root.constraint = VersionConstraint::from_clause(RelationOp::Ge, version("2.0"));
    let constrained = composed_environment(vec![composed_repository("main")], vec![valid_root]);
    assert!(matches!(
        Lockfile::from_resolution_with_composed_environment(&valid_resolution, &constrained),
        Err(LockError::DirectRootVersionMismatch { name }) if name == "root"
    ));

    let unreachable = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(repository.clone()),
            },
        )],
    );
    let unreachable_resolution = resolution_for_packages(vec![
        (release("root", "1.0.0"), vec![repository.clone()]),
        (release("extra", "1.0.0"), Vec::new()),
    ]);
    assert!(matches!(
        Lockfile::from_resolution_with_composed_environment(
            &unreachable_resolution,
            &unreachable
        ),
        Err(LockError::UnreachablePackage { package }) if package == "extra"
    ));

    let allowlist = crate::manifest::RepositorySpec::new_with_packages(
        repository.clone(),
        crate::manifest::RegistrySpec::Cran,
        crate::manifest::Endpoint::new("https://example.org/cran").unwrap(),
        Some(vec![package("other")]),
    )
    .unwrap();
    let allowlist_composed = composed_environment(
        vec![allowlist],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry { repository: None },
        )],
    );
    let allowlist_resolution =
        resolution_for_packages(vec![(release("root", "1.0.0"), vec![repository])]);
    assert!(matches!(
        Lockfile::from_resolution_with_composed_environment(
            &allowlist_resolution,
            &allowlist_composed
        ),
        Err(LockError::VisibleRepositoryPackageNotAllowed { package, .. })
            if package == "root"
    ));
}

#[test]
fn composed_consumption_accepts_allowlisted_locked_visibility_without_catalog_lookup() {
    let repository = rsolve_core::RepositoryId::new("main").unwrap();
    let package_name = package("root");
    let spec = crate::manifest::RepositorySpec::new_with_packages(
        repository.clone(),
        crate::manifest::RegistrySpec::Cran,
        crate::manifest::Endpoint::new("https://example.org/cran").unwrap(),
        Some(vec![package_name.clone()]),
    )
    .unwrap();
    let mut locked = LockedPackage::from_release(&release("root", "1.0.0"));
    locked.visible_repository_ids = vec![repository.clone()];
    let composed = composed_environment(
        vec![spec],
        vec![composed_root(
            package_name.as_str(),
            crate::manifest::ManifestSource::Registry {
                repository: Some(repository),
            },
        )],
    );
    let lock = lockfile_for_composed(vec![locked], &composed).unwrap();
    assert!(lock.consume_composed_environment(&composed).is_ok());
}

#[test]
fn composed_consumption_rejects_unknown_visible_repository_and_root_mismatch() {
    let unknown = rsolve_core::RepositoryId::new("unknown").unwrap();
    let mut locked = LockedPackage::from_release(&release("root", "1.0.0"));
    locked.visible_repository_ids = vec![unknown.clone()];
    let composed = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(rsolve_core::RepositoryId::new("main").unwrap()),
            },
        )],
    );
    let lock = lockfile_for_composed(vec![locked.clone()], &composed).unwrap();
    assert!(matches!(
        lock.consume_composed_environment(&composed),
        Err(LockError::UnknownVisibleRepository { repository, .. }) if repository == "unknown"
    ));

    locked.visible_repository_ids = vec![rsolve_core::RepositoryId::new("other").unwrap()];
    let mismatch = composed_environment(
        vec![composed_repository("main"), composed_repository("other")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(rsolve_core::RepositoryId::new("main").unwrap()),
            },
        )],
    );
    let mismatch_lock = lockfile_for_composed(vec![locked], &mismatch).unwrap();
    assert!(matches!(
        mismatch_lock.consume_composed_environment(&mismatch),
        Err(LockError::RootRepositoryNotVisible { repository, .. }) if repository == "main"
    ));
}

#[test]
fn composed_consumption_requires_registry_visibility_but_direct_roots_do_not() {
    let locked = LockedPackage::from_release(&release("root", "1.0.0"));
    let neutral = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry { repository: None },
        )],
    );
    let lock = lockfile_for_composed(vec![locked.clone()], &neutral).unwrap();
    assert!(matches!(
        lock.consume_composed_environment(&neutral),
        Err(LockError::NoVisibleRepository { package }) if package == "root"
    ));
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
    let direct_lock = lockfile_for_composed(vec![locked], &direct).unwrap();
    assert!(direct_lock.consume_composed_environment(&direct).is_ok());
}

#[test]
fn composed_consumption_rejects_empty_visibility_when_allowlist_excludes_registry_root() {
    let repository = rsolve_core::RepositoryId::new("main").unwrap();
    let spec = crate::manifest::RepositorySpec::new_with_packages(
        repository,
        crate::manifest::RegistrySpec::Cran,
        crate::manifest::Endpoint::new("https://example.org/cran").unwrap(),
        Some(vec![package("other")]),
    )
    .unwrap();
    let composed = composed_environment(
        vec![spec],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry { repository: None },
        )],
    );
    let lock = lockfile_for_composed(
        vec![LockedPackage::from_release(&release("root", "1.0.0"))],
        &composed,
    )
    .unwrap();
    assert!(matches!(
        lock.consume_composed_environment(&composed),
        Err(LockError::NoVisibleRepository { package }) if package == "root"
    ));
}

#[test]
fn composed_consumption_requires_visibility_for_direct_source_dependencies() {
    let mut root = LockedPackage::from_release(&release("root", "1.0.0"));
    root.dependencies = vec![edge("dependency")];
    let dependency = LockedPackage::from_release(&release("dependency", "1.0.0"));
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
    let direct_lock = lockfile_for_composed(vec![root, dependency], &direct).unwrap();
    assert!(matches!(
        direct_lock.consume_composed_environment(&direct),
        Err(LockError::NoVisibleRepository { package }) if package == "dependency"
    ));
}

#[test]
fn composed_consumption_applies_r_base_overlay_only_to_unqualified_roots() {
    let unqualified = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "stats",
            crate::manifest::ManifestSource::Registry { repository: None },
        )],
    );
    let empty_lock = lockfile_for_composed(Vec::new(), &unqualified).unwrap();
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
    let qualified_lock = lockfile_for_composed(Vec::new(), &qualified).unwrap();
    assert!(matches!(
        qualified_lock.consume_composed_environment(&qualified),
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
    let direct_lock = lockfile_for_composed(Vec::new(), &direct).unwrap();
    assert!(matches!(
        direct_lock.consume_composed_environment(&direct),
        Err(LockError::DirectRootMissing { name }) if name == "stats"
    ));
}

#[test]
fn composed_consumption_requires_matching_publication_cutoff() {
    let cutoff = PublicationDate::parse("2026-08-01").unwrap();
    let other_cutoff = PublicationDate::parse("2026-08-02").unwrap();
    let mut composed = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry { repository: None },
        )],
    );
    composed.published_before = Some(cutoff);
    let main = rsolve_core::RepositoryId::new("main").unwrap();
    let mut locked_root = LockedPackage::from_release(&release("root", "1.0.0"));
    locked_root.visible_repository_ids = vec![main.clone()];
    let lock_with_cutoff = lockfile_for_composed(vec![locked_root], &composed).unwrap();
    composed.published_before = None;
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

    let no_cutoff_composed = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry { repository: None },
        )],
    );
    let lock_without_cutoff = lockfile_for_composed(
        vec![{
            let mut locked_root = LockedPackage::from_release(&release("root", "1.0.0"));
            locked_root.visible_repository_ids = vec![main];
            locked_root
        }],
        &no_cutoff_composed,
    )
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
    let composed = composed_environment(
        vec![composed_repository("main")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(rsolve_core::RepositoryId::new("main").unwrap()),
            },
        )],
    );
    let lock = lockfile_for_composed(vec![root, child], &composed).unwrap();
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
    let composed = composed_environment(
        vec![composed_repository("first"), composed_repository("second")],
        vec![composed_root(
            "root",
            crate::manifest::ManifestSource::Registry {
                repository: Some(first),
            },
        )],
    );
    let lock = lockfile_for_composed(vec![locked], &composed).unwrap();
    assert!(matches!(
        lock.consume_composed_environment(&composed),
        Err(LockError::VisibleRepositoryOrderMismatch { package }) if package == "root"
    ));
}

#[test]
fn composed_consumption_enforces_selected_intent_freshness() {
    let input = "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://main.example'\nregistry='cran'\n[dependencies]\nfoo='*'\n[groups.unselected.dependencies]\nbar='*'\n[environments]\nci=['unselected']\n";
    let target = ResolutionTarget::new(version("4.4.0"));
    let baseline_document = crate::manifest::parse_manifest(input).unwrap();
    let baseline = baseline_document
        .compose_environment("default", target.clone())
        .unwrap();
    let main = rsolve_core::RepositoryId::new("main").unwrap();
    let mut locked_foo = LockedPackage::from_release(&release("foo", "1.0.0"));
    locked_foo.visible_repository_ids = vec![main];
    let lock = lockfile_for_composed(vec![locked_foo], &baseline).unwrap();
    assert!(lock.consume_composed_environment(&baseline).is_ok());

    let unselected = crate::manifest::parse_manifest(&input.replace("bar='*'", "bar='< 9.0'"))
        .unwrap()
        .compose_environment("default", target.clone())
        .unwrap();
    assert_eq!(
        baseline.resolution_intent_digest().unwrap(),
        unselected.resolution_intent_digest().unwrap()
    );
    assert!(lock.consume_composed_environment(&unselected).is_ok());

    let changed_inputs = [
        input.replace("foo='*'", "foo='>= 2.0'"),
        input.replace("url='https://main.example'", "url='https://other.example'"),
        input.replace("foo='*'", "foo={repository='main'}"),
        input.replace("foo='*'", "foo={version='*',include-suggests=true}"),
        input.replace(
            "[environments]\nci=['unselected']",
            "[groups.selected.dependencies]\nbar='*'\n[environments]\ndefault=['selected']\nci=['unselected']",
        ),
    ];
    for changed in changed_inputs {
        let composed = crate::manifest::parse_manifest(&changed)
            .unwrap()
            .compose_environment("default", target.clone())
            .unwrap();
        assert!(matches!(
            lock.consume_composed_environment(&composed),
            Err(LockError::ResolutionIntentMismatch { .. })
        ));
    }
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
        requested_git_source: None,
    };
    assert!(matches!(
        lockfile(vec![package], None),
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
        requested_git_source: None,
    };
    let mut reversed = make(alpha.clone());
    reversed.dependencies.reverse();
    let ordered = make(alpha.clone());
    let first = lockfile(vec![ordered, make(beta.clone())], None).unwrap();
    let second = lockfile(vec![make(beta.clone()), reversed], None).unwrap();
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
    let lock = project(&resolution).unwrap();
    let packages = &lock.resolution.packages;
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
    let lock = project(&resolution).unwrap();
    let root_lock = lock
        .resolution
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
    let promoted_lock = project(&promoted).unwrap();
    assert_eq!(
        promoted_lock.resolution.packages[0].dependencies,
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
    let mut lock = project(&resolution).unwrap();
    lock.resolution.packages[0].version = version("2.0.0");
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
    let lock = lockfile(Vec::new(), Some(cutoff)).unwrap();
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
    let manifest = manifest_for("root", VersionConstraint::unconstrained());
    let lock = lockfile_for_manifest(
        vec![root_package, LockedPackage::from_release(&dependency)],
        &manifest,
        None,
    )
    .unwrap();
    let before = lock.clone();

    let graph = lock.consume_locked_graph(manifest, &environment()).unwrap();

    assert_eq!(lock, before);
    assert_eq!(graph.target(), &target());
    assert_eq!(graph.environment(), &environment());
    assert_eq!(graph.packages(), lock.resolution.packages);
    let root_package = graph
        .packages()
        .iter()
        .find(|locked| locked.identity.name() == &package("root"))
        .unwrap();
    assert_eq!(root_package.dependencies, vec![edge("dependency")]);
}

#[test]
fn consume_locked_graph_rejects_root_and_r_constraint_mismatches() {
    let base_manifest = manifest_for("root", VersionConstraint::unconstrained());
    let lock = lockfile_for_manifest(
        vec![LockedPackage::from_release(&release("root", "1.0.0"))],
        &base_manifest,
        None,
    )
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
    let exact_target = manifest_for(
        "methods",
        VersionConstraint::from_clause(RelationOp::Eq, version("4.4.0")),
    );
    let lock = lockfile_for_manifest(Vec::new(), &exact_target, None).unwrap();
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
    let manifest = manifest_for("root", VersionConstraint::unconstrained());
    let lock = lockfile_for_manifest(
        vec![
            LockedPackage::from_release(&release("root", "1.0.0")),
            LockedPackage::from_release(&release("extra", "1.0.0")),
        ],
        &manifest,
        None,
    )
    .unwrap();
    assert!(matches!(
        lock.consume_locked_graph(
            manifest,
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
    assert!(lockfile(vec![first, second], None).is_err());
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
        project(&resolution),
        Err(LockError::InstalledNameConflict { .. })
    ));
    let first_lock = LockedPackage {
        identity: first.identity().clone(),
        version: first.version().clone(),
        published_version_spelling: None,
        dependencies: Vec::new(),
        visible_repository_ids: Vec::new(),
        metadata_sha256: digest(),
        requested_git_source: None,
    };
    let second_lock = LockedPackage {
        identity: second.identity().clone(),
        version: second.version().clone(),
        published_version_spelling: None,
        dependencies: Vec::new(),
        visible_repository_ids: Vec::new(),
        metadata_sha256: digest(),
        requested_git_source: None,
    };
    assert!(matches!(
        lockfile(vec![first_lock, second_lock], None),
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
    let lock = lockfile(
        vec![
            LockedPackage {
                identity: registry.clone(),
                version: version("1.0.0"),
                published_version_spelling: None,
                dependencies: Vec::new(),
                visible_repository_ids: Vec::new(),
                metadata_sha256: digest(),
                requested_git_source: None,
            },
            LockedPackage {
                identity: bioconductor.clone(),
                version: version("2.0.0"),
                published_version_spelling: None,
                dependencies: Vec::new(),
                visible_repository_ids: Vec::new(),
                metadata_sha256: digest(),
                requested_git_source: None,
            },
        ],
        None,
    )
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
        requested_git_source: None,
    };
    let lock = lockfile(vec![locked], None).unwrap();
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
