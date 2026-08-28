use super::*;
use crate::{LockedPackage, LockedResolution};
use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoadResult, CandidateLoader,
    DeclaredDependency, DependencyKind, DependencySourceConstraint, GitCommitId, NormalizedGitUrl,
    PackageName, PackageNamespace, PackageRelease, Provenance, RPackageVersion, ReleaseIdentity,
    ReleaseMetadata, ReleaseObservation, ResolutionTarget, Sha256Digest, SolverKey, SourceScheme,
    VersionConstraint,
};
use rsolve_provider::cran::CranCandidateSnapshot;
use rsolve_resolver::R_BASE_PACKAGE_NAMES;
use std::collections::BTreeMap;

/// A compact CRAN-shaped fixture for the historical R 3.6 tidyverse closure.
///
/// The real archive contains malformed XML releases (0.2 and 0.3-3) next to
/// usable releases. Keeping those versions in the fixture's quarantine side
/// makes this test exercise the same resolver boundary as a provider snapshot,
/// without making the test depend on a live CRAN mirror.
#[derive(Clone, Default)]
struct TidyverseFixtureLoader {
    candidates: BTreeMap<PackageName, Vec<PackageRelease>>,
    quarantined: BTreeMap<PackageName, Vec<RPackageVersion>>,
}

impl CandidateLoader for TidyverseFixtureLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let result = self.load(package)?;
        if result.candidates().is_empty() && !result.quarantined().is_empty() {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                format!("tidyverse fixture has no eligible releases for {package:?}"),
            ));
        }
        Ok(result.into_parts().0)
    }

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("tidyverse fixture has no candidates for {package:?}"),
            ));
        };
        let candidates = self.candidates.get(name).cloned().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("tidyverse fixture has not refreshed package {name}"),
            )
        })?;
        let quarantined = self
            .quarantined
            .get(name)
            .into_iter()
            .flatten()
            .cloned()
            .map(|version| {
                rsolve_core::QuarantinedCandidate::new(version, "invalid CRAN archive release")
            })
            .collect();
        Ok(CandidateLoadResult::new(candidates, quarantined))
    }
}

fn tidyverse_fixture(
    xml_candidates: &[&str],
    xml_constraint: VersionConstraint,
) -> TidyverseFixtureLoader {
    let tidyverse = PackageName::new("tidyverse").unwrap();
    let rvest = PackageName::new("rvest").unwrap();
    let xml = PackageName::new("XML").unwrap();
    let r = PackageName::new("R").unwrap();
    let mut candidates = BTreeMap::new();
    candidates.insert(
        tidyverse.clone(),
        vec![release_at_version_with_dependencies(
            &tidyverse,
            "1.3.2",
            vec![
                dependency(DependencyKind::Depends, &r, ge_version("3.6.0")),
                dependency(
                    DependencyKind::Imports,
                    &rvest,
                    VersionConstraint::unconstrained(),
                ),
            ],
        )],
    );
    candidates.insert(
        rvest.clone(),
        vec![release_at_version_with_dependencies(
            &rvest,
            "0.3.6",
            vec![dependency(DependencyKind::Imports, &xml, xml_constraint)],
        )],
    );
    candidates.insert(
        xml.clone(),
        xml_candidates
            .iter()
            .map(|version| release_at_version_with_dependencies(&xml, version, Vec::new()))
            .collect(),
    );

    TidyverseFixtureLoader {
        candidates,
        quarantined: BTreeMap::from([(
            xml,
            ["0.2", "0.3-3"]
                .into_iter()
                .map(|version| RPackageVersion::parse(version).unwrap())
                .collect(),
        )]),
    }
}

fn dependency(
    kind: DependencyKind,
    name: &PackageName,
    constraint: VersionConstraint,
) -> DeclaredDependency {
    DeclaredDependency::from_parts(
        kind,
        name.clone(),
        DependencySourceConstraint::Any,
        constraint,
    )
    .unwrap()
}

fn ge_version(version: &str) -> VersionConstraint {
    VersionConstraint::from_clause(
        rsolve_core::RelationOp::Ge,
        RPackageVersion::parse(version).unwrap(),
    )
}

fn release_at_version_with_dependencies(
    name: &PackageName,
    version: &str,
    dependencies: Vec<DeclaredDependency>,
) -> PackageRelease {
    let version = RPackageVersion::parse(version).unwrap();
    PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            name.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        ),
        observed_package: name.clone(),
        observed_version: version,
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        publication: None,
        declared_dependencies: dependencies,
        distributions: Vec::new(),
    })
    .unwrap()
}

fn tidyverse_manifest() -> Manifest {
    let tidyverse = PackageName::new("tidyverse").unwrap();
    Manifest::new(
        ge_version("3.6.0"),
        crate::manifest::ManifestTarget::new(RPackageVersion::parse("3.6").unwrap()),
        vec![crate::manifest::ManifestDependency::new(
            tidyverse,
            VersionConstraint::unconstrained(),
        )],
    )
    .unwrap()
}

fn tidyverse_lock(loader: &TidyverseFixtureLoader) -> Lockfile {
    let resolution =
        resolve_with_loader(tidyverse_manifest(), loader).expect("tidyverse fixture must resolve");
    Lockfile::from_resolution(&resolution, EnvironmentId::new("default").unwrap())
        .expect("tidyverse resolution must project into a lock")
}

struct FixtureLoader {
    package: PackageRelease,
}

struct QuarantinedFixtureLoader {
    package: PackageRelease,
    quarantined_version: RPackageVersion,
}

struct ChoiceLoader {
    packages: Vec<PackageRelease>,
}

impl CandidateLoader for ChoiceLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        match package {
            SolverKey::InstalledName(name)
                if self
                    .packages
                    .iter()
                    .any(|release| release.identity().name() == name) =>
            {
                Ok(self
                    .packages
                    .iter()
                    .filter(|release| release.identity().name() == name)
                    .cloned()
                    .collect())
            }
            SolverKey::InstalledName(_) | SolverKey::R => Ok(Vec::new()),
            _ => Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                "choice fixture has no candidates for this solver key",
            )),
        }
    }
}

impl CandidateLoader for FixtureLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        match package {
            SolverKey::InstalledName(name) if name == self.package.identity().name() => {
                Ok(vec![self.package.clone()])
            }
            SolverKey::InstalledName(_) => Ok(Vec::new()),
            SolverKey::R => Ok(Vec::new()),
            _ => Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                "fixture has no candidates for this solver key",
            )),
        }
    }
}

impl CandidateLoader for QuarantinedFixtureLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        FixtureLoader {
            package: self.package.clone(),
        }
        .releases(package)
    }

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        Ok(CandidateLoadResult::new(
            self.releases(package)?,
            vec![rsolve_core::QuarantinedCandidate::new(
                self.quarantined_version.clone(),
                "fixture quarantine",
            )],
        ))
    }
}

fn fixture_loader() -> FixtureLoader {
    let package = PackageName::new("fixture").unwrap();
    let version = RPackageVersion::parse("1.0.0").unwrap();
    let identity = ReleaseIdentity::new(
        package.clone(),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version.clone(),
        },
    );
    let observation = ReleaseObservation {
        identity,
        observed_package: package,
        observed_version: version,
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    };
    FixtureLoader {
        package: PackageRelease::try_from(observation).unwrap(),
    }
}

fn release_with_dependencies(
    name: &PackageName,
    dependencies: Vec<DeclaredDependency>,
) -> PackageRelease {
    let version = RPackageVersion::parse("1.0.0").unwrap();
    let identity = ReleaseIdentity::new(
        name.clone(),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version.clone(),
        },
    );
    PackageRelease::try_from(ReleaseObservation {
        identity,
        observed_package: name.clone(),
        observed_version: version,
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        publication: None,
        declared_dependencies: dependencies,
        distributions: Vec::new(),
    })
    .unwrap()
}

fn release_at_version(name: &PackageName, value: &str) -> PackageRelease {
    let version = RPackageVersion::parse(value).unwrap();
    PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            name.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
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
    .unwrap()
}

fn release_with_identity(identity: ReleaseIdentity, version: RPackageVersion) -> PackageRelease {
    PackageRelease::try_from(ReleaseObservation {
        observed_package: identity.name().clone(),
        observed_version: version.clone(),
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        identity,
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap()
}

fn lock_for_identity(identity: ReleaseIdentity, version: RPackageVersion) -> Lockfile {
    Lockfile::new(vec![LockedResolution {
        target: ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        environment: EnvironmentId::new("default").unwrap(),
        publication_cutoff: None,
        packages: vec![LockedPackage {
            identity,
            version,
            published_version_spelling: None,
            dependencies: Vec::new(),
            metadata_sha256: Sha256Digest::new("0".repeat(64)).unwrap(),
        }],
    }])
    .unwrap()
}

fn manifest_for(name: PackageName) -> Manifest {
    Manifest::new(
        VersionConstraint::from_clause(
            rsolve_core::RelationOp::Ge,
            RPackageVersion::parse("4.0").unwrap(),
        ),
        crate::manifest::ManifestTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        vec![crate::manifest::ManifestDependency::new(
            name,
            VersionConstraint::unconstrained(),
        )],
    )
    .unwrap()
}

#[test]
fn cran_registry_ids_are_endpoint_scoped_and_canonical() {
    let first = cran_registry_id("https://cloud.r-project.org/cran");
    let same = cran_registry_id("https://cloud.r-project.org/cran");
    let different = cran_registry_id("https://mirror.example.test/cran");
    assert_eq!(first, same);
    assert_ne!(first, different);
    assert_eq!(
        first.as_str(),
        "cran-sha256:4d1af2a840d22f869630003ab8b6a4677859fb2dc2e67685eca7af1d2aeae7bf"
    );
    assert!(first.as_str().starts_with("cran-sha256:"));
    assert!(first.as_str().chars().all(|character| {
        character == ':'
            || character == '-'
            || character.is_ascii_digit()
            || character.is_ascii_lowercase()
    }));
}

#[test]
fn cran_dependency_closure_is_deterministic_and_excludes_optional_and_r_base() {
    let root = PackageName::new("root").unwrap();
    let first = PackageName::new("first").unwrap();
    let second = PackageName::new("second").unwrap();
    let transitive = PackageName::new("transitive").unwrap();
    let methods = PackageName::new("methods").unwrap();
    let r_base = PackageName::new("R").unwrap();
    let optional = PackageName::new("optional").unwrap();
    let required = |kind, name: &PackageName| {
        DeclaredDependency::from_parts(
            kind,
            name.clone(),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )
        .unwrap()
    };
    let root_candidates = vec![
        release_with_dependencies(
            &root,
            vec![
                required(DependencyKind::Imports, &first),
                required(DependencyKind::Depends, &methods),
                required(DependencyKind::Depends, &r_base),
                required(DependencyKind::Suggests, &optional),
            ],
        ),
        release_with_dependencies(
            &root,
            vec![
                required(DependencyKind::LinkingTo, &second),
                required(DependencyKind::Imports, &first),
            ],
        ),
    ];
    let mut calls = Vec::new();
    let closure = collect_cran_dependency_closure(std::slice::from_ref(&root), |batch| {
        calls.push(batch.to_vec());
        match calls.len() {
            1 => Ok(CranCandidateSnapshot::from_candidates([(
                root.clone(),
                root_candidates.clone(),
            )])),
            2 => Ok(CranCandidateSnapshot::from_candidates([
                (
                    first.clone(),
                    vec![release_with_dependencies(
                        &first,
                        vec![required(DependencyKind::Imports, &transitive)],
                    )],
                ),
                (
                    second.clone(),
                    vec![release_with_dependencies(&second, vec![])],
                ),
            ])),
            3 => Ok(CranCandidateSnapshot::from_candidates([(
                transitive.clone(),
                vec![release_with_dependencies(&transitive, vec![])],
            )])),
            _ => panic!("closure retried a package"),
        }
    })
    .unwrap();
    assert_eq!(
        closure,
        vec![first.clone(), root.clone(), second, transitive.clone()]
    );
    assert_eq!(
        calls,
        vec![
            vec![root],
            vec![first, PackageName::new("second").unwrap()],
            vec![transitive.clone()]
        ]
    );
    assert!(!closure.contains(&methods));
    assert!(!closure.contains(&r_base));
    assert!(!closure.contains(&optional));
}

#[test]
fn base_only_dependency_closure_skips_refresh_and_publication_inputs() {
    let methods = PackageName::new("methods").unwrap();
    let mut refresh_calls = 0;
    let closure = collect_cran_dependency_closure(std::slice::from_ref(&methods), |_| {
        refresh_calls += 1;
        Ok(CranCandidateSnapshot::default())
    })
    .unwrap();
    assert!(closure.is_empty());
    assert_eq!(refresh_calls, 0);
}

#[test]
fn lock_boundary_uses_prefer_fallback_and_require_exact_policy() {
    let name = PackageName::new("choice").unwrap();
    let old = release_at_version(&name, "1.0.0");
    let newer = release_at_version(&name, "2.0.0");
    let old_resolution = Resolution::new(
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        vec![rsolve_core::ResolvedPackage::new(
            SolverKey::InstalledName(name.clone()),
            old,
            Vec::new(),
        )],
    );
    let environment = EnvironmentId::new("default").unwrap();
    let lock = Lockfile::from_resolution(&old_resolution, environment.clone()).unwrap();
    let loader = ChoiceLoader {
        packages: vec![newer.clone()],
    };
    let normal = resolve_with_lock_policy(
        manifest_for(name.clone()),
        &lock,
        &environment,
        LockResolutionPolicy::Prefer,
        &loader,
    )
    .unwrap();
    assert_eq!(normal.selected(&name).unwrap().version(), newer.version());
    assert!(
        resolve_with_lock_policy(
            manifest_for(name),
            &lock,
            &environment,
            LockResolutionPolicy::RequireExact,
            &loader,
        )
        .is_err()
    );
}

#[test]
fn prefer_policy_updates_a_changed_root_without_consume_precondition() {
    let root = PackageName::new("root").unwrap();
    let dependency = PackageName::new("dependency").unwrap();
    let old_root = release_with_dependencies(
        &root,
        vec![
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                dependency.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )
            .unwrap(),
        ],
    );
    let old_dependency = release_with_dependencies(&dependency, Vec::new());
    let old_resolution = Resolution::new(
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        vec![
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(root.clone()),
                old_root,
                Vec::new(),
            ),
            rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(dependency),
                old_dependency,
                Vec::new(),
            ),
        ],
    );
    let environment = EnvironmentId::new("default").unwrap();
    let lock = Lockfile::from_resolution(&old_resolution, environment.clone()).unwrap();
    let changed_manifest = Manifest::new(
        VersionConstraint::from_clause(
            rsolve_core::RelationOp::Ge,
            RPackageVersion::parse("4.0").unwrap(),
        ),
        crate::manifest::ManifestTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        vec![crate::manifest::ManifestDependency::new(
            root.clone(),
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("2.0.0").unwrap(),
            ),
        )],
    )
    .unwrap();
    assert!(matches!(
        lock.consume_locked_graph(changed_manifest.clone(), &environment),
        Err(LockError::DirectRootVersionMismatch { .. })
    ));

    let newer_root = release_at_version(&root, "2.0.0");
    let resolution = resolve_with_lock_policy(
        changed_manifest,
        &lock,
        &environment,
        LockResolutionPolicy::Prefer,
        &ChoiceLoader {
            packages: vec![newer_root.clone()],
        },
    )
    .unwrap();
    assert_eq!(
        resolution.selected(&root).unwrap().version(),
        newer_root.version()
    );
}

#[test]
fn require_exact_rejects_new_transitive_identity_from_upstream_metadata() {
    let root = PackageName::new("root").unwrap();
    let extra = PackageName::new("extra").unwrap();
    let old_resolution = Resolution::new(
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        vec![rsolve_core::ResolvedPackage::new(
            SolverKey::InstalledName(root.clone()),
            release_at_version(&root, "1.0.0"),
            Vec::new(),
        )],
    );
    let environment = EnvironmentId::new("default").unwrap();
    let lock = Lockfile::from_resolution(&old_resolution, environment.clone()).unwrap();
    let refreshed_root = release_with_dependencies(
        &root,
        vec![
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                extra.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )
            .unwrap(),
        ],
    );
    let error = resolve_with_lock_policy(
        manifest_for(root),
        &lock,
        &environment,
        LockResolutionPolicy::RequireExact,
        &ChoiceLoader {
            packages: vec![
                refreshed_root,
                release_with_dependencies(&extra, Vec::new()),
            ],
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CranResolutionError::Lock(LockError::ExactIdentitySetMismatch { missing, extra })
            if missing.is_empty() && extra.len() == 1
    ));
}

#[test]
fn require_exact_identity_mismatch_diagnostics_are_order_independent() {
    let root = PackageName::new("root").unwrap();
    let first = PackageName::new("first").unwrap();
    let second = PackageName::new("second").unwrap();
    let lock = Lockfile::from_resolution(
        &Resolution::new(
            ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            vec![rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(root.clone()),
                release_at_version(&root, "1.0.0"),
                Vec::new(),
            )],
        ),
        EnvironmentId::new("default").unwrap(),
    )
    .unwrap();
    let environment = EnvironmentId::new("default").unwrap();
    let refreshed_root = release_with_dependencies(
        &root,
        vec![
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                first.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )
            .unwrap(),
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                second.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )
            .unwrap(),
        ],
    );
    let first_release = release_with_dependencies(&first, Vec::new());
    let second_release = release_with_dependencies(&second, Vec::new());
    let run = |packages| {
        let Err(CranResolutionError::Lock(LockError::ExactIdentitySetMismatch { missing, extra })) =
            resolve_with_lock_policy(
                manifest_for(root.clone()),
                &lock,
                &environment,
                LockResolutionPolicy::RequireExact,
                &ChoiceLoader { packages },
            )
        else {
            panic!("expected deterministic exact identity mismatch");
        };
        (missing, extra)
    };
    assert_eq!(
        run(vec![
            refreshed_root.clone(),
            first_release.clone(),
            second_release.clone(),
        ]),
        run(vec![refreshed_root, second_release, first_release])
    );
}

#[test]
fn require_exact_rejects_same_git_commit_with_changed_semantic_version() {
    let name = PackageName::new("gitpkg").unwrap();
    let identity = ReleaseIdentity::new(
        name.clone(),
        Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
            subdirectory: None,
        },
    );
    let lock = lock_for_identity(identity.clone(), RPackageVersion::parse("1.0").unwrap());
    let error = resolve_with_lock_policy(
        manifest_for(name),
        &lock,
        &EnvironmentId::new("default").unwrap(),
        LockResolutionPolicy::RequireExact,
        &FixtureLoader {
            package: release_with_identity(identity, RPackageVersion::parse("2.0").unwrap()),
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CranResolutionError::Lock(LockError::ExactIdentitySetMismatch { missing, extra })
            if missing.iter().any(|value| value.ends_with("@1"))
                && extra.iter().any(|value| value.ends_with("@2"))
    ));
}

#[test]
fn require_exact_rejects_same_immutable_source_with_changed_semantic_version() {
    let name = PackageName::new("immutablepkg").unwrap();
    let identity = ReleaseIdentity::new(
        name.clone(),
        Provenance::ImmutableSource {
            scheme: SourceScheme::new("sha256").unwrap(),
            digest: Sha256Digest::new("a".repeat(64)).unwrap(),
        },
    );
    let lock = lock_for_identity(identity.clone(), RPackageVersion::parse("1.0").unwrap());
    let error = resolve_with_lock_policy(
        manifest_for(name),
        &lock,
        &EnvironmentId::new("default").unwrap(),
        LockResolutionPolicy::RequireExact,
        &FixtureLoader {
            package: release_with_identity(identity, RPackageVersion::parse("2.0").unwrap()),
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CranResolutionError::Lock(LockError::ExactIdentitySetMismatch { missing, extra })
            if missing.iter().any(|value| value.ends_with("@1"))
                && extra.iter().any(|value| value.ends_with("@2"))
    ));
}

#[test]
fn require_exact_treats_trailing_zero_versions_as_semantically_equal() {
    let name = PackageName::new("registrypkg").unwrap();
    let identity = ReleaseIdentity::new(
        name.clone(),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: RPackageVersion::parse("4.4").unwrap(),
        },
    );
    let lock = lock_for_identity(identity.clone(), RPackageVersion::parse("4.4").unwrap());
    let resolution = resolve_with_lock_policy(
        manifest_for(name),
        &lock,
        &EnvironmentId::new("default").unwrap(),
        LockResolutionPolicy::RequireExact,
        &FixtureLoader {
            package: release_with_identity(identity, RPackageVersion::parse("4.4.0").unwrap()),
        },
    )
    .unwrap();
    assert_eq!(
        resolution.packages().first().unwrap().version().as_str(),
        "4.4.0"
    );
}

#[test]
fn source_qualified_not_found_is_propagated_without_refresh_retry() {
    let root = PackageName::new("fixture").unwrap();
    let dependency = PackageName::new("fixture.registry").unwrap();
    let root_release = release_with_dependencies(
        &root,
        vec![
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                dependency,
                DependencySourceConstraint::Registry {
                    namespace: PackageNamespace::new("cran").unwrap(),
                },
                VersionConstraint::unconstrained(),
            )
            .unwrap(),
        ],
    );
    let initial = CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release])]);
    let error = resolve_with_loader(manifest_for(root), &initial).unwrap_err();
    assert!(matches!(
        error,
        CranResolutionError::Resolution(ResolutionFailure::CandidateLoad {
            package: SolverKey::Registry { .. },
            ..
        })
    ));
}

#[test]
fn r_base_overlay_shadows_cran_base_names_but_not_matrix() {
    let target = RPackageVersion::parse("4.4.0").unwrap();
    let methods = PackageName::new("methods").unwrap();
    let matrix = PackageName::new("Matrix").unwrap();
    let cran = CranCandidateSnapshot::from_candidates([
        (
            methods.clone(),
            vec![release_with_dependencies(&methods, Vec::new())],
        ),
        (
            matrix.clone(),
            vec![release_with_dependencies(&matrix, Vec::new())],
        ),
    ]);
    let overlay = RBasePackageOverlay::new(CandidateLoaderRef(&cran), target.clone()).unwrap();
    assert_eq!(R_BASE_PACKAGE_NAMES.len(), 14);
    assert_eq!(
        R_BASE_PACKAGE_NAMES
            .iter()
            .map(|name| PackageName::new(name).unwrap())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        14
    );
    let base_release = overlay
        .releases(&SolverKey::InstalledName(methods.clone()))
        .unwrap();
    assert_eq!(base_release.len(), 1);
    assert!(base_release[0].is_r_base_package());
    assert_eq!(base_release[0].version(), &target);
    assert!(!cran.needs_refresh(&SolverKey::InstalledName(methods)));
    assert!(!overlay.releases(&SolverKey::InstalledName(matrix)).unwrap()[0].is_r_base_package());
    let empty = CranCandidateSnapshot::from_candidates([]);
    assert!(empty.needs_refresh(&SolverKey::InstalledName(
        PackageName::new("Matrix").unwrap()
    )));
}

#[test]
fn methods_dependency_uses_target_r_base_without_refresh_or_resolution_output() {
    let root = PackageName::new("fixture").unwrap();
    let methods = PackageName::new("methods").unwrap();
    let target = RPackageVersion::parse("4.4.0").unwrap();
    let root_release = release_with_dependencies(
        &root,
        vec![
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                methods.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::from_clause(rsolve_core::RelationOp::Eq, target.clone()),
            )
            .unwrap(),
        ],
    );
    let resolution = resolve_with_loader(
        manifest_for(root.clone()),
        &CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release])]),
    )
    .unwrap();
    assert!(resolution.selected(&root).is_some());
    assert!(resolution.selected(&methods).is_none());
}

#[test]
fn incompatible_methods_constraint_is_no_solution_without_refresh() {
    let root = PackageName::new("fixture").unwrap();
    let methods = PackageName::new("methods").unwrap();
    let root_release = release_with_dependencies(
        &root,
        vec![
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                methods,
                DependencySourceConstraint::Any,
                VersionConstraint::from_clause(
                    rsolve_core::RelationOp::Eq,
                    RPackageVersion::parse("4.3.0").unwrap(),
                ),
            )
            .unwrap(),
        ],
    );
    let error = resolve_with_loader(
        manifest_for(root.clone()),
        &CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release])]),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CranResolutionError::Resolution(ResolutionFailure::NoSolution { .. })
    ));
}

#[test]
fn injected_loader_exercises_manifest_to_resolution_orchestration() {
    let manifest = Manifest::new(
        VersionConstraint::from_clause(
            rsolve_core::RelationOp::Ge,
            RPackageVersion::parse("4.0").unwrap(),
        ),
        crate::manifest::ManifestTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        vec![crate::manifest::ManifestDependency::new(
            PackageName::new("fixture").unwrap(),
            VersionConstraint::unconstrained(),
        )],
    )
    .unwrap();
    let loader = fixture_loader();
    let resolution = resolve_with_loader(manifest, &loader).unwrap();
    assert_eq!(
        resolution
            .selected(&PackageName::new("fixture").unwrap())
            .unwrap()
            .version(),
        &RPackageVersion::parse("1.0.0").unwrap()
    );
}

#[test]
fn hermetic_tidyverse_r36_lock_reaches_xml_without_quarantined_releases() {
    let loader = tidyverse_fixture(&["3.99-0.19"], VersionConstraint::unconstrained());
    let lock = tidyverse_lock(&loader);
    let encoded = crate::to_toml(&lock).expect("tidyverse lock must encode");
    let decoded = crate::from_toml(&encoded).expect("tidyverse lock must decode");
    assert_eq!(decoded, lock);

    let packages = &lock.resolutions[0].packages;
    let xml = packages
        .iter()
        .find(|package| package.identity.name().as_str() == "XML")
        .expect("tidyverse dependency closure must reach XML");
    assert_eq!(xml.version, RPackageVersion::parse("3.99-0.19").unwrap());
    assert!(packages.iter().all(|package| {
        package.identity.name().as_str() != "XML"
            || !matches!(package.version.as_str(), "0.2" | "0.3-3")
    }));
}

#[test]
fn hermetic_tidyverse_r36_all_quarantined_xml_releases_is_metadata_invalid() {
    let loader = tidyverse_fixture(&[], VersionConstraint::unconstrained());
    let error = resolve_with_loader(tidyverse_manifest(), &loader).unwrap_err();
    assert!(matches!(
        error,
        CranResolutionError::Resolution(ResolutionFailure::CandidateLoad { source, .. })
            if source.category() == CandidateLoadErrorCategory::MetadataInvalid
    ));
}

#[test]
fn hermetic_tidyverse_r36_quarantine_only_xml_constraint_is_metadata_invalid() {
    let xml_constraint = VersionConstraint::from_clause(
        rsolve_core::RelationOp::Lt,
        RPackageVersion::parse("1.0.0").unwrap(),
    );
    let loader = tidyverse_fixture(&["3.99-0.19"], xml_constraint);
    let error = resolve_with_loader(tidyverse_manifest(), &loader).unwrap_err();
    assert!(matches!(
        error,
        CranResolutionError::Resolution(ResolutionFailure::CandidateLoad { source, .. })
            if source.category() == CandidateLoadErrorCategory::MetadataInvalid
    ));
}

#[test]
fn injected_loader_preserves_quarantine_metadata_through_orchestration() {
    let root = PackageName::new("fixture").unwrap();
    let manifest = Manifest::new(
        VersionConstraint::from_clause(
            rsolve_core::RelationOp::Ge,
            RPackageVersion::parse("4.0").unwrap(),
        ),
        crate::manifest::ManifestTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        vec![crate::manifest::ManifestDependency::new(
            root.clone(),
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("2.0").unwrap(),
            ),
        )],
    )
    .unwrap();
    let loader = QuarantinedFixtureLoader {
        package: fixture_loader().package,
        quarantined_version: RPackageVersion::parse("2.0").unwrap(),
    };
    let error = resolve_with_loader(manifest, &loader).unwrap_err();
    assert!(matches!(
        error,
        CranResolutionError::Resolution(ResolutionFailure::CandidateLoad { source, .. })
            if source.category() == CandidateLoadErrorCategory::MetadataInvalid
    ));
}

#[test]
fn injected_loader_uses_target_r_base_package_without_loader_candidates() {
    let root = PackageName::new("fixture").unwrap();
    let methods = PackageName::new("methods").unwrap();
    let target = RPackageVersion::parse("4.4.0").unwrap();
    let root_release = release_with_dependencies(
        &root,
        vec![
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                methods.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::from_clause(rsolve_core::RelationOp::Eq, target.clone()),
            )
            .unwrap(),
        ],
    );

    let resolution = resolve_with_loader(
        manifest_for(root.clone()),
        &FixtureLoader {
            package: root_release,
        },
    )
    .unwrap();

    assert!(resolution.selected(&root).is_some());
    assert!(resolution.selected(&methods).is_none());
}

#[test]
fn injected_loader_does_not_infer_recommended_packages_as_runtime_provided() {
    let root = PackageName::new("fixture").unwrap();
    let matrix = PackageName::new("Matrix").unwrap();
    let root_release = release_with_dependencies(
        &root,
        vec![
            DeclaredDependency::from_parts(
                DependencyKind::Imports,
                matrix,
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )
            .unwrap(),
        ],
    );

    let error = resolve_with_loader(
        manifest_for(root),
        &FixtureLoader {
            package: root_release,
        },
    )
    .unwrap_err();

    assert!(matches!(
        error,
        CranResolutionError::Resolution(ResolutionFailure::NoSolution { .. })
    ));
}
