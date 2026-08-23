use super::*;
use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, DependencyKind, DependencyRequirement,
    DependencySourceConstraint, PackageName, PackageNamespace, PackageRelease, Provenance,
    RPackageVersion, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, ResolutionTarget,
    SolverKey, VersionConstraint,
};
use rsolve_provider::cran::CranCandidateSnapshot;
use rsolve_resolver::R_BASE_PACKAGE_NAMES;
use std::collections::BTreeMap;

struct FixtureLoader {
    package: PackageRelease,
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
        dependencies: Vec::new(),
        distributions: Vec::new(),
    };
    FixtureLoader {
        package: PackageRelease::try_from(observation).unwrap(),
    }
}

fn release_with_dependencies(
    name: &PackageName,
    dependencies: Vec<DependencyRequirement>,
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
        dependencies,
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
        dependencies: Vec::new(),
        distributions: Vec::new(),
    })
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
        DependencyRequirement::new(
            kind,
            name.clone(),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )
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
        vec![DependencyRequirement::new(
            DependencyKind::Imports,
            dependency.clone(),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )],
    );
    let old_dependency = release_with_dependencies(&dependency, Vec::new());
    let old_resolution = Resolution::new(
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        vec![
            rsolve_core::ResolvedPackage::new(SolverKey::InstalledName(root.clone()), old_root),
            rsolve_core::ResolvedPackage::new(SolverKey::InstalledName(dependency), old_dependency),
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
        )],
    );
    let environment = EnvironmentId::new("default").unwrap();
    let lock = Lockfile::from_resolution(&old_resolution, environment.clone()).unwrap();
    let refreshed_root = release_with_dependencies(
        &root,
        vec![DependencyRequirement::new(
            DependencyKind::Imports,
            extra.clone(),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )],
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
            )],
        ),
        EnvironmentId::new("default").unwrap(),
    )
    .unwrap();
    let environment = EnvironmentId::new("default").unwrap();
    let refreshed_root = release_with_dependencies(
        &root,
        vec![
            DependencyRequirement::new(
                DependencyKind::Imports,
                first.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            ),
            DependencyRequirement::new(
                DependencyKind::Imports,
                second.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            ),
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
fn source_qualified_not_found_is_propagated_without_refresh_retry() {
    let root = PackageName::new("fixture").unwrap();
    let dependency = PackageName::new("fixture.registry").unwrap();
    let root_release = release_with_dependencies(
        &root,
        vec![DependencyRequirement::new(
            DependencyKind::Imports,
            dependency,
            DependencySourceConstraint::Registry {
                namespace: PackageNamespace::new("cran").unwrap(),
            },
            VersionConstraint::unconstrained(),
        )],
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
        vec![DependencyRequirement::new(
            DependencyKind::Imports,
            methods.clone(),
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(rsolve_core::RelationOp::Eq, target.clone()),
        )],
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
        vec![DependencyRequirement::new(
            DependencyKind::Imports,
            methods,
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Eq,
                RPackageVersion::parse("4.3.0").unwrap(),
            ),
        )],
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
fn injected_loader_uses_target_r_base_package_without_loader_candidates() {
    let root = PackageName::new("fixture").unwrap();
    let methods = PackageName::new("methods").unwrap();
    let target = RPackageVersion::parse("4.4.0").unwrap();
    let root_release = release_with_dependencies(
        &root,
        vec![DependencyRequirement::new(
            DependencyKind::Imports,
            methods.clone(),
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(rsolve_core::RelationOp::Eq, target.clone()),
        )],
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
        vec![DependencyRequirement::new(
            DependencyKind::Imports,
            matrix,
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )],
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
