use std::error::Error;
use std::fmt;

use rsolve_core::{
    CandidateLoadError, CandidateLoader, PackageRelease, PublicationCutoff, PublicationDate,
    Resolution, SolverKey,
};
use rsolve_provider::cran::{
    CranCandidateSnapshot, CranRefreshDiagnostic, CranSnapshotRefresher, CranSnapshotRefresherError,
};
use rsolve_resolver::{
    DefaultCandidatePreference, PreferLocked, RBasePackageOverlay, RequireLocked,
    ResolutionFailure, Resolver, is_r_base_package_name,
};

use crate::lock::{EnvironmentId, LockError, Lockfile};
use crate::manifest::{Manifest, ManifestError, compose_resolution_request};

struct CandidateLoaderRef<'a>(&'a dyn CandidateLoader);

impl CandidateLoader for CandidateLoaderRef<'_> {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        self.0.releases(package)
    }
}

type RuntimeSnapshot = RBasePackageOverlay<CranCandidateSnapshot>;

fn runtime_snapshot_needs_refresh(snapshot: &RuntimeSnapshot, package: &SolverKey) -> bool {
    match package {
        SolverKey::InstalledName(name) if is_r_base_package_name(name) => false,
        SolverKey::InstalledName(_) => snapshot.inner().needs_refresh(package),
        _ => false,
    }
}

/// The failure stage of a CRAN-backed resolution orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranResolutionError {
    Composition(ManifestError),
    Lock(LockError),
    Provider(CranSnapshotRefresherError),
    Refresh(CandidateLoadError),
    Resolution(ResolutionFailure),
}

impl fmt::Display for CranResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Composition(error) => write!(formatter, "manifest composition failed: {error}"),
            Self::Lock(error) => write!(formatter, "lock projection failed: {error}"),
            Self::Provider(error) => {
                write!(formatter, "CRAN provider construction failed: {error}")
            }
            Self::Refresh(error) => write!(formatter, "CRAN refresh failed: {error}"),
            Self::Resolution(error) => write!(formatter, "resolution failed: {error}"),
        }
    }
}

impl Error for CranResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Composition(error) => Some(error),
            Self::Lock(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::Refresh(error) => Some(error),
            Self::Resolution(error) => Some(error),
        }
    }
}

/// Whether a lock is a soft preference or an exact constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionMode {
    Normal,
    Frozen,
}

/// A concrete CRAN resolution together with its per-package refresh diagnostics.
#[derive(Clone, Debug)]
pub struct CranResolutionOutcome {
    resolution: Resolution,
    diagnostics: Vec<CranRefreshDiagnostic>,
}

impl CranResolutionOutcome {
    pub fn resolution(&self) -> &Resolution {
        &self.resolution
    }

    pub fn diagnostics(&self) -> &[CranRefreshDiagnostic] {
        &self.diagnostics
    }
}

/// Resolve a composed manifest through an injected candidate loader.
///
/// This helper keeps orchestration tests hermetic while exercising the same
/// resolver policy used by the concrete CRAN entry point.
pub fn resolve_with_loader(
    manifest: Manifest,
    loader: &dyn CandidateLoader,
) -> Result<Resolution, CranResolutionError> {
    resolve_with_loader_with_publication_cutoff(manifest, loader, None)
}

pub fn resolve_with_loader_with_publication_cutoff(
    manifest: Manifest,
    loader: &dyn CandidateLoader,
    publication_cutoff: Option<PublicationDate>,
) -> Result<Resolution, CranResolutionError> {
    let request = compose_resolution_request(manifest).map_err(CranResolutionError::Composition)?;
    let request =
        request.with_optional_publication_cutoff(publication_cutoff.map(PublicationCutoff::new));
    let overlay =
        RBasePackageOverlay::new(CandidateLoaderRef(loader), request.target.r_version.clone())
            .map_err(CranResolutionError::Refresh)?;
    resolve_request(request, &overlay)
}

/// Resolve a manifest using a shared logical lock and an injected loader.
///
/// The lock contributes identities only; resolver policy remains owned by
/// `rsolve-resolver`, where normal mode uses `PreferLocked` and frozen mode uses
/// `RequireLocked`.
pub fn resolve_with_lock(
    manifest: Manifest,
    lockfile: &Lockfile,
    environment: &EnvironmentId,
    mode: ResolutionMode,
    loader: &dyn CandidateLoader,
) -> Result<Resolution, CranResolutionError> {
    let request = lockfile
        .resolution_request(manifest, environment)
        .map_err(CranResolutionError::Lock)?;
    let overlay =
        RBasePackageOverlay::new(CandidateLoaderRef(loader), request.target.r_version.clone())
            .map_err(CranResolutionError::Refresh)?;
    resolve_request_with_mode(request, &overlay, mode)
}

fn resolve_request(
    request: rsolve_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
) -> Result<Resolution, CranResolutionError> {
    resolve_request_with_mode(request, loader, ResolutionMode::Normal)
}

fn resolve_request_with_mode(
    request: rsolve_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
    mode: ResolutionMode,
) -> Result<Resolution, CranResolutionError> {
    let preference = DefaultCandidatePreference;
    let prefer = PreferLocked;
    let require = RequireLocked;
    let lock_policy: &dyn rsolve_resolver::LockUpdatePolicy = match mode {
        ResolutionMode::Normal => &prefer,
        ResolutionMode::Frozen => &require,
    };
    Resolver::new(loader, &preference, lock_policy)
        .resolve(request)
        .map_err(CranResolutionError::Resolution)
}

fn resolve_request_with_snapshot_refresh<F>(
    request: rsolve_core::ResolutionRequest,
    mut snapshot: RuntimeSnapshot,
    mut refresh: F,
) -> Result<Resolution, CranResolutionError>
where
    F: FnMut(&[rsolve_core::PackageName]) -> Result<CranCandidateSnapshot, CandidateLoadError>,
{
    loop {
        match resolve_request(request.clone(), &snapshot) {
            Ok(resolution) => return Ok(resolution),
            Err(CranResolutionError::Resolution(ResolutionFailure::CandidateLoad {
                package: rsolve_core::SolverKey::InstalledName(name),
                source,
            })) if source.category() == rsolve_core::CandidateLoadErrorCategory::NotFound
                && runtime_snapshot_needs_refresh(
                    &snapshot,
                    &rsolve_core::SolverKey::InstalledName(name.clone()),
                ) =>
            {
                let next_snapshot = refresh(std::slice::from_ref(&name))
                    .map_err(CranResolutionError::Refresh)
                    .and_then(|next| {
                        RuntimeSnapshot::new(next, snapshot.r_version().clone())
                            .map_err(CranResolutionError::Refresh)
                    })?;
                if runtime_snapshot_needs_refresh(
                    &next_snapshot,
                    &SolverKey::InstalledName(name.clone()),
                ) {
                    return Err(CranResolutionError::Refresh(CandidateLoadError::new(
                        rsolve_core::CandidateLoadErrorCategory::SnapshotInvalid,
                        format!("refresh did not produce a result for package {name}"),
                    )));
                }
                snapshot = next_snapshot;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Resolve a manifest against CRAN's synchronous blocking snapshot refresher.
///
/// This boundary is synchronous; callers running inside an async runtime
/// should invoke it on a blocking worker rather than directly on an async
/// executor thread.
pub fn resolve_from_cran(
    manifest: Manifest,
    base_url: impl AsRef<str>,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    resolve_from_cran_with_publication_cutoff(manifest, base_url, None)
}

pub fn resolve_from_cran_with_publication_cutoff(
    manifest: Manifest,
    base_url: impl AsRef<str>,
    publication_cutoff: Option<PublicationDate>,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    let request = compose_resolution_request(manifest).map_err(CranResolutionError::Composition)?;
    let request =
        request.with_optional_publication_cutoff(publication_cutoff.map(PublicationCutoff::new));
    let refresher = CranSnapshotRefresher::new(base_url).map_err(CranResolutionError::Provider)?;
    let roots = request
        .requirements
        .iter()
        .map(|requirement| requirement.name.clone())
        .filter(|name| !is_r_base_package_name(name))
        .collect::<Vec<_>>();
    let snapshot = refresher
        .refresh_packages(&roots)
        .map_err(CranResolutionError::Refresh)
        .and_then(|snapshot| {
            RuntimeSnapshot::new(snapshot, request.target.r_version.clone())
                .map_err(CranResolutionError::Refresh)
        })?;
    let resolution = resolve_request_with_snapshot_refresh(request, snapshot, |packages| {
        refresher.refresh_packages(packages)
    })?;
    Ok(CranResolutionOutcome {
        resolution,
        diagnostics: refresher.diagnostics(),
    })
}

#[cfg(test)]
mod tests {
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
                    Ok(self.packages.clone())
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
            crate::manifest::ManifestTarget::new(
                RPackageVersion::parse("4.4.0").unwrap(),
                "linux",
                "x86_64",
            )
            .unwrap(),
            vec![crate::manifest::ManifestDependency::new(
                name,
                VersionConstraint::unconstrained(),
            )],
        )
        .unwrap()
    }

    #[test]
    fn lock_boundary_uses_soft_fallback_and_frozen_exact_policy() {
        let name = PackageName::new("choice").unwrap();
        let old = release_at_version(&name, "1.0.0");
        let newer = release_at_version(&name, "2.0.0");
        let old_resolution = Resolution::new(
            ResolutionTarget::new(
                RPackageVersion::parse("4.4.0").unwrap(),
                rsolve_core::Target::new("linux", "x86_64"),
            ),
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
        let normal = resolve_with_lock(
            manifest_for(name.clone()),
            &lock,
            &environment,
            ResolutionMode::Normal,
            &loader,
        )
        .unwrap();
        assert_eq!(normal.selected(&name).unwrap().version(), newer.version());
        assert!(
            resolve_with_lock(
                manifest_for(name),
                &lock,
                &environment,
                ResolutionMode::Frozen,
                &loader,
            )
            .is_err()
        );
    }

    #[test]
    fn snapshot_retry_refreshes_only_the_missing_solver_package() {
        let root = PackageName::new("fixture").unwrap();
        let dependency = PackageName::new("fixture.dependency").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![DependencyRequirement::new(
                DependencyKind::Imports,
                dependency.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )],
        );
        let dependency_release = release_with_dependencies(&dependency, Vec::new());
        let initial =
            CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release.clone()])]);
        let complete = CranCandidateSnapshot::from_candidates([
            (root.clone(), vec![root_release]),
            (dependency.clone(), vec![dependency_release]),
        ]);
        let manifest = Manifest::new(
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("4.0").unwrap(),
            ),
            crate::manifest::ManifestTarget::new(
                RPackageVersion::parse("4.4.0").unwrap(),
                "linux",
                "x86_64",
            )
            .unwrap(),
            vec![crate::manifest::ManifestDependency::new(
                root.clone(),
                VersionConstraint::unconstrained(),
            )],
        )
        .unwrap();
        let request = compose_resolution_request(manifest).unwrap();
        let mut refreshed = Vec::new();
        let resolution = resolve_request_with_snapshot_refresh(
            request,
            RuntimeSnapshot::new(initial, RPackageVersion::parse("4.4.0").unwrap()).unwrap(),
            |names| {
                refreshed.push(names.to_vec());
                Ok(complete.clone())
            },
        )
        .unwrap();
        assert_eq!(refreshed, vec![vec![dependency.clone()]]);
        assert!(resolution.selected(&root).is_some());
        assert!(resolution.selected(&dependency).is_some());

        let initial = CranCandidateSnapshot::from_candidates([(
            root.clone(),
            vec![release_with_dependencies(
                &root,
                vec![DependencyRequirement::new(
                    DependencyKind::Imports,
                    dependency.clone(),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                )],
            )],
        )]);
        let empty = CranCandidateSnapshot::from_candidates([
            (
                root.clone(),
                vec![release_with_dependencies(
                    &root,
                    vec![DependencyRequirement::new(
                        DependencyKind::Imports,
                        dependency.clone(),
                        DependencySourceConstraint::Any,
                        VersionConstraint::unconstrained(),
                    )],
                )],
            ),
            (dependency.clone(), Vec::new()),
        ]);
        let request = compose_resolution_request(
            Manifest::new(
                VersionConstraint::from_clause(
                    rsolve_core::RelationOp::Ge,
                    RPackageVersion::parse("4.0").unwrap(),
                ),
                crate::manifest::ManifestTarget::new(
                    RPackageVersion::parse("4.4.0").unwrap(),
                    "linux",
                    "x86_64",
                )
                .unwrap(),
                vec![crate::manifest::ManifestDependency::new(
                    root,
                    VersionConstraint::unconstrained(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
        let mut empty_refreshes = 0;
        let error = resolve_request_with_snapshot_refresh(
            request,
            RuntimeSnapshot::new(initial, RPackageVersion::parse("4.4.0").unwrap()).unwrap(),
            |_| {
                empty_refreshes += 1;
                Ok(empty.clone())
            },
        )
        .unwrap_err();
        assert_eq!(empty_refreshes, 1);
        assert!(matches!(
            error,
            CranResolutionError::Resolution(ResolutionFailure::NoSolution { .. })
        ));
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
        let request = compose_resolution_request(manifest_for(root)).unwrap();
        let mut refreshes = 0;
        let error = resolve_request_with_snapshot_refresh(
            request,
            RuntimeSnapshot::new(initial.clone(), RPackageVersion::parse("4.4.0").unwrap())
                .unwrap(),
            |_| {
                refreshes += 1;
                Ok(initial.clone())
            },
        )
        .unwrap_err();
        assert_eq!(refreshes, 0);
        assert!(matches!(
            error,
            CranResolutionError::Resolution(ResolutionFailure::CandidateLoad {
                package: SolverKey::Registry { .. },
                ..
            })
        ));
    }

    #[test]
    fn refresh_result_missing_requested_package_stops_with_snapshot_invalid() {
        let root = PackageName::new("fixture").unwrap();
        let dependency = PackageName::new("fixture.missing").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![DependencyRequirement::new(
                DependencyKind::Imports,
                dependency,
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )],
        );
        let initial =
            CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release.clone()])]);
        let request = compose_resolution_request(manifest_for(root.clone())).unwrap();
        let mut refreshes = 0;
        let error = resolve_request_with_snapshot_refresh(
            request,
            RuntimeSnapshot::new(initial, RPackageVersion::parse("4.4.0").unwrap()).unwrap(),
            |_| {
                refreshes += 1;
                Ok(CranCandidateSnapshot::from_candidates([(
                    root.clone(),
                    vec![root_release.clone()],
                )]))
            },
        )
        .unwrap_err();
        assert_eq!(refreshes, 1);
        assert!(matches!(
            error,
            CranResolutionError::Refresh(error)
                if error.category() == CandidateLoadErrorCategory::SnapshotInvalid
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
        let overlay = RuntimeSnapshot::new(cran, target.clone()).unwrap();
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
        assert!(!runtime_snapshot_needs_refresh(
            &overlay,
            &SolverKey::InstalledName(methods),
        ));
        assert!(
            !overlay.releases(&SolverKey::InstalledName(matrix)).unwrap()[0].is_r_base_package()
        );
        let empty_overlay =
            RuntimeSnapshot::new(CranCandidateSnapshot::from_candidates([]), target).unwrap();
        assert!(runtime_snapshot_needs_refresh(
            &empty_overlay,
            &SolverKey::InstalledName(PackageName::new("Matrix").unwrap()),
        ));
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
        let initial = RuntimeSnapshot::new(
            CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release])]),
            target.clone(),
        )
        .unwrap();
        let request = compose_resolution_request(manifest_for(root.clone())).unwrap();
        let mut refreshes = 0;
        let resolution = resolve_request_with_snapshot_refresh(request, initial, |_| {
            refreshes += 1;
            Ok(CranCandidateSnapshot::from_candidates([]))
        })
        .unwrap();
        assert_eq!(refreshes, 0);
        assert!(resolution.selected(&root).is_some());
        assert!(resolution.selected(&methods).is_none());
    }

    #[test]
    fn incompatible_methods_constraint_is_no_solution_without_refresh() {
        let root = PackageName::new("fixture").unwrap();
        let methods = PackageName::new("methods").unwrap();
        let target = RPackageVersion::parse("4.4.0").unwrap();
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
        let initial = RuntimeSnapshot::new(
            CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release])]),
            target,
        )
        .unwrap();
        let request = compose_resolution_request(manifest_for(root)).unwrap();
        let mut refreshes = 0;
        let error = resolve_request_with_snapshot_refresh(request, initial, |_| {
            refreshes += 1;
            Ok(CranCandidateSnapshot::from_candidates([]))
        })
        .unwrap_err();
        assert_eq!(refreshes, 0);
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
            crate::manifest::ManifestTarget::new(
                RPackageVersion::parse("4.4.0").unwrap(),
                "linux",
                "x86_64",
            )
            .unwrap(),
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
}
