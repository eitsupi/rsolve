use std::error::Error;
use std::fmt;

use nrr_core::{CandidateLoadError, CandidateLoader, Resolution};
use nrr_provider::cran::{
    CranCandidateSnapshot, CranRefreshDiagnostic, CranSnapshotRefresher, CranSnapshotRefresherError,
};
use nrr_resolver::{DefaultCandidatePreference, PreferLocked, ResolutionFailure, Resolver};

use crate::manifest::{Manifest, ManifestError, compose_resolution_request};

/// The failure stage of a CRAN-backed resolution orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranResolutionError {
    Composition(ManifestError),
    Provider(CranSnapshotRefresherError),
    Refresh(CandidateLoadError),
    Resolution(ResolutionFailure),
}

impl fmt::Display for CranResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Composition(error) => write!(formatter, "manifest composition failed: {error}"),
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
            Self::Provider(error) => Some(error),
            Self::Refresh(error) => Some(error),
            Self::Resolution(error) => Some(error),
        }
    }
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
    let request = compose_resolution_request(manifest).map_err(CranResolutionError::Composition)?;
    resolve_request(request, loader)
}

fn resolve_request(
    request: nrr_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
) -> Result<Resolution, CranResolutionError> {
    let preference = DefaultCandidatePreference;
    let lock_policy = PreferLocked;
    Resolver::new(loader, &preference, &lock_policy)
        .resolve(request)
        .map_err(CranResolutionError::Resolution)
}

fn resolve_request_with_snapshot_refresh<F>(
    request: nrr_core::ResolutionRequest,
    mut snapshot: CranCandidateSnapshot,
    mut refresh: F,
) -> Result<Resolution, CranResolutionError>
where
    F: FnMut(&[nrr_core::PackageName]) -> Result<CranCandidateSnapshot, CandidateLoadError>,
{
    loop {
        match resolve_request(request.clone(), &snapshot) {
            Ok(resolution) => return Ok(resolution),
            Err(CranResolutionError::Resolution(ResolutionFailure::CandidateLoad {
                package: nrr_core::SolverKey::InstalledName(name),
                source,
            })) if source.category() == nrr_core::CandidateLoadErrorCategory::NotFound
                && snapshot.needs_refresh(&nrr_core::SolverKey::InstalledName(name.clone())) =>
            {
                let next_snapshot =
                    refresh(std::slice::from_ref(&name)).map_err(CranResolutionError::Refresh)?;
                if !next_snapshot.contains_package(&name) {
                    return Err(CranResolutionError::Refresh(CandidateLoadError::new(
                        nrr_core::CandidateLoadErrorCategory::SnapshotInvalid,
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
    let request = compose_resolution_request(manifest).map_err(CranResolutionError::Composition)?;
    let refresher = CranSnapshotRefresher::new(base_url).map_err(CranResolutionError::Provider)?;
    let roots = request
        .requirements
        .iter()
        .map(|requirement| requirement.name.clone())
        .collect::<Vec<_>>();
    let snapshot = refresher
        .refresh_packages(&roots)
        .map_err(CranResolutionError::Refresh)?;
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
    use nrr_core::{
        CandidateLoadError, CandidateLoadErrorCategory, DependencyKind, DependencyRequirement,
        DependencySourceConstraint, PackageName, PackageNamespace, PackageRelease, Provenance,
        RPackageVersion, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, SolverKey,
        VersionConstraint,
    };
    use nrr_provider::cran::CranCandidateSnapshot;
    use std::collections::BTreeMap;

    struct FixtureLoader {
        package: PackageRelease,
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
            dependencies,
            distributions: Vec::new(),
        })
        .unwrap()
    }

    fn manifest_for(name: PackageName) -> Manifest {
        Manifest::new(
            VersionConstraint::from_clause(
                nrr_core::RelationOp::Ge,
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
                nrr_core::RelationOp::Ge,
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
        let resolution = resolve_request_with_snapshot_refresh(request, initial, |names| {
            refreshed.push(names.to_vec());
            Ok(complete.clone())
        })
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
                    nrr_core::RelationOp::Ge,
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
        let error = resolve_request_with_snapshot_refresh(request, initial, |_| {
            empty_refreshes += 1;
            Ok(empty.clone())
        })
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
        let error = resolve_request_with_snapshot_refresh(request, initial.clone(), |_| {
            refreshes += 1;
            Ok(initial.clone())
        })
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
        let error = resolve_request_with_snapshot_refresh(request, initial, |_| {
            refreshes += 1;
            Ok(CranCandidateSnapshot::from_candidates([(
                root.clone(),
                vec![root_release.clone()],
            )]))
        })
        .unwrap_err();
        assert_eq!(refreshes, 1);
        assert!(matches!(
            error,
            CranResolutionError::Refresh(error)
                if error.category() == CandidateLoadErrorCategory::SnapshotInvalid
        ));
    }

    #[test]
    fn injected_loader_exercises_manifest_to_resolution_orchestration() {
        let manifest = Manifest::new(
            VersionConstraint::from_clause(
                nrr_core::RelationOp::Ge,
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
}
