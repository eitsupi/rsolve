//! Persistent CRAN snapshot preparation before resolver execution.

use std::collections::BTreeSet;

use rsolve_core::{
    CandidateLoadError, CandidateLoader, DependencyKind, PackageName, PublicationDate, RegistryId,
    SolverKey,
};
use rsolve_provider::SnapshotStore;
use rsolve_provider::cran::{CranCandidateSnapshot, CranSnapshotRefresher};
use sha2::{Digest, Sha256};

use crate::Manifest;
use crate::orchestration::{
    CandidateLoaderRef, CranResolutionError, CranResolutionOutcome, resolve_request,
};
use rsolve_resolver::{RBasePackageOverlay, is_r_base_package_name};

/// Derive the private CRAN registry identity from the canonical endpoint.
/// The provider kind and endpoint are length-delimited to avoid ambiguous
/// concatenations; the input bytes are not case-folded.
pub(crate) fn cran_registry_id(canonical_endpoint: &str) -> RegistryId {
    let mut digest = Sha256::new();
    digest.update(b"rsolve-registry-id-v1");
    for field in [b"cran".as_slice(), canonical_endpoint.as_bytes()] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    let hexadecimal = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    RegistryId::new(format!("cran-sha256:{hexadecimal}")).expect("derived registry id is valid")
}

/// Collect the transitive CRAN dependency closure without making resolver-time
/// transport calls. Only Depends, Imports, and LinkingTo participate in the
/// current resolver policy; Suggests and Enhances remain optional metadata.
pub(crate) fn collect_cran_dependency_closure<F>(
    roots: &[PackageName],
    mut refresh: F,
) -> Result<Vec<PackageName>, CandidateLoadError>
where
    F: FnMut(&[PackageName]) -> Result<CranCandidateSnapshot, CandidateLoadError>,
{
    let mut closure = roots
        .iter()
        .filter(|name| is_remote_cran_package(name))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut refreshed = BTreeSet::new();
    loop {
        let batch = closure.difference(&refreshed).cloned().collect::<Vec<_>>();
        if batch.is_empty() {
            return Ok(closure.into_iter().collect());
        }
        let snapshot = refresh(&batch)?;
        for package in &batch {
            let candidates = snapshot.releases(&SolverKey::InstalledName(package.clone()))?;
            for release in candidates {
                for dependency in release.dependencies() {
                    if matches!(
                        dependency.kind,
                        DependencyKind::Depends
                            | DependencyKind::Imports
                            | DependencyKind::LinkingTo
                    ) && is_remote_cran_package(&dependency.name)
                    {
                        closure.insert(dependency.name.clone());
                    }
                }
            }
            refreshed.insert(package.clone());
        }
    }
}

fn collect_cran_dependency_closure_from_loader(
    roots: &[PackageName],
    loader: &dyn CandidateLoader,
) -> Result<Vec<PackageName>, CandidateLoadError> {
    let mut closure = roots
        .iter()
        .filter(|name| is_remote_cran_package(name))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut inspected = BTreeSet::new();
    loop {
        let batch = closure.difference(&inspected).cloned().collect::<Vec<_>>();
        if batch.is_empty() {
            return Ok(closure.into_iter().collect());
        }
        for package in batch {
            let candidates = loader.releases(&SolverKey::InstalledName(package.clone()))?;
            for release in candidates {
                for dependency in release.dependencies() {
                    if matches!(
                        dependency.kind,
                        DependencyKind::Depends
                            | DependencyKind::Imports
                            | DependencyKind::LinkingTo
                    ) && is_remote_cran_package(&dependency.name)
                    {
                        closure.insert(dependency.name.clone());
                    }
                }
            }
            inspected.insert(package);
        }
    }
}

fn try_reuse_current_snapshot(
    request: &rsolve_core::ResolutionRequest,
    roots: &[PackageName],
    loader: &dyn CandidateLoader,
) -> Option<Result<rsolve_core::Resolution, CranResolutionError>> {
    collect_cran_dependency_closure_from_loader(roots, loader).ok()?;
    Some(resolve_prepared_snapshot_without_transport(
        request.clone(),
        loader,
    ))
}

fn is_remote_cran_package(name: &PackageName) -> bool {
    name.as_str() != "R" && !is_r_base_package_name(name)
}

/// Resolve a CRAN manifest against one persistent, immutable snapshot.
pub(crate) fn resolve_from_cran_with_store(
    manifest: Manifest,
    base_url: impl AsRef<str>,
    publication_cutoff: Option<PublicationDate>,
    store: &SnapshotStore,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    let request = crate::manifest::compose_resolution_request(manifest)
        .map_err(CranResolutionError::Composition)?;
    let request = request.with_optional_publication_cutoff(
        publication_cutoff.map(rsolve_core::PublicationCutoff::new),
    );
    let roots = request
        .requirements
        .iter()
        .map(|requirement| requirement.name.clone())
        .collect::<Vec<_>>();
    if let Ok(current) = store.read_current()
        && let Some(Ok(resolution)) = try_reuse_current_snapshot(&request, &roots, &current)
    {
        return Ok(CranResolutionOutcome {
            resolution,
            diagnostics: Vec::new(),
        });
    }
    let refresher = CranSnapshotRefresher::new(base_url).map_err(CranResolutionError::Provider)?;
    let closure =
        collect_cran_dependency_closure(&roots, |batch| refresher.refresh_packages(batch))
            .map_err(CranResolutionError::Refresh)?;
    let resolution = if closure.is_empty() {
        // R/base-only manifests need no remote snapshot, and therefore must
        // not create an empty publication or perform a transport request.
        let empty = CranCandidateSnapshot::default();
        resolve_prepared_snapshot_without_transport(request, &empty)?
    } else {
        let loader = refresher
            .refresh_and_publish_snapshot(store, &closure)
            .map_err(CranResolutionError::Publish)?;
        resolve_prepared_snapshot_without_transport(request, &loader)?
    };
    Ok(CranResolutionOutcome {
        resolution,
        diagnostics: refresher.diagnostics(),
    })
}

/// Solve only through the already prepared loader; no refresh callback is
/// available on this path, so resolver traversal cannot perform transport.
fn resolve_prepared_snapshot_without_transport(
    request: rsolve_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
) -> Result<rsolve_core::Resolution, CranResolutionError> {
    let overlay =
        RBasePackageOverlay::new(CandidateLoaderRef(loader), request.target.r_version.clone())
            .map_err(CranResolutionError::Refresh)?;
    resolve_request(request, &overlay)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsolve_core::{
        CandidateLoadErrorCategory, DependencyRequirement, DependencySourceConstraint,
        PackageNamespace, PackageRelease, Provenance, RPackageVersion, RelationOp, ReleaseIdentity,
        ReleaseMetadata, ReleaseObservation, VersionConstraint,
    };
    use std::collections::BTreeMap;

    fn release_with_dependencies(
        name: &PackageName,
        dependencies: Vec<DependencyRequirement>,
    ) -> PackageRelease {
        let version = RPackageVersion::parse("1.0.0").unwrap();
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
            dependencies,
            distributions: Vec::new(),
        })
        .unwrap()
    }

    fn manifest_for(name: PackageName) -> Manifest {
        Manifest::new(
            VersionConstraint::from_clause(RelationOp::Ge, RPackageVersion::parse("4.0").unwrap()),
            crate::manifest::ManifestTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            vec![crate::manifest::ManifestDependency::new(
                name,
                VersionConstraint::unconstrained(),
            )],
        )
        .unwrap()
    }

    fn required_dependency(kind: DependencyKind, name: &PackageName) -> DependencyRequirement {
        DependencyRequirement::new(
            kind,
            name.clone(),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )
    }

    struct FailingLoader(CandidateLoadError);

    impl CandidateLoader for FailingLoader {
        fn releases(
            &self,
            _package: &SolverKey,
        ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            Err(self.0.clone())
        }
    }

    #[test]
    fn complete_current_snapshot_is_reused_without_refresh_callback() {
        let root = PackageName::new("root").unwrap();
        let dependency = PackageName::new("dependency").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![required_dependency(DependencyKind::Imports, &dependency)],
        );
        let current = CranCandidateSnapshot::from_candidates([
            (root.clone(), vec![root_release]),
            (
                dependency.clone(),
                vec![release_with_dependencies(&dependency, Vec::new())],
            ),
        ]);
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();

        let reused = try_reuse_current_snapshot(&request, std::slice::from_ref(&root), &current)
            .expect("complete current coverage should be eligible for reuse")
            .expect("current snapshot should resolve");

        assert!(reused.selected(&root).is_some());
        assert!(reused.selected(&dependency).is_some());
        assert_eq!(
            collect_cran_dependency_closure_from_loader(&[root], &current).unwrap(),
            vec![dependency, PackageName::new("root").unwrap()]
        );
    }

    #[test]
    fn partial_current_snapshot_falls_back_to_full_closure_refresh() {
        let root = PackageName::new("root").unwrap();
        let dependency = PackageName::new("dependency").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![required_dependency(DependencyKind::Depends, &dependency)],
        );
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
        let partial =
            CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release.clone()])]);
        assert!(
            try_reuse_current_snapshot(&request, std::slice::from_ref(&root), &partial).is_none()
        );

        let complete = CranCandidateSnapshot::from_candidates([
            (root.clone(), vec![root_release]),
            (
                dependency.clone(),
                vec![release_with_dependencies(&dependency, Vec::new())],
            ),
        ]);
        let mut refresh_calls = 0;
        let closure = collect_cran_dependency_closure(&[root], |_| {
            refresh_calls += 1;
            Ok(complete.clone())
        })
        .unwrap();
        assert_eq!(closure, vec![dependency, PackageName::new("root").unwrap()]);
        assert_eq!(refresh_calls, 2, "fallback refreshes the full closure");
    }

    #[test]
    fn invalid_current_snapshot_is_not_reused() {
        let root = PackageName::new("root").unwrap();
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
        let invalid = FailingLoader(CandidateLoadError::new(
            CandidateLoadErrorCategory::SnapshotInvalid,
            "current generation is invalid",
        ));

        assert!(try_reuse_current_snapshot(&request, &[root], &invalid).is_none());
    }
}
