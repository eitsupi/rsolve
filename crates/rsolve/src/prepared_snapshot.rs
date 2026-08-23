//! Persistent CRAN snapshot preparation before resolver execution.

use std::collections::BTreeSet;

use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, DependencyKind, PackageName,
    PublicationDate, RegistryId, SolverKey,
};
use rsolve_provider::SnapshotStore;
use rsolve_provider::cran::{CranCandidateSnapshot, CranSnapshotRefresher};
use rsolve_provider::cran::{
    CranSnapshotCacheDiagnostic, CranSnapshotCachePolicy, CranSnapshotCacheResult,
    CranSnapshotCacheStatus, inspect_cran_snapshot_cache,
};
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

fn is_remote_cran_package(name: &PackageName) -> bool {
    name.as_str() != "R" && !is_r_base_package_name(name)
}

enum CacheProbe<L> {
    Compatible {
        loader: L,
        diagnostic: CranSnapshotCacheDiagnostic,
    },
    Rejected(CranSnapshotCacheDiagnostic),
}

/// Shared cache decision boundary used by both production resolution and
/// deterministic orchestration tests. Refresh is invoked only when the
/// compatible generation is stale or cannot prove the requested closure.
fn cache_or_refresh<L, F>(
    probe: CacheProbe<L>,
    roots: &[PackageName],
    mut refresh: F,
) -> Result<(L, Vec<CranSnapshotCacheDiagnostic>), CranResolutionError>
where
    L: CandidateLoader,
    F: FnMut(&[PackageName]) -> Result<L, CranResolutionError>,
{
    let mut diagnostics = Vec::new();
    match probe {
        CacheProbe::Compatible { loader, diagnostic }
            if diagnostic.status() == CranSnapshotCacheStatus::Fresh =>
        {
            match collect_cran_dependency_closure_from_loader(roots, &loader) {
                Ok(_) => return Ok((loader, vec![diagnostic])),
                Err(error) => {
                    diagnostics.push(CranSnapshotCacheDiagnostic::closure_incomplete(&error))
                }
            }
        }
        CacheProbe::Compatible { diagnostic, .. } | CacheProbe::Rejected(diagnostic) => {
            diagnostics.push(diagnostic)
        }
    }
    let loader = refresh(roots)?;
    Ok((loader, diagnostics))
}

fn resolve_offline_from_cache<L: CandidateLoader>(
    request: rsolve_core::ResolutionRequest,
    roots: &[PackageName],
    probe: CacheProbe<L>,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    let (loader, diagnostic) = match probe {
        CacheProbe::Compatible { loader, diagnostic } => (loader, diagnostic),
        CacheProbe::Rejected(diagnostic) => return Err(CranResolutionError::Cache(diagnostic)),
    };
    collect_cran_dependency_closure_from_loader(roots, &loader)
        .map_err(CranResolutionError::Offline)?;
    let resolution = resolve_prepared_snapshot_without_transport(request, &loader)?;
    Ok(CranResolutionOutcome {
        resolution,
        diagnostics: Vec::new(),
        cache_diagnostics: vec![diagnostic],
    })
}

/// Resolve a CRAN manifest against one persistent, immutable snapshot.
pub(crate) fn resolve_from_cran_with_store(
    manifest: Manifest,
    base_url: impl AsRef<str>,
    publication_cutoff: Option<PublicationDate>,
    store: &SnapshotStore,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    resolve_from_cran_with_store_at_policy(
        manifest,
        base_url,
        publication_cutoff,
        store,
        CranSnapshotCachePolicy::default(),
    )
}

/// Testable policy seam for the provider-owned cache decision. Production
/// callers use [`resolve_from_cran_with_store`] and its system clock default.
pub(crate) fn resolve_from_cran_with_store_at_policy(
    manifest: Manifest,
    base_url: impl AsRef<str>,
    publication_cutoff: Option<PublicationDate>,
    store: &SnapshotStore,
    cache_policy: CranSnapshotCachePolicy,
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
    if roots.iter().all(|name| !is_remote_cran_package(name)) {
        let resolution = resolve_prepared_snapshot_without_transport(
            request,
            &CranCandidateSnapshot::default(),
        )?;
        return Ok(CranResolutionOutcome {
            resolution,
            diagnostics: Vec::new(),
            cache_diagnostics: Vec::new(),
        });
    }
    let refresher = CranSnapshotRefresher::new(base_url).map_err(CranResolutionError::Provider)?;
    let cache_policy = cache_policy.with_expected_endpoint(refresher.canonical_endpoint());
    let cache = inspect_cran_snapshot_cache(store, &cache_policy);
    let probe = match cache {
        CranSnapshotCacheResult::Compatible { loader, diagnostic } => CacheProbe::Compatible {
            loader: *loader,
            diagnostic,
        },
        CranSnapshotCacheResult::Rejected(diagnostic) => CacheProbe::Rejected(diagnostic),
    };
    let (loader, cache_diagnostics) = cache_or_refresh(probe, &roots, |batch| {
        let closure =
            collect_cran_dependency_closure(batch, |batch| refresher.refresh_packages(batch))
                .map_err(CranResolutionError::Refresh)?;
        if closure.is_empty() {
            return Err(CranResolutionError::Refresh(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                format!(
                    "refresh returned no remote packages for batch of {}",
                    batch.len()
                ),
            )));
        }
        refresher
            .refresh_and_publish_snapshot(store, &closure)
            .map_err(CranResolutionError::Publish)
    })?;
    let resolution = resolve_prepared_snapshot_without_transport(request, &loader)?;
    Ok(CranResolutionOutcome {
        resolution,
        diagnostics: refresher.diagnostics(),
        cache_diagnostics,
    })
}

/// Resolve through the configured current generation without creating a
/// provider refresher. This is the explicit offline policy boundary.
pub(crate) fn resolve_from_cran_offline_with_store(
    manifest: Manifest,
    publication_cutoff: Option<PublicationDate>,
    store: &SnapshotStore,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    resolve_from_cran_offline_with_store_at_policy(
        manifest,
        publication_cutoff,
        store,
        CranSnapshotCachePolicy::default(),
    )
}

pub(crate) fn resolve_from_cran_offline_with_store_at_policy(
    manifest: Manifest,
    publication_cutoff: Option<PublicationDate>,
    store: &SnapshotStore,
    cache_policy: CranSnapshotCachePolicy,
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
    if roots.iter().all(|name| !is_remote_cran_package(name)) {
        let resolution = resolve_prepared_snapshot_without_transport(
            request,
            &CranCandidateSnapshot::default(),
        )?;
        return Ok(CranResolutionOutcome {
            resolution,
            diagnostics: Vec::new(),
            cache_diagnostics: Vec::new(),
        });
    }
    let cache = inspect_cran_snapshot_cache(store, &cache_policy);
    let probe = match cache {
        CranSnapshotCacheResult::Compatible { loader, diagnostic } => CacheProbe::Compatible {
            loader: *loader,
            diagnostic,
        },
        CranSnapshotCacheResult::Rejected(diagnostic) => CacheProbe::Rejected(diagnostic),
    };
    resolve_offline_from_cache(request, &roots, probe)
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
    use tempfile::tempdir;

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
    fn offline_complete_current_snapshot_resolves_without_refresh_callback() {
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

        collect_cran_dependency_closure_from_loader(std::slice::from_ref(&root), &current)
            .expect("complete current coverage should be eligible for offline use");
        let reused = resolve_prepared_snapshot_without_transport(request, &current).unwrap();

        assert!(reused.selected(&root).is_some());
        assert!(reused.selected(&dependency).is_some());
        assert_eq!(
            collect_cran_dependency_closure_from_loader(&[root], &current).unwrap(),
            vec![dependency, PackageName::new("root").unwrap()]
        );
    }

    #[test]
    fn online_preparation_refreshes_full_closure_after_partial_current_failure() {
        let root = PackageName::new("root").unwrap();
        let dependency = PackageName::new("dependency").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![required_dependency(DependencyKind::Depends, &dependency)],
        );
        let partial =
            CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release.clone()])]);
        let error =
            collect_cran_dependency_closure_from_loader(std::slice::from_ref(&root), &partial)
                .unwrap_err();
        assert_eq!(error.category(), CandidateLoadErrorCategory::NotFound);

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

    fn cache_diagnostic(
        status: CranSnapshotCacheStatus,
        age: Option<u64>,
    ) -> CranSnapshotCacheDiagnostic {
        CranSnapshotCacheDiagnostic::new(
            status,
            age,
            ["https://cran.example/src/contrib/PACKAGES"],
            "test cache decision",
        )
    }

    #[test]
    fn fresh_complete_cache_reuse_skips_refresh_callback() {
        let root = PackageName::new("root").unwrap();
        let dependency = PackageName::new("dependency").unwrap();
        let loader = CranCandidateSnapshot::from_candidates([
            (
                root.clone(),
                vec![release_with_dependencies(
                    &root,
                    vec![required_dependency(DependencyKind::Imports, &dependency)],
                )],
            ),
            (
                dependency.clone(),
                vec![release_with_dependencies(&dependency, Vec::new())],
            ),
        ]);
        let mut refreshes = 0;
        let (reused, diagnostics) = cache_or_refresh(
            CacheProbe::Compatible {
                loader,
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Fresh, Some(30)),
            },
            std::slice::from_ref(&root),
            |_| {
                refreshes += 1;
                unreachable!("fresh complete cache must not refresh")
            },
        )
        .unwrap();
        assert!(reused.contains_package(&dependency));
        assert_eq!(refreshes, 0);
        assert_eq!(diagnostics[0].status(), CranSnapshotCacheStatus::Fresh);
    }

    #[test]
    fn stale_or_incomplete_cache_refreshes_once() {
        let root = PackageName::new("root").unwrap();
        let complete = CranCandidateSnapshot::from_candidates([(
            root.clone(),
            vec![release_with_dependencies(&root, Vec::new())],
        )]);
        for (probe, expected_status) in [
            (
                CacheProbe::Compatible {
                    loader: complete.clone(),
                    diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Stale, Some(7200)),
                },
                CranSnapshotCacheStatus::Stale,
            ),
            (
                CacheProbe::Compatible {
                    loader: CranCandidateSnapshot::default(),
                    diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Fresh, Some(30)),
                },
                CranSnapshotCacheStatus::Incomplete,
            ),
        ] {
            let mut refreshes = 0;
            let (_, diagnostics) = cache_or_refresh(probe, std::slice::from_ref(&root), |_| {
                refreshes += 1;
                Ok(complete.clone())
            })
            .unwrap();
            assert_eq!(refreshes, 1);
            assert_eq!(diagnostics[0].status(), expected_status);
        }
    }

    #[test]
    fn offline_stale_cache_preserves_age_and_sources_and_rejections_are_typed() {
        let root = PackageName::new("root").unwrap();
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
        let loader = CranCandidateSnapshot::from_candidates([(
            root.clone(),
            vec![release_with_dependencies(&root, Vec::new())],
        )]);
        let outcome = resolve_offline_from_cache(
            request,
            std::slice::from_ref(&root),
            CacheProbe::Compatible {
                loader,
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Stale, Some(7200)),
            },
        )
        .unwrap();
        assert_eq!(outcome.cache_diagnostics()[0].age_seconds(), Some(7200));
        assert_eq!(
            outcome.cache_diagnostics()[0]
                .endpoints()
                .collect::<Vec<_>>(),
            vec!["https://cran.example/src/contrib/PACKAGES"]
        );
        let request = crate::manifest::compose_resolution_request(manifest_for(root)).unwrap();
        let error = resolve_offline_from_cache(
            request,
            &[],
            CacheProbe::<CranCandidateSnapshot>::Rejected(cache_diagnostic(
                CranSnapshotCacheStatus::RevisionIncompatible,
                None,
            )),
        )
        .unwrap_err();
        let CranResolutionError::Cache(diagnostic) = error else {
            panic!("cache rejection must remain typed");
        };
        assert_eq!(
            diagnostic.status(),
            CranSnapshotCacheStatus::RevisionIncompatible
        );
    }

    #[test]
    fn base_only_online_resolution_bypasses_cache_inspection() {
        let directory = tempdir().unwrap();
        let store = SnapshotStore::open(directory.path(), cran_registry_id("https://cran.example"))
            .unwrap();
        let result = resolve_from_cran_with_store_at_policy(
            manifest_for(PackageName::new("methods").unwrap()),
            "not-a-url",
            None,
            &store,
            CranSnapshotCachePolicy::at("2026-08-23T00:00:00Z".parse().unwrap()),
        );
        assert!(
            result.is_ok(),
            "base-only resolution must bypass cache and refresh"
        );
        assert!(result.unwrap().cache_diagnostics().is_empty());
    }

    #[test]
    fn offline_invalid_current_snapshot_preserves_typed_error() {
        let root = PackageName::new("root").unwrap();
        let invalid = FailingLoader(CandidateLoadError::new(
            CandidateLoadErrorCategory::SnapshotInvalid,
            "current generation is invalid",
        ));

        let error = collect_cran_dependency_closure_from_loader(&[root], &invalid).unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::SnapshotInvalid
        );
    }

    #[test]
    fn offline_missing_current_returns_snapshot_invalid_without_fallback() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), cran_registry_id("https://cran.test")).unwrap();
        let error = resolve_from_cran_offline_with_store(
            manifest_for(PackageName::new("remote").unwrap()),
            None,
            &store,
        )
        .unwrap_err();
        let CranResolutionError::Cache(error) = error else {
            panic!("missing current must not fall back to online refresh");
        };
        assert_eq!(error.status(), CranSnapshotCacheStatus::Missing);
    }

    #[test]
    fn offline_base_package_succeeds_without_current_snapshot() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), cran_registry_id("https://cran.test")).unwrap();
        let methods = PackageName::new("methods").unwrap();
        let resolution =
            resolve_from_cran_offline_with_store(manifest_for(methods.clone()), None, &store)
                .unwrap()
                .resolution()
                .clone();

        assert!(resolution.selected(&methods).is_none());
        assert!(resolution.packages().is_empty());
    }
}
