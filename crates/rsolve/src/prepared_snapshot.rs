//! Persistent CRAN snapshot preparation before resolver execution.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, DependencyKind, PackageName,
    PublicationDate, RegistryId, SolverKey,
};
use rsolve_provider::SnapshotStore;
use rsolve_provider::cran::{
    CranCandidateSnapshot, CranMetadataConfig, CranRefreshProgressCallback, CranSnapshotRefresher,
};
use rsolve_provider::cran::{
    CranSnapshotCacheDiagnostic, CranSnapshotCachePolicy, CranSnapshotCacheResult,
    CranSnapshotCacheStatus, inspect_cran_snapshot_cache,
};
use sha2::{Digest, Sha256};

use crate::Manifest;
use crate::metrics::{Phase, Recorder, SnapshotCacheDecision};
use crate::orchestration::{
    CandidateLoaderRef, CranResolutionError, CranResolutionOutcome, MeasuredCandidateLoaderRef,
    resolve_request_with_metrics,
};
use crate::progress::{ProgressCallback, ProgressEvent};
use rsolve_resolver::{RBasePackageOverlay, ResolutionFailure, is_r_base_package_name};

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
#[cfg(test)]
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

fn collect_cran_dependency_closure_with_metrics<F>(
    roots: &[PackageName],
    mut refresh: F,
    recorder: &Recorder,
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
            recorder.measure(Phase::ClosureLookup, || {
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
                Ok::<(), CandidateLoadError>(())
            })?;
            refreshed.insert(package.clone());
        }
    }
}

#[cfg(test)]
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

fn classify_cache_decision(
    offline: bool,
    cache_applicable: bool,
    refreshed: bool,
) -> SnapshotCacheDecision {
    if !cache_applicable {
        SnapshotCacheDecision::NotApplicable
    } else if offline {
        SnapshotCacheDecision::OfflineCompatible
    } else if refreshed {
        SnapshotCacheDecision::Refreshed
    } else {
        SnapshotCacheDecision::FreshHit
    }
}

fn finalize_online_outcome(
    resolution: rsolve_core::Resolution,
    diagnostics: Vec<rsolve_provider::cran::CranRefreshDiagnostic>,
    cache_diagnostics: Vec<CranSnapshotCacheDiagnostic>,
    recorder: Recorder,
    decision: SnapshotCacheDecision,
    provider_metrics: rsolve_provider::cran::CranRefreshMetrics,
) -> CranResolutionOutcome {
    recorder.set_cache_decision(decision);
    recorder.set_provider_refresh(provider_metrics);
    CranResolutionOutcome {
        resolution,
        diagnostics,
        cache_diagnostics,
        metrics: recorder.snapshot(),
    }
}

fn cache_revision(cache: &CranSnapshotCacheResult) -> Option<Box<str>> {
    match cache {
        CranSnapshotCacheResult::Compatible { diagnostic, .. } => diagnostic
            .revision_token()
            .map(str::to_owned)
            .map(Into::into),
        CranSnapshotCacheResult::Rejected(_) => None,
    }
}

/// Shared cache decision boundary used by both production resolution and
/// deterministic orchestration tests. Refresh is invoked only when the
/// compatible generation is stale or cannot prove the requested resolution.
#[cfg(test)]
fn cache_or_refresh<L, F>(
    probe: CacheProbe<L>,
    roots: &[PackageName],
    request: &rsolve_core::ResolutionRequest,
    refresh: F,
) -> Result<(L, Vec<CranSnapshotCacheDiagnostic>), CranResolutionError>
where
    L: CandidateLoader,
    F: FnMut(&[PackageName]) -> Result<L, CranResolutionError>,
{
    cache_or_refresh_with_recorder(probe, roots, request, refresh, None)
}

fn cache_or_refresh_with_recorder<L, F>(
    probe: CacheProbe<L>,
    roots: &[PackageName],
    request: &rsolve_core::ResolutionRequest,
    mut refresh: F,
    recorder: Option<Recorder>,
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
            let result = if let Some(recorder) = &recorder {
                resolve_prepared_snapshot_without_transport_with_metrics(
                    request.clone(),
                    &loader,
                    Some(recorder.clone()),
                )
            } else {
                resolve_prepared_snapshot_without_transport(request.clone(), &loader)
            };
            match result {
                Ok(_) => return Ok((loader, vec![diagnostic])),
                Err(error) => {
                    let error = cache_resolution_error(error);
                    diagnostics.push(CranSnapshotCacheDiagnostic::closure_incomplete(&error));
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

#[cfg(test)]
fn prepare_then_refresh<L, P, F>(
    roots: &[PackageName],
    mut prepare: P,
    mut refresh: F,
) -> Result<L, CranResolutionError>
where
    P: FnMut() -> Result<(), CranResolutionError>,
    F: FnMut(&[PackageName]) -> Result<L, CranResolutionError>,
{
    prepare()?;
    refresh(roots)
}

fn cache_resolution_error(error: CranResolutionError) -> CandidateLoadError {
    match error {
        CranResolutionError::Resolution(ResolutionFailure::CandidateLoad { source, .. }) => *source,
        error => CandidateLoadError::new(
            CandidateLoadErrorCategory::MetadataInvalid,
            format!(
                "cached CRAN generation cannot satisfy the requested dependency closure: {error}"
            ),
        ),
    }
}

#[cfg(test)]
fn resolve_offline_from_cache<L: CandidateLoader>(
    request: rsolve_core::ResolutionRequest,
    probe: CacheProbe<L>,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    resolve_offline_from_cache_with_recorder(request, probe, Recorder::new())
}

fn resolve_offline_from_cache_with_recorder<L: CandidateLoader>(
    request: rsolve_core::ResolutionRequest,
    probe: CacheProbe<L>,
    recorder: Recorder,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    let (loader, diagnostic) = match probe {
        CacheProbe::Compatible { loader, diagnostic } => (loader, diagnostic),
        CacheProbe::Rejected(diagnostic) => return Err(CranResolutionError::Cache(diagnostic)),
    };
    recorder.set_cache_decision(classify_cache_decision(true, true, false));
    let resolution = resolve_prepared_snapshot_without_transport_with_metrics(
        request,
        &loader,
        Some(recorder.clone()),
    )
    .map_err(map_offline_resolution_error)?;
    Ok(CranResolutionOutcome {
        resolution,
        diagnostics: Vec::new(),
        cache_diagnostics: vec![diagnostic],
        metrics: recorder.snapshot(),
    })
}

fn map_offline_resolution_error(error: CranResolutionError) -> CranResolutionError {
    match error {
        CranResolutionError::Resolution(ResolutionFailure::CandidateLoad { source, .. }) => {
            CranResolutionError::Offline(*source)
        }
        error => error,
    }
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

pub(crate) fn resolve_from_cran_with_store_at_policy(
    manifest: Manifest,
    base_url: impl AsRef<str>,
    publication_cutoff: Option<PublicationDate>,
    store: &SnapshotStore,
    cache_policy: CranSnapshotCachePolicy,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    resolve_from_cran_with_store_at_policy_with_progress(
        manifest,
        base_url,
        publication_cutoff,
        store,
        cache_policy,
        None,
    )
}

pub(crate) fn resolve_from_cran_with_store_at_policy_with_progress(
    manifest: Manifest,
    base_url: impl AsRef<str>,
    publication_cutoff: Option<PublicationDate>,
    store: &SnapshotStore,
    cache_policy: CranSnapshotCachePolicy,
    progress: Option<ProgressCallback>,
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
        emit_progress(&progress, ProgressEvent::ResolveStarted);
        let recorder = Recorder::new();
        recorder.set_cache_decision(classify_cache_decision(false, false, false));
        let resolution = resolve_prepared_snapshot_without_transport_with_metrics(
            request,
            &CranCandidateSnapshot::default(),
            Some(recorder.clone()),
        )?;
        emit_progress(
            &progress,
            ProgressEvent::ResolveCompleted {
                packages: resolution.packages().len(),
            },
        );
        return Ok(CranResolutionOutcome {
            resolution,
            diagnostics: Vec::new(),
            cache_diagnostics: Vec::new(),
            metrics: recorder.snapshot(),
        });
    }
    let metadata_config =
        CranMetadataConfig::for_repository(base_url.as_ref().to_owned().into_boxed_str());
    let metadata_config = if publication_cutoff.is_some() {
        metadata_config.without_allpackages_history()
    } else {
        metadata_config
    };
    let metadata_config = if cache_policy.refresh_metadata {
        metadata_config.with_refresh_metadata()
    } else {
        metadata_config
    };
    let provider_progress = progress.as_ref().map(|progress| {
        let progress = Rc::clone(progress);
        Rc::new(move |event| progress(ProgressEvent::Cran(event))) as CranRefreshProgressCallback
    });
    let refresher = CranSnapshotRefresher::new_with_progress(metadata_config, provider_progress)
        .map_err(CranResolutionError::Provider)?;
    let cache_policy = cache_policy
        .with_expected_endpoint(refresher.canonical_endpoint())
        .with_allowed_auxiliary_endpoint(refresher.allpackages_feed_endpoint());
    // Capture the provider-owned validation observation before attempting the
    // non-blocking cache probe. The same observation is consumed by the
    // transaction if this request has to wait for another refresh.
    let recorder = Recorder::new();
    let preflight = recorder.measure(Phase::SnapshotCacheDecision, || {
        refresher.preflight_refresh(store, &cache_policy)
    });
    // Keep the warm, complete-cache path entirely loader-only. Acquiring the
    // persistent refresh transaction here would add lock/raw-cache work to
    // every online invocation even when no metadata refresh is necessary.
    if !cache_policy.refresh_metadata
        && let Some(CranSnapshotCacheResult::Compatible { loader, diagnostic }) =
            preflight.cache_result()
        && diagnostic.status() == CranSnapshotCacheStatus::Fresh
    {
        emit_progress(&progress, ProgressEvent::ResolveStarted);
        if let Ok(resolution) = resolve_prepared_snapshot_without_transport_with_metrics(
            request.clone(),
            loader.as_ref(),
            Some(recorder.clone()),
        ) {
            emit_progress(
                &progress,
                ProgressEvent::ResolveCompleted {
                    packages: resolution.packages().len(),
                },
            );
            return Ok(finalize_online_outcome(
                resolution,
                Vec::new(),
                vec![diagnostic.clone()],
                recorder,
                classify_cache_decision(false, true, false),
                refresher.metrics(),
            ));
        }
    }
    // Hold the refresh lock through closure discovery, metadata acquisition,
    // composition and publication. Waiters re-read after lock handoff.
    let transaction = recorder
        .measure(Phase::SnapshotCacheDecision, || {
            refresher.begin_persistent_refresh(preflight)
        })
        .map_err(CranResolutionError::Publish)?;
    let mut locked_policy = cache_policy.clone();
    locked_policy.refresh_metadata = false;
    let locked_cache = recorder.measure(Phase::SnapshotCacheDecision, || {
        transaction.inspect_cache(&locked_policy)
    });
    let locked_revision = cache_revision(&locked_cache);
    let forced_refresh_satisfied = cache_policy.refresh_metadata
        && transaction.refresh_completed_while_waiting(locked_revision.as_deref());
    let probe = if cache_policy.refresh_metadata && !forced_refresh_satisfied {
        match locked_cache {
            CranSnapshotCacheResult::Compatible { diagnostic, .. } => {
                CacheProbe::Rejected(diagnostic)
            }
            CranSnapshotCacheResult::Rejected(diagnostic) => CacheProbe::Rejected(diagnostic),
        }
    } else {
        match locked_cache {
            CranSnapshotCacheResult::Compatible { loader, diagnostic } => CacheProbe::Compatible {
                loader: *loader,
                diagnostic,
            },
            CranSnapshotCacheResult::Rejected(diagnostic) => CacheProbe::Rejected(diagnostic),
        }
    };
    let refreshed = Cell::new(false);
    let (loader, cache_diagnostics) = cache_or_refresh_with_recorder(
        probe,
        &roots,
        &request,
        |batch| {
            refreshed.set(true);
            let closure = collect_cran_dependency_closure_with_metrics(
                batch,
                |batch| {
                    recorder.measure(Phase::RefreshAcquisition, || {
                        transaction.refresh_packages(batch)
                    })
                },
                &recorder,
            )
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
            recorder
                .measure(Phase::SnapshotCompositionAndPublication, || {
                    transaction.refresh_and_publish_snapshot(&closure)
                })
                .map_err(CranResolutionError::Publish)
        },
        Some(recorder.clone()),
    )?;
    drop(transaction);
    emit_progress(&progress, ProgressEvent::ResolveStarted);
    let resolution = resolve_prepared_snapshot_without_transport_with_metrics(
        request,
        &loader,
        Some(recorder.clone()),
    )?;
    emit_progress(
        &progress,
        ProgressEvent::ResolveCompleted {
            packages: resolution.packages().len(),
        },
    );
    Ok(finalize_online_outcome(
        resolution,
        refresher.diagnostics(),
        cache_diagnostics,
        recorder,
        classify_cache_decision(false, true, refreshed.get()),
        refresher.metrics(),
    ))
}

fn emit_progress(progress: &Option<ProgressCallback>, event: ProgressEvent) {
    if let Some(progress) = progress {
        progress(event);
    }
}

/// Resolve through the configured current generation without creating a
/// provider refresher. This is the explicit offline policy boundary.
#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn resolve_from_cran_offline_with_store_at_policy(
    manifest: Manifest,
    publication_cutoff: Option<PublicationDate>,
    store: &SnapshotStore,
    cache_policy: CranSnapshotCachePolicy,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    resolve_from_cran_offline_with_store_at_policy_with_progress(
        manifest,
        publication_cutoff,
        store,
        cache_policy,
        None,
    )
}

pub(crate) fn resolve_from_cran_offline_with_store_at_policy_with_progress(
    manifest: Manifest,
    publication_cutoff: Option<PublicationDate>,
    store: &SnapshotStore,
    cache_policy: CranSnapshotCachePolicy,
    progress: Option<ProgressCallback>,
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
        emit_progress(&progress, ProgressEvent::ResolveStarted);
        let recorder = Recorder::new();
        recorder.set_cache_decision(classify_cache_decision(false, false, false));
        let resolution = resolve_prepared_snapshot_without_transport_with_metrics(
            request,
            &CranCandidateSnapshot::default(),
            Some(recorder.clone()),
        )?;
        emit_progress(
            &progress,
            ProgressEvent::ResolveCompleted {
                packages: resolution.packages().len(),
            },
        );
        return Ok(CranResolutionOutcome {
            resolution,
            diagnostics: Vec::new(),
            cache_diagnostics: Vec::new(),
            metrics: recorder.snapshot(),
        });
    }
    let recorder = Recorder::new();
    let cache = recorder.measure(Phase::SnapshotCacheDecision, || {
        inspect_cran_snapshot_cache(store, &cache_policy)
    });
    let probe = match cache {
        CranSnapshotCacheResult::Compatible { loader, diagnostic } => CacheProbe::Compatible {
            loader: *loader,
            diagnostic,
        },
        CranSnapshotCacheResult::Rejected(diagnostic) => CacheProbe::Rejected(diagnostic),
    };
    emit_progress(&progress, ProgressEvent::ResolveStarted);
    let result = resolve_offline_from_cache_with_recorder(request, probe, recorder);
    if let Ok(outcome) = &result {
        emit_progress(
            &progress,
            ProgressEvent::ResolveCompleted {
                packages: outcome.resolution().packages().len(),
            },
        );
    }
    result
}

/// Solve only through the already prepared loader; no refresh callback is
/// available on this path, so resolver traversal cannot perform transport.
fn resolve_prepared_snapshot_without_transport(
    request: rsolve_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
) -> Result<rsolve_core::Resolution, CranResolutionError> {
    resolve_prepared_snapshot_without_transport_with_metrics(request, loader, None)
}

fn resolve_prepared_snapshot_without_transport_with_metrics(
    request: rsolve_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
    metrics: Option<Recorder>,
) -> Result<rsolve_core::Resolution, CranResolutionError> {
    if let Some(metrics) = metrics {
        let measured = MeasuredCandidateLoaderRef {
            loader,
            metrics: metrics.clone(),
        };
        let overlay = RBasePackageOverlay::new(
            CandidateLoaderRef(&measured),
            request.target.r_version.clone(),
        )
        .map_err(CranResolutionError::Refresh)?;
        resolve_request_with_metrics(request, &overlay, Some(metrics))
    } else {
        let overlay =
            RBasePackageOverlay::new(CandidateLoaderRef(loader), request.target.r_version.clone())
                .map_err(CranResolutionError::Refresh)?;
        resolve_request_with_metrics(request, &overlay, None)
    }
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

    fn release_at_version_with_dependencies(
        name: &PackageName,
        version: &str,
        dependencies: Vec<DependencyRequirement>,
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

    struct FlakyLoader {
        snapshot: CranCandidateSnapshot,
        fail_first_lookup: Cell<bool>,
    }

    impl CandidateLoader for FlakyLoader {
        fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            if self.fail_first_lookup.replace(false) {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    "synthetic first lookup failure",
                ));
            }
            self.snapshot.releases(package)
        }
    }

    #[test]
    fn measured_cached_retry_accumulates_after_initial_failed_solve() {
        let root = PackageName::new("root").unwrap();
        let snapshot = CranCandidateSnapshot::from_candidates([(
            root.clone(),
            vec![release_with_dependencies(&root, Vec::new())],
        )]);
        let loader = FlakyLoader {
            snapshot,
            fail_first_lookup: Cell::new(true),
        };
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
        let recorder = Recorder::new();
        assert!(
            resolve_prepared_snapshot_without_transport_with_metrics(
                request.clone(),
                &loader,
                Some(recorder.clone()),
            )
            .is_err()
        );
        let first = recorder.snapshot();
        let mut refreshes = 0;
        let (reused, _) = cache_or_refresh_with_recorder(
            CacheProbe::Compatible {
                loader,
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Fresh, Some(1)),
            },
            std::slice::from_ref(&root),
            &request,
            |_| {
                refreshes += 1;
                unreachable!("cached retry should succeed without refresh")
            },
            Some(recorder.clone()),
        )
        .unwrap();
        assert!(reused.snapshot.contains_package(&root));
        assert_eq!(refreshes, 0);
        let second = recorder.snapshot();
        assert!(second.phases.solve_ns.is_some());
        assert!(second.loader_lookup_calls > first.loader_lookup_calls);
        assert!(second.loader_unique_package_count >= first.loader_unique_package_count);
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
    fn cache_decision_classification_preserves_all_operation_paths() {
        assert_eq!(
            classify_cache_decision(false, false, false),
            SnapshotCacheDecision::NotApplicable
        );
        assert_eq!(
            classify_cache_decision(false, true, false),
            SnapshotCacheDecision::FreshHit
        );
        assert_eq!(
            classify_cache_decision(false, true, true),
            SnapshotCacheDecision::Refreshed
        );
        assert_eq!(
            classify_cache_decision(true, true, false),
            SnapshotCacheDecision::OfflineCompatible
        );
    }

    #[test]
    fn online_finalize_preserves_provider_metrics_for_both_cache_branches() {
        let root = PackageName::new("root").unwrap();
        let loader = CranCandidateSnapshot::from_candidates([(
            root.clone(),
            vec![release_with_dependencies(&root, Vec::new())],
        )]);
        let request = crate::manifest::compose_resolution_request(manifest_for(root)).unwrap();
        let resolution = resolve_prepared_snapshot_without_transport(request, &loader).unwrap();

        let fresh_recorder = Recorder::new();
        fresh_recorder.record_duration(Phase::Solve, std::time::Duration::ZERO);
        let fresh = finalize_online_outcome(
            resolution.clone(),
            Vec::new(),
            Vec::new(),
            fresh_recorder,
            SnapshotCacheDecision::FreshHit,
            rsolve_provider::cran::CranRefreshMetrics::default(),
        );
        assert_eq!(
            fresh.metrics().snapshot_cache_decision,
            Some(SnapshotCacheDecision::FreshHit)
        );
        assert!(fresh.metrics().phases.solve_ns.is_some());
        assert!(fresh.metrics().phases.refresh_acquisition_ns.is_none());
        assert_eq!(fresh.metrics().provider_refresh, Some(Default::default()));

        let refreshed_recorder = Recorder::new();
        refreshed_recorder.record_duration(Phase::RefreshAcquisition, std::time::Duration::ZERO);
        let provider_metrics = rsolve_provider::cran::CranRefreshMetrics {
            http_attempts: 2,
            ..Default::default()
        };
        let refreshed = finalize_online_outcome(
            resolution,
            Vec::new(),
            Vec::new(),
            refreshed_recorder,
            SnapshotCacheDecision::Refreshed,
            provider_metrics.clone(),
        );
        assert_eq!(
            refreshed.metrics().snapshot_cache_decision,
            Some(SnapshotCacheDecision::Refreshed)
        );
        assert!(refreshed.metrics().phases.refresh_acquisition_ns.is_some());
        assert_eq!(refreshed.metrics().provider_refresh, Some(provider_metrics));
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
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
        let mut refreshes = 0;
        let (reused, diagnostics) = cache_or_refresh(
            CacheProbe::Compatible {
                loader,
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Fresh, Some(30)),
            },
            std::slice::from_ref(&root),
            &request,
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
    fn persistent_refresh_preparation_precedes_package_refresh() {
        let root = PackageName::new("root").unwrap();
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let prepare_events = std::rc::Rc::clone(&events);
        let refresh_events = std::rc::Rc::clone(&events);
        prepare_then_refresh(
            std::slice::from_ref(&root),
            || {
                prepare_events.borrow_mut().push("prepare");
                Ok(())
            },
            |_| {
                refresh_events.borrow_mut().push("refresh_packages");
                Ok::<_, CranResolutionError>(())
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), ["prepare", "refresh_packages"]);
    }

    #[test]
    fn fresh_generation_reuse_skips_persistent_refresh_preparation() {
        let root = PackageName::new("root").unwrap();
        let loader = CranCandidateSnapshot::from_candidates([(
            root.clone(),
            vec![release_with_dependencies(&root, Vec::new())],
        )]);
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
        let mut preparations = 0;
        cache_or_refresh(
            CacheProbe::Compatible {
                loader,
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Fresh, Some(30)),
            },
            std::slice::from_ref(&root),
            &request,
            |_| {
                preparations += 1;
                unreachable!("fresh generation reuse must not prepare a refresh");
            },
        )
        .unwrap();
        assert_eq!(preparations, 0);
    }

    #[test]
    fn fresh_cache_reuse_ignores_missing_dependency_of_unselected_legacy_candidate() {
        let root = PackageName::new("root").unwrap();
        let legacy_dependency = PackageName::new("legacydep").unwrap();
        let current = release_at_version_with_dependencies(&root, "2.0.0", Vec::new());
        let legacy = release_at_version_with_dependencies(
            &root,
            "1.0.0",
            vec![required_dependency(
                DependencyKind::Imports,
                &legacy_dependency,
            )],
        );
        let loader =
            CranCandidateSnapshot::from_candidates([(root.clone(), vec![legacy, current])]);
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
        let mut refreshes = 0;
        let (reused, diagnostics) = cache_or_refresh(
            CacheProbe::Compatible {
                loader,
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Fresh, Some(30)),
            },
            std::slice::from_ref(&root),
            &request,
            |_| {
                refreshes += 1;
                unreachable!("fresh selectable cache must not refresh");
            },
        )
        .unwrap();
        assert_eq!(refreshes, 0);
        assert_eq!(diagnostics[0].status(), CranSnapshotCacheStatus::Fresh);
        let resolution = resolve_prepared_snapshot_without_transport(request, &reused).unwrap();
        assert_eq!(
            resolution.selected(&root).unwrap().version().as_str(),
            "2.0.0"
        );
    }

    #[test]
    fn offline_cache_with_only_missing_dependency_returns_typed_failure() {
        let root = PackageName::new("root").unwrap();
        let missing = PackageName::new("missing").unwrap();
        let root_release = release_at_version_with_dependencies(
            &root,
            "1.0.0",
            vec![required_dependency(DependencyKind::Imports, &missing)],
        );
        let loader = CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release])]);
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
        let error = resolve_offline_from_cache(
            request,
            CacheProbe::Compatible {
                loader,
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Fresh, Some(30)),
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CranResolutionError::Offline(source)
                if source.category() == CandidateLoadErrorCategory::NotFound
        ));
    }

    #[test]
    fn offline_missing_root_and_corrupt_snapshot_keep_typed_failures() {
        let root = PackageName::new("root").unwrap();
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
        let missing = resolve_offline_from_cache(
            request.clone(),
            CacheProbe::Compatible {
                loader: CranCandidateSnapshot::default(),
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Fresh, Some(30)),
            },
        )
        .unwrap_err();
        assert!(matches!(
            missing,
            CranResolutionError::Offline(source)
                if source.category() == CandidateLoadErrorCategory::NotFound
        ));

        let corrupt = FailingLoader(CandidateLoadError::new(
            CandidateLoadErrorCategory::SnapshotInvalid,
            "corrupt current snapshot",
        ));
        let error = resolve_offline_from_cache(
            request,
            CacheProbe::Compatible {
                loader: corrupt,
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Fresh, Some(30)),
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CranResolutionError::Offline(source)
                if source.category() == CandidateLoadErrorCategory::SnapshotInvalid
        ));
    }

    #[test]
    fn stale_or_incomplete_cache_refreshes_once() {
        let root = PackageName::new("root").unwrap();
        let complete = CranCandidateSnapshot::from_candidates([(
            root.clone(),
            vec![release_with_dependencies(&root, Vec::new())],
        )]);
        let request =
            crate::manifest::compose_resolution_request(manifest_for(root.clone())).unwrap();
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
            let (_, diagnostics) =
                cache_or_refresh(probe, std::slice::from_ref(&root), &request, |_| {
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
            CacheProbe::Compatible {
                loader,
                diagnostic: cache_diagnostic(CranSnapshotCacheStatus::Stale, Some(7200)),
            },
        )
        .unwrap();
        assert_eq!(outcome.cache_diagnostics()[0].age_seconds(), Some(7200));
        assert_eq!(
            outcome.metrics().snapshot_cache_decision,
            Some(SnapshotCacheDecision::OfflineCompatible)
        );
        assert!(outcome.metrics().phases.solve_ns.is_some());
        assert!(outcome.metrics().phases.refresh_acquisition_ns.is_none());
        assert!(outcome.metrics().provider_refresh.is_none());
        assert!(outcome.metrics().loader_lookup_calls > 0);
        assert_eq!(
            outcome.cache_diagnostics()[0]
                .endpoints()
                .collect::<Vec<_>>(),
            vec!["https://cran.example/src/contrib/PACKAGES"]
        );
        let request = crate::manifest::compose_resolution_request(manifest_for(root)).unwrap();
        let error = resolve_offline_from_cache(
            request,
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
        let outcome = result.unwrap();
        assert!(outcome.cache_diagnostics().is_empty());
        assert_eq!(
            outcome.metrics().snapshot_cache_decision,
            Some(SnapshotCacheDecision::NotApplicable)
        );
        assert!(outcome.metrics().phases.solve_ns.is_some());
        assert!(
            outcome
                .metrics()
                .phases
                .snapshot_cache_decision_ns
                .is_none()
        );
    }

    #[test]
    fn base_only_online_progress_skips_cran_refresh() {
        let directory = tempdir().unwrap();
        let store = SnapshotStore::open(directory.path(), cran_registry_id("https://cran.example"))
            .unwrap();
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let capture = std::rc::Rc::clone(&events);
        let callback = std::rc::Rc::new(move |event| capture.borrow_mut().push(event));
        let methods = PackageName::new("methods").unwrap();
        resolve_from_cran_with_store_at_policy_with_progress(
            manifest_for(methods),
            "not-a-url",
            None,
            &store,
            CranSnapshotCachePolicy::at("2026-08-23T00:00:00Z".parse().unwrap()),
            Some(callback),
        )
        .unwrap();
        assert_eq!(
            *events.borrow(),
            [
                ProgressEvent::ResolveStarted,
                ProgressEvent::ResolveCompleted { packages: 0 }
            ]
        );
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

    #[test]
    fn offline_progress_reports_resolution_start_and_completion() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), cran_registry_id("https://cran.test")).unwrap();
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let capture = std::rc::Rc::clone(&events);
        let callback = std::rc::Rc::new(move |event| capture.borrow_mut().push(event));
        let methods = PackageName::new("methods").unwrap();
        resolve_from_cran_offline_with_store_at_policy_with_progress(
            manifest_for(methods),
            None,
            &store,
            CranSnapshotCachePolicy::default(),
            Some(callback),
        )
        .unwrap();
        assert_eq!(
            *events.borrow(),
            [
                ProgressEvent::ResolveStarted,
                ProgressEvent::ResolveCompleted { packages: 0 }
            ]
        );
    }
}
