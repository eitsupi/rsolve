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
    let refresher = CranSnapshotRefresher::new(base_url).map_err(CranResolutionError::Provider)?;
    let roots = request
        .requirements
        .iter()
        .map(|requirement| requirement.name.clone())
        .collect::<Vec<_>>();
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
