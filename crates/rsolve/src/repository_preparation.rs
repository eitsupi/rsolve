//! Production orchestration for acquiring selected R-universe artifacts and
//! publishing the project-local source repository.
//!
//! This is an R-universe-only workflow. Resolution and repository
//! materialization remain separate implementation layers, and this module only
//! coordinates their already-defined boundaries. Non-R-universe selections
//! fail closed during acquisition rather than being silently omitted.

use std::path::Path;

use rsolve_core::Resolution;
use rsolve_repository::{
    MaterializationError, MaterializationRequest, MaterializationState, materialize,
};
use thiserror::Error;

use crate::artifact_acquisition::{
    ArtifactAcquisitionError, ArtifactAcquisitionMode, ArtifactFetcher, UreqArtifactFetcher,
    acquire_selected_artifact,
};
use crate::manifest::ComposedEnvironment;

/// A failure while preparing a project-local source repository.
#[derive(Debug, Error)]
pub enum RepositoryPreparationError {
    #[error("artifact acquisition failed for {package}: {source}")]
    Acquisition {
        package: String,
        #[source]
        source: ArtifactAcquisitionError,
    },
    #[error("repository materialization failed: {source}")]
    Materialization {
        #[source]
        source: MaterializationError,
    },
}

/// Acquire all selected package artifacts and publish them as one repository.
///
/// This production entry point uses the blocking HTTPS fetcher. Offline mode
/// still avoids network access because the acquisition layer probes the cache
/// before consulting its fetcher.
pub fn prepare_r_universe_project_repository(
    project_root: impl AsRef<Path>,
    cache_root: impl AsRef<Path>,
    resolution: &Resolution,
    composed: &ComposedEnvironment,
    mode: ArtifactAcquisitionMode,
) -> Result<MaterializationState, RepositoryPreparationError> {
    let fetcher = UreqArtifactFetcher::new();
    prepare_r_universe_project_repository_with_fetcher(
        project_root,
        cache_root,
        resolution,
        composed,
        mode,
        &fetcher,
    )
}

/// Acquire all selected package artifacts through an injected transport and
/// publish them as one repository.
///
/// Every selected package must acquire successfully before materialization is
/// started. In particular, packages without a visible R-universe source are
/// reported as an acquisition failure instead of being silently omitted.
pub fn prepare_r_universe_project_repository_with_fetcher<F: ArtifactFetcher>(
    project_root: impl AsRef<Path>,
    cache_root: impl AsRef<Path>,
    resolution: &Resolution,
    composed: &ComposedEnvironment,
    mode: ArtifactAcquisitionMode,
    fetcher: &F,
) -> Result<MaterializationState, RepositoryPreparationError> {
    let project_root = project_root.as_ref();
    let cache_root = cache_root.as_ref();
    let mut artifacts = Vec::with_capacity(resolution.packages().len());
    for selected in resolution.packages() {
        let artifact = acquire_selected_artifact(cache_root, selected, composed, mode, fetcher)
            .map_err(|source| RepositoryPreparationError::Acquisition {
                package: selected.name().to_string(),
                source,
            })?;
        artifacts.push(artifact);
    }
    materialize(MaterializationRequest::new(project_root, &artifacts))
        .map_err(|source| RepositoryPreparationError::Materialization { source })
}
