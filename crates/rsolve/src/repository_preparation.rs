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
    ArtifactAcquisitionCapability, ArtifactAcquisitionError, ArtifactAcquisitionMode,
    ArtifactFetcher, UreqArtifactFetcher, acquire_planned_artifact, preflight_selected_artifact,
};
use crate::manifest::ComposedEnvironment;

/// A failure while preparing a project-local source repository.
#[derive(Debug, Error)]
pub enum RepositoryPreparationError {
    #[error("artifact acquisition preflight failed for selected packages")]
    Preflight {
        failures: Vec<ArtifactPreflightFailure>,
    },
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

/// Context for one selected package that cannot be acquired in the requested
/// preparation mode. Keeping the original typed acquisition error allows
/// callers to inspect the precise failure while the surrounding fields make a
/// complete graph failure report actionable.
#[derive(Debug, thiserror::Error)]
#[error("{package} release {version} source {source:?} lacks {capability:?} capability: {cause}")]
pub struct ArtifactPreflightFailure {
    package: rsolve_core::PackageName,
    release: rsolve_core::ReleaseIdentity,
    version: rsolve_core::RPackageVersion,
    source: rsolve_core::Provenance,
    capability: ArtifactAcquisitionCapability,
    #[source]
    cause: ArtifactAcquisitionError,
}

impl ArtifactPreflightFailure {
    fn new(
        selected: &rsolve_core::ResolvedPackage,
        capability: ArtifactAcquisitionCapability,
        cause: ArtifactAcquisitionError,
    ) -> Self {
        Self {
            package: selected.name().clone(),
            release: selected.identity().clone(),
            version: selected.version().clone(),
            source: selected.identity().provenance().clone(),
            capability,
            cause,
        }
    }

    pub fn package(&self) -> &rsolve_core::PackageName {
        &self.package
    }

    pub fn release(&self) -> &rsolve_core::ReleaseIdentity {
        &self.release
    }

    pub fn version(&self) -> &rsolve_core::RPackageVersion {
        &self.version
    }

    pub fn source(&self) -> &rsolve_core::Provenance {
        &self.source
    }

    pub fn capability(&self) -> ArtifactAcquisitionCapability {
        self.capability
    }

    pub fn cause(&self) -> &ArtifactAcquisitionError {
        &self.cause
    }
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
/// Every selected package is preflighted before any artifact fetch or
/// materialization starts. In particular, packages without a visible
/// R-universe source are reported instead of being silently omitted.
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
    let capability = match mode {
        ArtifactAcquisitionMode::Online => ArtifactAcquisitionCapability::OnlineFetch,
        ArtifactAcquisitionMode::Offline => ArtifactAcquisitionCapability::OfflineCache,
    };
    let mut plans = Vec::with_capacity(resolution.packages().len());
    let mut failures = Vec::new();
    for selected in resolution.packages() {
        match preflight_selected_artifact(cache_root, selected, composed, mode) {
            Ok(plan) => plans.push((selected, plan)),
            Err(cause) => failures.push(ArtifactPreflightFailure::new(selected, capability, cause)),
        }
    }
    if !failures.is_empty() {
        return Err(RepositoryPreparationError::Preflight { failures });
    }

    let mut artifacts = Vec::with_capacity(plans.len());
    for (selected, plan) in plans {
        let artifact = acquire_planned_artifact(cache_root, selected, plan, mode, fetcher)
            .map_err(|source| RepositoryPreparationError::Acquisition {
                package: selected.name().to_string(),
                source,
            })?;
        artifacts.push(artifact);
    }
    materialize(MaterializationRequest::new(project_root, &artifacts))
        .map_err(|source| RepositoryPreparationError::Materialization { source })
}
