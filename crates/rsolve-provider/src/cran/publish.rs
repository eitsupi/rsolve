//! Provider-private CRAN snapshot composition and atomic publication.
// This seam is crate-visible for the provider orchestration layer while its
// parent module remains crate-private; public item visibility avoids exposing
// it through the external CRAN API.

use std::error::Error;
use std::fmt;

use crate::snapshot::CoverageV1;
use crate::snapshot::{ReadOnlySnapshotCandidateLoader, SnapshotPublishError, SnapshotStore};
use rsolve_core::{CandidateLoadError, RegistryId};

use super::evidence::{
    CranEvidenceObservation, EvidenceCompositionError, SnapshotCompositionContext, compose_snapshot,
};

/// A public category-and-diagnostic error for CRAN snapshot publication.
///
/// Composition and publication error values remain provider-private; their
/// stable diagnostic text is exposed here so callers can report failures
/// without depending on snapshot implementation details.
#[derive(Debug)]
pub enum CranSnapshotPublishError {
    Acquisition(CandidateLoadError),
    Composition(Box<str>),
    Publication(Box<str>),
}

impl fmt::Display for CranSnapshotPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acquisition(error) => {
                write!(formatter, "CRAN snapshot acquisition failed: {error}")
            }
            Self::Composition(error) => {
                write!(formatter, "CRAN snapshot composition failed: {error}")
            }
            Self::Publication(error) => {
                write!(formatter, "CRAN snapshot publication failed: {error}")
            }
        }
    }
}

impl Error for CranSnapshotPublishError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Acquisition(error) => Some(error),
            Self::Composition(_) | Self::Publication(_) => None,
        }
    }
}

pub(crate) fn default_context(registry_id: RegistryId) -> SnapshotCompositionContext {
    SnapshotCompositionContext {
        registry_id,
        compatibility_profile: 1,
        parser_schema: 1,
        normalization_policy: 1,
        created_at: jiff::Timestamp::now()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
        producer: "rsolve-provider/cran".into(),
        coverage: CoverageV1 {
            state: "partial".into(),
            scope: "requested-packages".into(),
            freshness: "current".into(),
            source_ids: Vec::new(),
            missing_evidence: Vec::new(),
        },
    }
}

/// Compose validated CRAN evidence and atomically publish one generation.
/// The returned loader pins the generation published by this operation while
/// the publication lock is held, before the lock is released. A later
/// publication may replace the store's current pointer without changing the
/// generation observed through this loader.
pub fn publish_snapshot(
    store: &SnapshotStore,
    context: SnapshotCompositionContext,
    observations: Vec<CranEvidenceObservation>,
) -> Result<ReadOnlySnapshotCandidateLoader, CranSnapshotPublishError> {
    let input =
        compose_snapshot(context, observations).map_err(|error: EvidenceCompositionError| {
            CranSnapshotPublishError::Composition(error.to_string().into_boxed_str())
        })?;
    store
        .build_and_publish(input)
        .map_err(|error: SnapshotPublishError| {
            CranSnapshotPublishError::Publication(error.to_string().into_boxed_str())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cran::evidence::tests::{context, fixture_observations};
    use crate::snapshot::SnapshotGenerationBuilder;
    use rsolve_core::{CandidateLoader, PackageName, PackageRelease, RegistryId, SolverKey};
    use tempfile::tempdir;

    fn read_versions(loader: &ReadOnlySnapshotCandidateLoader) -> Vec<String> {
        loader
            .releases(&SolverKey::InstalledName(
                PackageName::new("P3MOverlay").unwrap(),
            ))
            .unwrap()
            .into_iter()
            .map(|release| release.version().to_string())
            .collect()
    }

    fn semantic_fingerprints(loader: &ReadOnlySnapshotCandidateLoader) -> Vec<String> {
        let mut fingerprints = loader
            .releases(&SolverKey::InstalledName(
                PackageName::new("P3MOverlay").unwrap(),
            ))
            .unwrap()
            .iter()
            .map(release_fingerprint)
            .collect::<Vec<_>>();
        fingerprints.sort();
        fingerprints
    }

    fn release_fingerprint(release: &PackageRelease) -> String {
        format!(
            "identity={:?};version={:?};metadata={:?};publication={:?};dependencies={:?};distributions={:?};digest={:?}",
            release.identity(),
            release.version(),
            release.metadata().fields(),
            release.publication(),
            release.dependencies(),
            release.distributions(),
            release.metadata_digest(),
        )
    }

    #[test]
    fn publishes_composed_sources_and_reopens_the_committed_generation() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let observations = fixture_observations();
        let reference_input = compose_snapshot(context(), observations.clone()).unwrap();
        let reference_path = directory.path().join("reference.redb");
        let reference_generation = SnapshotGenerationBuilder::new(reference_input, &reference_path)
            .build()
            .unwrap();
        let reference = ReadOnlySnapshotCandidateLoader::open(
            reference_generation.path(),
            RegistryId::new("cran").unwrap(),
        )
        .unwrap();

        let loader = publish_snapshot(&store, context(), observations).unwrap();
        let reopened = store.read_current().unwrap();
        assert_eq!(read_versions(&loader), ["0.9", "1.0"]);
        assert_eq!(
            semantic_fingerprints(&reference),
            semantic_fingerprints(&loader)
        );
        assert_eq!(
            semantic_fingerprints(&reference),
            semantic_fingerprints(&reopened)
        );
    }

    #[test]
    fn same_generation_reuse_and_failed_refresh_preserve_current_and_pinned_reader() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let pinned = publish_snapshot(&store, context(), fixture_observations()).unwrap();
        let generation = pinned.header().generation.clone();

        let reused = publish_snapshot(&store, context(), fixture_observations()).unwrap();
        assert_eq!(reused.header().generation, generation);

        let mut invalid = fixture_observations();
        invalid[0].package = PackageName::new("Other").unwrap();
        assert!(matches!(
            publish_snapshot(&store, context(), invalid),
            Err(CranSnapshotPublishError::Composition(_))
        ));
        let reopened = store.read_current().unwrap();
        assert_eq!(reopened.header().generation, generation);
        assert_eq!(read_versions(&pinned), ["0.9", "1.0"]);
        assert_eq!(read_versions(&reopened), ["0.9", "1.0"]);
    }

    #[test]
    fn build_failure_does_not_replace_current_pointer() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let pinned = publish_snapshot(&store, context(), fixture_observations()).unwrap();
        let generation = pinned.header().generation.clone();
        let mut invalid_context = context();
        invalid_context.created_at = "not-a-timestamp".into();
        assert!(matches!(
            publish_snapshot(&store, invalid_context, fixture_observations()),
            Err(CranSnapshotPublishError::Publication(_))
        ));
        assert_eq!(
            store.read_current().unwrap().header().generation,
            generation
        );
        assert_eq!(read_versions(&pinned), ["0.9", "1.0"]);
    }
}
