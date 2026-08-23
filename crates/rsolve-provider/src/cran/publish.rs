//! Provider-private CRAN snapshot composition and atomic publication.
// This seam is crate-visible for the provider orchestration layer while its
// parent module remains crate-private; public item visibility avoids exposing
// it through the external CRAN API.
// The seam is not called by the legacy package-refresh path yet, so retain
// dead-code checking suppression until that production path is migrated.
#![allow(dead_code)]

use std::error::Error;
use std::fmt;

use crate::snapshot::{ReadOnlySnapshotCandidateLoader, SnapshotPublishError, SnapshotStore};

use super::evidence::{
    CranEvidenceObservation, EvidenceCompositionError, SnapshotCompositionContext, compose_snapshot,
};

/// A lossless boundary error for CRAN snapshot refresh publication.
#[derive(Debug)]
pub enum CranSnapshotPublishError {
    Composition(EvidenceCompositionError),
    Publication(SnapshotPublishError),
}

impl fmt::Display for CranSnapshotPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::Composition(error) => Some(error),
            Self::Publication(error) => Some(error),
        }
    }
}

/// Compose validated CRAN evidence and atomically publish the resulting
/// generation. The returned loader is reopened only after publication lock
/// release, so resolver-facing state is always read from the committed
/// current pointer.
pub fn publish_snapshot(
    store: &SnapshotStore,
    context: SnapshotCompositionContext,
    observations: Vec<CranEvidenceObservation>,
) -> Result<ReadOnlySnapshotCandidateLoader, CranSnapshotPublishError> {
    let input =
        compose_snapshot(context, observations).map_err(CranSnapshotPublishError::Composition)?;
    store
        .build_and_publish(input)
        .map_err(CranSnapshotPublishError::Publication)
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
            Err(CranSnapshotPublishError::Publication(
                SnapshotPublishError::Build(_)
            ))
        ));
        assert_eq!(
            store.read_current().unwrap().header().generation,
            generation
        );
        assert_eq!(read_versions(&pinned), ["0.9", "1.0"]);
    }
}
