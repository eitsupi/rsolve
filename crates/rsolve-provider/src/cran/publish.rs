//! Provider-private CRAN snapshot composition and atomic publication.
// This seam is crate-visible for the provider orchestration layer while its
// parent module remains crate-private; public item visibility avoids exposing
// it through the external CRAN API.

use std::error::Error;
use std::fmt;

use super::provider::{CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA};
use crate::snapshot::CoverageV1;
#[cfg(test)]
use crate::snapshot::SnapshotStore;
use crate::snapshot::{
    ReadOnlySnapshotCandidateLoader, SnapshotPublishError, SnapshotRefreshGuard,
};
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
        compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
        parser_schema: CRAN_PARSER_SCHEMA,
        normalization_policy: CRAN_NORMALIZATION_POLICY,
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
#[cfg(test)]
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
pub(crate) fn publish_snapshot_with_endpoint(
    store: &SnapshotStore,
    context: SnapshotCompositionContext,
    observations: Vec<CranEvidenceObservation>,
    effective_endpoint: impl AsRef<str>,
) -> Result<ReadOnlySnapshotCandidateLoader, CranSnapshotPublishError> {
    let input =
        compose_snapshot(context, observations).map_err(|error: EvidenceCompositionError| {
            CranSnapshotPublishError::Composition(error.to_string().into_boxed_str())
        })?;
    store
        .build_and_publish_with_endpoint(input, effective_endpoint.as_ref())
        .map_err(|error: SnapshotPublishError| {
            CranSnapshotPublishError::Publication(error.to_string().into_boxed_str())
        })
}

pub(crate) fn publish_snapshot_with_endpoint_and_refresh_guard(
    guard: &SnapshotRefreshGuard<'_>,
    context: SnapshotCompositionContext,
    observations: Vec<CranEvidenceObservation>,
    effective_endpoint: impl AsRef<str>,
) -> Result<ReadOnlySnapshotCandidateLoader, CranSnapshotPublishError> {
    let input =
        compose_snapshot(context, observations).map_err(|error: EvidenceCompositionError| {
            CranSnapshotPublishError::Composition(error.to_string().into_boxed_str())
        })?;
    guard
        .store()
        .build_and_publish_with_refresh_guard(guard, input, effective_endpoint.as_ref())
        .map_err(|error: SnapshotPublishError| {
            CranSnapshotPublishError::Publication(error.to_string().into_boxed_str())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cran::evidence::tests::{context, fixture_observations};
    use crate::cran::{
        CranSnapshotCachePolicy, CranSnapshotCacheResult, CranSnapshotCacheStatus,
        inspect_cran_snapshot_cache,
    };
    use crate::snapshot::SnapshotGenerationBuilder;
    use rsolve_core::{CandidateLoader, PackageName, PackageRelease, RegistryId, SolverKey};
    use tempfile::tempdir;

    fn observations_from_endpoint(endpoint: &str) -> Vec<CranEvidenceObservation> {
        let mut observations = fixture_observations();
        for observation in &mut observations {
            observation.source.endpoint = format!("{endpoint}/PACKAGES");
        }
        observations
    }

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

    #[test]
    fn cache_policy_reuses_fresh_generation_and_rejects_stale_or_incompatible() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let mut current_context = context();
        current_context.created_at = jiff::Timestamp::now()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        publish_snapshot_with_endpoint(
            &store,
            current_context,
            fixture_observations(),
            "https://cran.example",
        )
        .unwrap();

        let fresh = CranSnapshotCachePolicy::default();
        let CranSnapshotCacheResult::Compatible { diagnostic, .. } =
            inspect_cran_snapshot_cache(&store, &fresh)
        else {
            panic!("expected compatible generation");
        };
        assert_eq!(diagnostic.status(), CranSnapshotCacheStatus::Fresh);
        assert!(diagnostic.age_seconds().unwrap() < 60);

        let stale = CranSnapshotCachePolicy::at(
            fresh
                .now
                .checked_add(jiff::SignedDuration::from_secs(26 * 60 * 60))
                .unwrap(),
        );
        let CranSnapshotCacheResult::Compatible { diagnostic, .. } =
            inspect_cran_snapshot_cache(&store, &stale)
        else {
            panic!("stale compatible generation should remain usable");
        };
        assert_eq!(diagnostic.status(), CranSnapshotCacheStatus::Stale);

        let mut incompatible = stale.clone();
        incompatible.parser_schema = 2;
        let CranSnapshotCacheResult::Rejected(diagnostic) =
            inspect_cran_snapshot_cache(&store, &incompatible)
        else {
            panic!("revision mismatch must reject reuse");
        };
        assert_eq!(
            diagnostic.status(),
            CranSnapshotCacheStatus::RevisionIncompatible
        );

        let mut normalization_mismatch = stale;
        normalization_mismatch.normalization_policy = 1;
        let CranSnapshotCacheResult::Rejected(diagnostic) =
            inspect_cran_snapshot_cache(&store, &normalization_mismatch)
        else {
            panic!("normalization policy mismatch must reject reuse");
        };
        assert_eq!(
            diagnostic.status(),
            CranSnapshotCacheStatus::RevisionIncompatible
        );
    }

    #[test]
    fn identical_refresh_advances_validation_without_mutating_generation_bytes() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let t0 = "2026-08-23T00:00:00Z";
        let t2 = "2026-08-24T02:00:00Z";
        let mut first_context = context();
        first_context.created_at = t0.into();
        let first = publish_snapshot_with_endpoint(
            &store,
            first_context,
            observations_from_endpoint("https://mirror-a.example"),
            "https://mirror-a.example",
        )
        .unwrap();
        let generation = first.header().generation.to_owned();
        let generation_path = directory
            .path()
            .join("generations")
            .join(format!("{generation}.redb"));
        let before = std::fs::read(&generation_path).unwrap();
        let stale = crate::cran::CranSnapshotCachePolicy::at(t2.parse().unwrap());
        assert!(matches!(
            crate::cran::inspect_cran_snapshot_cache(&store, &stale),
            crate::cran::CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == crate::cran::CranSnapshotCacheStatus::Stale
        ));
        let mut second_context = context();
        second_context.created_at = t2.into();
        let second = publish_snapshot_with_endpoint(
            &store,
            second_context,
            observations_from_endpoint("https://mirror-a.example"),
            "https://mirror-a.example",
        )
        .unwrap();
        assert_eq!(second.header().generation, generation);
        assert_eq!(std::fs::read(&generation_path).unwrap(), before);
        let crate::cran::CranSnapshotCacheResult::Compatible { diagnostic, .. } =
            crate::cran::inspect_cran_snapshot_cache(
                &store,
                &crate::cran::CranSnapshotCachePolicy::at(t2.parse().unwrap()),
            )
        else {
            panic!("identical successful refresh should validate current content");
        };
        assert_eq!(
            diagnostic.status(),
            crate::cran::CranSnapshotCacheStatus::Fresh
        );
        let expected_a = crate::cran::CranSnapshotCachePolicy::at(t2.parse().unwrap())
            .with_expected_endpoint("https://mirror-a.example");
        let expected_b = crate::cran::CranSnapshotCachePolicy::at(t2.parse().unwrap())
            .with_expected_endpoint("https://mirror-b.example");
        assert!(matches!(
            crate::cran::inspect_cran_snapshot_cache(&store, &expected_a),
            crate::cran::CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == crate::cran::CranSnapshotCacheStatus::Fresh
        ));
        assert!(matches!(
            crate::cran::inspect_cran_snapshot_cache(&store, &expected_b),
            crate::cran::CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == crate::cran::CranSnapshotCacheStatus::Stale
        ));

        let validation_path = directory.path().join("current-validation");
        let read_validation = || -> crate::snapshot::CurrentValidationV2 {
            serde_json::from_slice(&std::fs::read(&validation_path).unwrap()).unwrap()
        };
        let write_validation = |validation: &crate::snapshot::CurrentValidationV2| {
            std::fs::write(&validation_path, serde_json::to_vec(validation).unwrap()).unwrap();
        };
        let mut validation = read_validation();
        validation.effective_endpoint = "https://other.example".into();
        write_validation(&validation);
        let mismatched = crate::cran::inspect_cran_snapshot_cache(
            &store,
            &crate::cran::CranSnapshotCachePolicy::at(t2.parse().unwrap())
                .with_expected_endpoint("https://configured.example"),
        );
        assert!(matches!(
            mismatched,
            crate::cran::CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == crate::cran::CranSnapshotCacheStatus::Stale
        ));
        let mut validation = read_validation();
        validation.generation = "0".repeat(64);
        write_validation(&validation);
        assert!(matches!(
            crate::cran::inspect_cran_snapshot_cache(&store, &expected_a),
            crate::cran::CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == crate::cran::CranSnapshotCacheStatus::Stale
        ));
        let mut validation = read_validation();
        validation.compatibility_profile = 2;
        write_validation(&validation);
        assert!(matches!(
            crate::cran::inspect_cran_snapshot_cache(&store, &expected_a),
            crate::cran::CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == crate::cran::CranSnapshotCacheStatus::Stale
        ));
        let mut validation = read_validation();
        validation.sources[0].content_sha256 = "0".repeat(64);
        validation.sources[0].id = "0".repeat(64);
        write_validation(&validation);
        assert!(matches!(
            crate::cran::inspect_cran_snapshot_cache(&store, &expected_a),
            crate::cran::CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == crate::cran::CranSnapshotCacheStatus::Stale
        ));
        std::fs::write(&validation_path, b"{").unwrap();
        let malformed = crate::cran::inspect_cran_snapshot_cache(&store, &stale);
        assert!(matches!(
            malformed,
            crate::cran::CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == crate::cran::CranSnapshotCacheStatus::Stale
        ));
    }

    #[test]
    fn online_endpoint_provenance_blocks_recent_evidence_from_another_mirror() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let mut context = context();
        context.created_at = "2026-08-23T00:00:00Z".into();
        publish_snapshot_with_endpoint(
            &store,
            context,
            observations_from_endpoint("https://cran-history.example"),
            "https://cran-history.example",
        )
        .unwrap();
        let at_thirty_seconds = |endpoint: &str| {
            CranSnapshotCachePolicy::at("2026-08-23T00:00:30Z".parse().unwrap())
                .with_expected_endpoint(endpoint)
        };
        let CranSnapshotCacheResult::Compatible { diagnostic, .. } =
            inspect_cran_snapshot_cache(&store, &at_thirty_seconds("https://cran-history.example"))
        else {
            panic!("expected compatible generation");
        };
        assert_eq!(diagnostic.status(), CranSnapshotCacheStatus::Fresh);
        let CranSnapshotCacheResult::Compatible { diagnostic, .. } =
            inspect_cran_snapshot_cache(&store, &at_thirty_seconds("https://other.example"))
        else {
            panic!("expected compatible generation");
        };
        assert_eq!(diagnostic.status(), CranSnapshotCacheStatus::Stale);
        assert!(
            diagnostic
                .diagnostic()
                .contains("different acquisition endpoint")
        );
    }

    #[test]
    fn configured_repository_allows_only_bound_allpackages_auxiliary_feed() {
        let custom_feed = "https://feed.example/custom-ALLPACKAGES.zst";
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let mut observations = fixture_observations();
        for (index, observation) in observations.iter_mut().enumerate() {
            observation.source.endpoint = if index == 0 {
                "https://mirror.example/PACKAGES.rds".into()
            } else {
                custom_feed.into()
            };
        }
        publish_snapshot_with_endpoint(&store, context(), observations, "https://mirror.example")
            .unwrap();
        let with_feed_binding =
            CranSnapshotCachePolicy::at("2026-08-23T00:00:30Z".parse().unwrap())
                .with_expected_endpoint("https://mirror.example")
                .with_allowed_auxiliary_endpoint(custom_feed);
        assert!(matches!(
            inspect_cran_snapshot_cache(&store, &with_feed_binding),
            CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == CranSnapshotCacheStatus::Fresh
        ));
        let without_feed_binding =
            CranSnapshotCachePolicy::at("2026-08-23T00:00:30Z".parse().unwrap())
                .with_expected_endpoint("https://mirror.example");
        assert!(matches!(
            inspect_cran_snapshot_cache(&store, &without_feed_binding),
            CranSnapshotCacheResult::Compatible { diagnostic, .. }
                if diagnostic.status() == CranSnapshotCacheStatus::Stale
        ));
    }

    #[test]
    fn identical_cross_mirror_validation_reuses_generation_without_extending_header_provenance() {
        let directory = tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let t0 = "2026-08-23T00:00:00Z";
        let t2 = "2026-08-23T02:00:00Z";
        let mut first_context = context();
        first_context.created_at = t0.into();
        let first = publish_snapshot_with_endpoint(
            &store,
            first_context,
            observations_from_endpoint("https://mirror-a.example"),
            "https://mirror-a.example",
        )
        .unwrap();
        let generation = first.header().generation.to_owned();
        let generation_path = directory
            .path()
            .join("generations")
            .join(format!("{generation}.redb"));
        let before = std::fs::read(&generation_path).unwrap();

        let mut second_context = context();
        second_context.created_at = t2.into();
        let second = publish_snapshot_with_endpoint(
            &store,
            second_context,
            observations_from_endpoint("https://mirror-b.example"),
            "https://mirror-b.example",
        )
        .unwrap();
        assert_eq!(second.header().generation, generation);
        assert_eq!(std::fs::read(&generation_path).unwrap(), before);

        let expected_b = CranSnapshotCachePolicy::at(t2.parse().unwrap())
            .with_expected_endpoint("https://mirror-b.example");
        let CranSnapshotCacheResult::Compatible { loader, diagnostic } =
            inspect_cran_snapshot_cache(&store, &expected_b)
        else {
            panic!("identical cross-mirror refresh should retain a compatible generation");
        };
        assert_eq!(diagnostic.status(), CranSnapshotCacheStatus::Fresh);
        assert!(
            diagnostic
                .endpoints()
                .all(|endpoint| endpoint.contains("mirror-b.example"))
        );
        assert!(
            loader
                .header()
                .sources
                .iter()
                .all(|source| source.endpoint.contains("mirror-a.example"))
        );
    }
}
