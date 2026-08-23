use super::*;

use crate::cran::catalog::CranCatalogRecordScope;
use crate::snapshot::{FreshnessStateV1, LookupStateV1, PublicationStateV1, SemanticsStateV1};
use rsolve_core::RPackageVersion;

#[test]
fn recommended_overlay_is_raw_evidence_but_never_eligible_or_distributed() {
    let mut observations = fixture_observations();
    observations[0]
        .artifact
        .as_mut()
        .unwrap()
        .checksums
        .push(ChecksumV1 {
            algorithm: "md5".into(),
            value: "root-md5".into(),
        });
    let overlay_fields = [
        ("Package", "P3MOverlay"),
        ("Version", "1.0"),
        ("Depends", "R (>= 4.7)"),
        ("MD5sum", "overlay-md5"),
        ("Path", "4.7.0/Recommended"),
    ];
    let (package, fields, artifact) = raw(
        &overlay_fields,
        "https://cran.example/src/contrib/4.7.0/Recommended/P3MOverlay_1.0.tar.gz",
    );
    observations.push(CranEvidenceObservation {
        source: source("cran-current", 3),
        package,
        record_index: 30,
        fields,
        artifact: Some(artifact),
        axes: axes(
            SemanticsStateV1::Complete,
            PublicationStateV1::Unknown,
            FreshnessStateV1::CurrentGeneration,
        ),
        release: Some(release(&overlay_fields)),
        distribution_registry: DistributionRegistryBinding::ConfiguredContext,
        scope: CranCatalogRecordScope::RecommendedOverlay {
            runtime: RPackageVersion::parse("4.7.0").unwrap(),
        },
    });

    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Present));
    assert_eq!(history.eligible_releases.len(), 2);
    let overlay = history
        .observations
        .iter()
        .find(|observation| observation.record_index == 30)
        .unwrap();
    assert_eq!(
        overlay.artifact.as_ref().unwrap().locator,
        "https://cran.example/src/contrib/4.7.0/Recommended/P3MOverlay_1.0.tar.gz"
    );
    assert!(history.decisions.iter().any(|decision| {
        matches!(
            decision.code,
            crate::snapshot::DecisionCodeV1::RecommendedOverlaySuppressed
        ) && decision.observation_ids == vec![overlay.id]
    }));
    assert!(
        history
            .eligible_releases
            .iter()
            .flat_map(|release| release.evidence.iter())
            .all(|reference| reference.observation_id != overlay.id)
    );
    let current = history
        .eligible_releases
        .iter()
        .find(|release| release.version == "1.0")
        .unwrap();
    assert!(current.metadata.iter().all(|field| {
        field.name != "Path" && field.value != "overlay-md5" && field.value != "R (>= 4.7)"
    }));
    assert!(
        current
            .metadata
            .iter()
            .any(|field| field.name == "Title" && field.value == "fixture")
    );
    assert!(current.dependencies.iter().all(|dependency| {
        dependency
            .clauses
            .iter()
            .all(|clause| clause.version != "4.7" && clause.version != "4.7.0")
    }));
    assert!(
        history
            .eligible_releases
            .iter()
            .flat_map(|release| release.distributions.iter())
            .flat_map(|distribution| distribution.artifacts.iter())
            .all(|artifact| !artifact.locator.contains("Recommended"))
    );
    assert!(
        current
            .distributions
            .iter()
            .flat_map(|distribution| distribution.artifacts.iter())
            .flat_map(|artifact| artifact.upstream_checksums.iter())
            .any(|checksum| checksum.algorithm == "md5" && checksum.value == "root-md5")
    );
}

#[test]
fn overlay_only_history_is_incomplete_without_eligible_release() {
    let fields = [
        ("Package", "OverlayOnly"),
        ("Version", "1.0"),
        ("Depends", "R (>= 4.7)"),
        ("MD5sum", "overlay-md5"),
        ("Path", "4.7.0/Recommended"),
    ];
    let (package, raw_fields, artifact) = raw(
        &fields,
        "https://cran.example/src/contrib/4.7.0/Recommended/OverlayOnly_1.0.tar.gz",
    );
    let input = compose_snapshot(
        context(),
        vec![CranEvidenceObservation {
            source: source("cran-current", 4),
            package,
            record_index: 40,
            fields: raw_fields,
            artifact: Some(artifact),
            axes: axes(
                SemanticsStateV1::Complete,
                PublicationStateV1::Unknown,
                FreshnessStateV1::CurrentGeneration,
            ),
            release: Some(release(&fields)),
            distribution_registry: DistributionRegistryBinding::ConfiguredContext,
            scope: CranCatalogRecordScope::RecommendedOverlay {
                runtime: RPackageVersion::parse("4.7.0").unwrap(),
            },
        }],
    )
    .unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "OverlayOnly")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Incomplete));
    assert!(history.eligible_releases.is_empty());
    assert_eq!(history.observations.len(), 1);
    assert!(history.decisions.iter().any(|decision| matches!(
        decision.code,
        crate::snapshot::DecisionCodeV1::RecommendedOverlaySuppressed
    )));
}
