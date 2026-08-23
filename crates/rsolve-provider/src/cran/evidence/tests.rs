use super::*;
use crate::snapshot::{
    ChecksumV1, CoverageV1, FreshnessStateV1, NamespaceStateV1, OccurrenceArtifactV1,
    OccurrenceStateV1, ParseStateV1, PublicationStateV1, SemanticsStateV1, encode_history,
};
use rsolve_core::{
    Artifact, ArtifactLocator, DependencyKind, DependencyRequirement, DependencySourceConstraint,
    Distribution, DistributionChannel, DistributionMetadata, PackageName, PackageNamespace,
    PackageRelease, RPackageVersion, RegistryId, RelationOp, SourceArtifact, VersionClause,
    VersionConstraint,
};

fn source(kind: &str, digest: u8) -> SourceInput {
    SourceInput {
        kind: kind.into(),
        representation: "dcf".into(),
        content_sha256: [digest; 32],
        etag: None,
        last_modified: None,
        observed_at: "2026-08-23T00:00:00Z".into(),
        endpoint: format!("https://{kind}.example/PACKAGES"),
    }
}

fn release(fields: &[(&str, &str)]) -> PackageRelease {
    PackageRelease::try_from(super::super::catalog::observation_from_fields(fields).unwrap())
        .unwrap()
}

fn release_with_preexisting_artifact(fields: &[(&str, &str)]) -> PackageRelease {
    let mut observation = super::super::catalog::observation_from_fields(fields).unwrap();
    observation.distributions[0]
        .artifacts
        .push(Artifact::Source(SourceArtifact {
            locator: ArtifactLocator::new("https://unobserved.example/preexisting.tar.gz").unwrap(),
            upstream_checksums: vec![],
            size: None,
        }));
    PackageRelease::try_from(observation).unwrap()
}

fn release_with_multiple_distribution_templates(fields: &[(&str, &str)]) -> PackageRelease {
    let mut observation = super::super::catalog::observation_from_fields(fields).unwrap();
    observation.distributions.push(Distribution {
        registry: RegistryId::new("other-registry").unwrap(),
        channel: DistributionChannel::new("binary").unwrap(),
        snapshot: None,
        artifacts: vec![],
        observed_metadata: DistributionMetadata::default(),
    });
    PackageRelease::try_from(observation).unwrap()
}

fn release_with_reordered_duplicate_dependencies() -> PackageRelease {
    let fields = [("Package", "P3MOverlay"), ("Version", "1.0")];
    let mut observation = super::super::catalog::observation_from_fields(&fields).unwrap();
    let package = PackageName::new("R").unwrap();
    let first = VersionConstraint::new(vec![
        VersionClause::new(RelationOp::Ge, RPackageVersion::parse("2.0").unwrap()),
        VersionClause::new(RelationOp::Ge, RPackageVersion::parse("1.0").unwrap()),
    ]);
    let second = VersionConstraint::new(vec![
        VersionClause::new(RelationOp::Ge, RPackageVersion::parse("1.0").unwrap()),
        VersionClause::new(RelationOp::Ge, RPackageVersion::parse("2.0").unwrap()),
    ]);
    observation.dependencies = vec![
        DependencyRequirement::new(
            DependencyKind::Depends,
            package.clone(),
            DependencySourceConstraint::Any,
            first,
        ),
        DependencyRequirement::new(
            DependencyKind::Depends,
            package,
            DependencySourceConstraint::Any,
            second,
        ),
    ];
    PackageRelease::try_from(observation).unwrap()
}

fn release_with_non_any_dependency() -> PackageRelease {
    let fields = [("Package", "P3MOverlay"), ("Version", "1.0")];
    let mut observation = super::super::catalog::observation_from_fields(&fields).unwrap();
    observation.dependencies = vec![DependencyRequirement::new(
        DependencyKind::Depends,
        PackageName::new("R").unwrap(),
        DependencySourceConstraint::Registry {
            namespace: PackageNamespace::new("cran").unwrap(),
        },
        VersionConstraint::unconstrained(),
    )];
    PackageRelease::try_from(observation).unwrap()
}

fn release_with_dependency_version_spelling(spelling: &str) -> PackageRelease {
    let fields = [("Package", "P3MOverlay"), ("Version", "1.0")];
    let mut observation = super::super::catalog::observation_from_fields(&fields).unwrap();
    observation.dependencies = vec![DependencyRequirement::new(
        DependencyKind::Depends,
        PackageName::new("R").unwrap(),
        DependencySourceConstraint::Any,
        VersionConstraint::from_clause(RelationOp::Ge, RPackageVersion::parse(spelling).unwrap()),
    )];
    PackageRelease::try_from(observation).unwrap()
}

fn raw(
    fields: &[(&str, &str)],
    locator: &str,
) -> (PackageName, Vec<FieldV1>, OccurrenceArtifactV1) {
    let package = fields
        .iter()
        .find(|(name, _)| *name == "Package")
        .map(|(_, value)| PackageName::new(*value).unwrap())
        .unwrap();
    (
        package,
        fields
            .iter()
            .map(|(name, value)| FieldV1 {
                name: (*name).into(),
                value: (*value).into(),
            })
            .collect(),
        OccurrenceArtifactV1 {
            locator: locator.into(),
            checksums: vec![],
            size: None,
        },
    )
}

fn axes(
    semantics: SemanticsStateV1,
    publication: PublicationStateV1,
    freshness: FreshnessStateV1,
) -> EvidenceAxesV1 {
    EvidenceAxesV1 {
        parse: ParseStateV1::Valid,
        namespace: NamespaceStateV1::Established,
        occurrence: OccurrenceStateV1::ArtifactBound,
        semantics,
        publication,
        freshness,
    }
}

pub(crate) fn context() -> SnapshotCompositionContext {
    SnapshotCompositionContext {
        registry_id: RegistryId::new("cran").unwrap(),
        compatibility_profile: 1,
        parser_schema: 1,
        normalization_policy: 1,
        created_at: "2026-08-23T00:00:00Z".into(),
        producer: "test".into(),
        coverage: CoverageV1 {
            state: "partial".into(),
            scope: "test".into(),
            freshness: "current".into(),
            source_ids: vec![],
            missing_evidence: vec![],
        },
    }
}

pub(crate) fn fixture_observations() -> Vec<CranEvidenceObservation> {
    let p3m = source("p3m-current", 1);
    let history = source("cran-history", 2);
    let current_fields = [
        ("Package", "P3MOverlay"),
        ("Version", "1.0"),
        ("Title", "fixture"),
    ];
    let history_fields = [
        ("Package", "P3MOverlay"),
        ("Version", "1.0"),
        ("License", "MIT"),
        ("Published", "2026-08-20"),
    ];
    let old_fields = [
        ("Package", "P3MOverlay"),
        ("Version", "0.9"),
        ("License", "MIT"),
        ("Published", "2025-08-20"),
    ];
    let (package, fields, artifact) = raw(&current_fields, "https://p3m.example/1.0.tar.gz");
    let (history_package, history_raw, history_artifact) =
        raw(&history_fields, "https://cran.example/1.0.tar.gz");
    let (old_package, old_raw, old_artifact) = raw(&old_fields, "https://cran.example/0.9.tar.gz");
    vec![
        CranEvidenceObservation {
            source: p3m,
            package,
            record_index: 10,
            fields,
            artifact: Some(artifact),
            axes: axes(
                SemanticsStateV1::Complete,
                PublicationStateV1::Unknown,
                FreshnessStateV1::CurrentGeneration,
            ),
            release: Some(release(&current_fields)),
            distribution_registry: DistributionRegistryBinding::Explicit(
                RegistryId::new("p3m").unwrap(),
            ),
        },
        CranEvidenceObservation {
            source: history.clone(),
            package: history_package,
            record_index: 20,
            fields: history_raw,
            artifact: Some(history_artifact),
            axes: axes(
                SemanticsStateV1::Complete,
                PublicationStateV1::Dated,
                FreshnessStateV1::BulkGeneration,
            ),
            release: Some(release(&history_fields)),
            distribution_registry: DistributionRegistryBinding::Explicit(
                RegistryId::new("cran").unwrap(),
            ),
        },
        CranEvidenceObservation {
            source: history,
            package: old_package,
            record_index: 21,
            fields: old_raw,
            artifact: Some(old_artifact),
            axes: axes(
                SemanticsStateV1::Complete,
                PublicationStateV1::Dated,
                FreshnessStateV1::BulkGeneration,
            ),
            release: Some(release(&old_fields)),
            distribution_registry: DistributionRegistryBinding::Explicit(
                RegistryId::new("cran").unwrap(),
            ),
        },
    ]
}

#[test]
fn composes_source_scoped_occurrences_and_canonical_only_history_release() {
    let input = compose_snapshot(context(), fixture_observations()).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert_eq!(history.eligible_releases.len(), 2);
    assert_eq!(history.eligible_releases[0].version, "0.9");
    assert_eq!(history.eligible_releases[1].version, "1.0");
    let old = &history.eligible_releases[0];
    assert_eq!(old.distributions.len(), 1);
    assert_eq!(old.distributions[0].registry, "cran");
    assert_eq!(old.distributions[0].artifacts.len(), 1);
    assert!(
        old.distributions[0].artifacts[0]
            .locator
            .contains("cran.example")
    );
    assert!(
        old.distributions[0].artifacts[0]
            .upstream_checksums
            .is_empty()
    );
    assert_eq!(old.evidence.len(), 1);
    let old_observation_id = history
        .observations
        .iter()
        .find(|observation| {
            observation
                .artifact
                .as_ref()
                .is_some_and(|artifact| artifact.locator.contains("0.9"))
        })
        .map(|observation| observation.id)
        .unwrap();
    assert_eq!(old.evidence[0].observation_id, old_observation_id);
    assert!(old.evidence[0].roles.contains(&EvidenceRoleV1::Artifact));
    assert_eq!(old.publication.as_deref(), Some("2025-08-20"));
    assert!(old.evidence[0].roles.contains(&EvidenceRoleV1::Publication));
    let merged = &history.eligible_releases[1];
    assert_eq!(merged.distributions.len(), 2);
    assert!(
        merged
            .distributions
            .iter()
            .any(|distribution| distribution.registry == "p3m")
    );
    assert!(
        merged
            .distributions
            .iter()
            .any(|distribution| distribution.registry == "cran")
    );
    assert!(
        merged
            .distributions
            .iter()
            .flat_map(|distribution| distribution.artifacts.iter())
            .any(|artifact| artifact.locator.contains("p3m.example"))
    );
    let p3m_observation_id = history
        .observations
        .iter()
        .find(|observation| {
            observation
                .artifact
                .as_ref()
                .is_some_and(|artifact| artifact.locator.contains("p3m.example"))
        })
        .map(|observation| observation.id)
        .unwrap();
    let canonical_observation_id = history
        .observations
        .iter()
        .find(|observation| {
            observation
                .artifact
                .as_ref()
                .is_some_and(|artifact| artifact.locator.contains("cran.example/1.0"))
        })
        .map(|observation| observation.id)
        .unwrap();
    for observation_id in [p3m_observation_id, canonical_observation_id] {
        let evidence = merged
            .evidence
            .iter()
            .find(|evidence| evidence.observation_id == observation_id)
            .unwrap();
        assert!(evidence.roles.contains(&EvidenceRoleV1::Artifact));
    }
    assert_eq!(merged.publication.as_deref(), Some("2026-08-20"));
    let p3m_evidence = merged
        .evidence
        .iter()
        .find(|evidence| evidence.observation_id == p3m_observation_id)
        .unwrap();
    let canonical_evidence = merged
        .evidence
        .iter()
        .find(|evidence| evidence.observation_id == canonical_observation_id)
        .unwrap();
    assert!(!p3m_evidence.roles.contains(&EvidenceRoleV1::Publication));
    assert!(
        canonical_evidence
            .roles
            .contains(&EvidenceRoleV1::Publication)
    );
    assert_eq!(merged.metadata.len(), 2);
    assert_eq!(
        merged
            .metadata
            .iter()
            .map(|field| field.name.to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        merged.metadata.len()
    );
    assert!(encode_history(history).is_ok());
}

#[test]
fn absent_occurrence_artifact_cannot_contribute_a_distribution() {
    let mut observations = fixture_observations();
    observations[0].artifact = None;
    observations[0].axes.occurrence = OccurrenceStateV1::ObservationOnly;
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    let current = history
        .eligible_releases
        .iter()
        .find(|release| release.version == "1.0")
        .unwrap();
    assert_eq!(current.distributions[0].artifacts.len(), 1);
    assert!(
        current
            .distributions
            .iter()
            .all(|distribution| distribution.registry != "p3m")
    );
    assert!(
        current.distributions[0].artifacts[0]
            .locator
            .contains("cran.example")
    );
    let p3m = history
        .observations
        .iter()
        .find(|observation| observation.record_index == 10)
        .unwrap();
    let p3m_evidence = current
        .evidence
        .iter()
        .find(|evidence| evidence.observation_id == p3m.id)
        .unwrap();
    assert!(!p3m_evidence.roles.contains(&EvidenceRoleV1::Artifact));
}

#[test]
fn configured_context_binding_resolves_to_the_store_registry() {
    let mut observations = fixture_observations();
    for observation in &mut observations {
        observation.distribution_registry = DistributionRegistryBinding::ConfiguredContext;
    }
    let mut configured = context();
    configured.registry_id = RegistryId::new("internal-cran-mirror").unwrap();
    let input = compose_snapshot(configured, observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(history.eligible_releases.iter().all(|release| {
        release
            .distributions
            .iter()
            .all(|distribution| distribution.registry == "internal-cran-mirror")
    }));
    assert!(
        history
            .eligible_releases
            .iter()
            .all(|release| release.namespace == "cran")
    );
}

#[test]
fn preexisting_release_artifacts_are_not_projected_without_occurrence_evidence() {
    let mut observations = fixture_observations();
    observations[0].release = Some(release_with_preexisting_artifact(&[
        ("Package", "P3MOverlay"),
        ("Version", "1.0"),
    ]));
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    let current = history
        .eligible_releases
        .iter()
        .find(|release| release.version == "1.0")
        .unwrap();
    let locators = current
        .distributions
        .iter()
        .flat_map(|distribution| distribution.artifacts.iter())
        .map(|artifact| artifact.locator.as_str())
        .collect::<Vec<_>>();
    assert!(
        locators
            .iter()
            .any(|locator| locator.contains("p3m.example"))
    );
    assert!(
        !locators
            .iter()
            .any(|locator| locator.contains("unobserved.example"))
    );
}

#[test]
fn multiple_distribution_templates_fail_closed_for_artifact_observations() {
    let mut observations = fixture_observations();
    observations[0].release = Some(release_with_multiple_distribution_templates(&[
        ("Package", "P3MOverlay"),
        ("Version", "1.0"),
    ]));
    let error = compose_snapshot(context(), observations).unwrap_err();
    assert!(matches!(
        error,
        EvidenceCompositionError::Invalid(message)
            if message.contains("multiple distribution templates")
    ));
}

#[test]
fn occurrence_checksums_are_canonicalized_before_projection() {
    let mut observations = fixture_observations();
    observations[0].artifact.as_mut().unwrap().checksums = vec![
        ChecksumV1 {
            algorithm: "md5".into(),
            value: "b".into(),
        },
        ChecksumV1 {
            algorithm: "md5".into(),
            value: "a".into(),
        },
        ChecksumV1 {
            algorithm: "md5".into(),
            value: "a".into(),
        },
    ];
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    let current = history
        .eligible_releases
        .iter()
        .find(|release| release.version == "1.0")
        .unwrap();
    let artifact = current
        .distributions
        .iter()
        .flat_map(|distribution| distribution.artifacts.iter())
        .find(|artifact| artifact.locator.contains("p3m.example"))
        .unwrap();
    assert_eq!(artifact.upstream_checksums.len(), 2);
    assert_eq!(artifact.upstream_checksums[0].value, "a");
    assert_eq!(artifact.upstream_checksums[1].value, "b");
    let directory = tempfile::tempdir().unwrap();
    crate::snapshot::SnapshotGenerationBuilder::new(
        input,
        directory.path().join("generation.redb"),
    )
    .build()
    .unwrap();
}

#[test]
fn invalid_occurrence_locator_or_sha256_is_a_typed_error() {
    let mut invalid_locator = fixture_observations();
    invalid_locator[0].artifact.as_mut().unwrap().locator = String::new();
    let error = compose_snapshot(context(), invalid_locator).unwrap_err();
    assert!(matches!(error, EvidenceCompositionError::Invalid(_)));

    let mut invalid_digest = fixture_observations();
    invalid_digest[0].artifact.as_mut().unwrap().checksums = vec![ChecksumV1 {
        algorithm: "sha256".into(),
        value: "not-a-digest".into(),
    }];
    let error = compose_snapshot(context(), invalid_digest).unwrap_err();
    assert!(matches!(error, EvidenceCompositionError::Invalid(_)));

    let mut uppercase_algorithm = fixture_observations();
    uppercase_algorithm[0].artifact.as_mut().unwrap().checksums = vec![ChecksumV1 {
        algorithm: "SHA256".into(),
        value: "00".repeat(32),
    }];
    let error = compose_snapshot(context(), uppercase_algorithm).unwrap_err();
    assert!(matches!(error, EvidenceCompositionError::Invalid(_)));
}

#[test]
fn metadata_field_names_are_compared_case_insensitively() {
    let mut observations = fixture_observations();
    observations[1].release = Some(release(&[
        ("Package", "P3MOverlay"),
        ("Version", "1.0"),
        ("license", "MIT"),
        ("Published", "2026-08-20"),
    ]));
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    let current = history
        .eligible_releases
        .iter()
        .find(|release| release.version == "1.0")
        .unwrap();
    assert_eq!(current.metadata.len(), 2);
    assert_eq!(
        current
            .metadata
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case("license"))
            .count(),
        1
    );
}

#[test]
fn rejects_overlapping_metadata_conflict() {
    let mut observations = fixture_observations();
    observations[0].fields.push(FieldV1 {
        name: "License".into(),
        value: "GPL".into(),
    });
    observations[0].release = Some(release(&[
        ("Package", "P3MOverlay"),
        ("Version", "1.0"),
        ("License", "GPL"),
        ("Title", "fixture"),
    ]));
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Incomplete));
    assert!(history.eligible_releases.is_empty());
    assert!(history.decisions.iter().any(|decision| matches!(
        decision.code,
        crate::snapshot::DecisionCodeV1::SemanticConflict
    )));
}

#[test]
fn one_incomplete_version_makes_the_whole_package_incomplete() {
    let mut observations = fixture_observations();
    observations[2].axes.semantics = SemanticsStateV1::Incomplete;
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Incomplete));
    assert!(history.eligible_releases.is_empty());
    assert!(history.decisions.iter().any(|decision| {
        matches!(
            decision.code,
            crate::snapshot::DecisionCodeV1::IncompleteSemantics
        )
    }));
}

#[test]
fn incomplete_same_identity_observation_enriches_without_semantics_evidence() {
    let mut observations = fixture_observations();
    observations[1].axes.semantics = SemanticsStateV1::Incomplete;
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Present));
    let current = history
        .eligible_releases
        .iter()
        .find(|release| release.version == "1.0")
        .unwrap();
    assert_eq!(current.metadata.len(), 2);
    let incomplete = history
        .observations
        .iter()
        .find(|observation| observation.record_index == 20)
        .unwrap();
    let evidence = current
        .evidence
        .iter()
        .find(|evidence| evidence.observation_id == incomplete.id)
        .unwrap();
    assert!(!evidence.roles.contains(&EvidenceRoleV1::Semantics));
    assert!(
        current
            .evidence
            .iter()
            .any(|evidence| evidence.roles.contains(&EvidenceRoleV1::Semantics))
    );
}

#[test]
fn publication_axis_must_match_release_publication() {
    let mut dated_mismatch = fixture_observations();
    dated_mismatch[0].axes.publication = PublicationStateV1::Dated;
    let error = compose_snapshot(context(), dated_mismatch).unwrap_err();
    assert!(matches!(error, EvidenceCompositionError::Invalid(_)));

    let mut unknown_mismatch = fixture_observations();
    unknown_mismatch[1].axes.publication = PublicationStateV1::Unknown;
    let error = compose_snapshot(context(), unknown_mismatch).unwrap_err();
    assert!(matches!(error, EvidenceCompositionError::Invalid(_)));

    let mut conflicting = fixture_observations();
    conflicting[2].axes.publication = PublicationStateV1::Conflicting;
    conflicting[2].axes.semantics = SemanticsStateV1::Incomplete;
    let input = compose_snapshot(context(), conflicting).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Incomplete));
    assert!(history.eligible_releases.is_empty());
}

#[test]
fn dependency_conflict_is_a_package_scoped_semantic_decision() {
    let mut observations = fixture_observations();
    observations[0].release = Some(release(&[
        ("Package", "P3MOverlay"),
        ("Version", "1.0"),
        ("Title", "fixture"),
        ("Depends", "R (>= 4.0)"),
    ]));
    observations[1].release = Some(release(&[
        ("Package", "P3MOverlay"),
        ("Version", "1.0"),
        ("License", "MIT"),
        ("Published", "2026-08-20"),
        ("Depends", "R (>= 4.1)"),
    ]));
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Incomplete));
    assert!(history.eligible_releases.is_empty());
    let conflict = history
        .decisions
        .iter()
        .find(|decision| {
            matches!(
                decision.code,
                crate::snapshot::DecisionCodeV1::SemanticConflict
            )
        })
        .unwrap();
    assert_eq!(conflict.observation_ids.len(), 2);
    assert!(conflict.detail.contains("dependencies"));
}

#[test]
fn unresolved_or_unreachable_observations_block_partial_presence() {
    let mut observations = fixture_observations();
    observations[1].axes.namespace = NamespaceStateV1::Unresolved;
    observations[2].axes.occurrence = OccurrenceStateV1::Unreachable;
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Incomplete));
    assert!(history.eligible_releases.is_empty());
    assert!(history.decisions.iter().any(|decision| {
        matches!(
            decision.code,
            crate::snapshot::DecisionCodeV1::UnresolvedNamespace
        )
    }));
    assert!(history.decisions.iter().any(|decision| {
        matches!(
            decision.code,
            crate::snapshot::DecisionCodeV1::UnreachableOccurrence
        )
    }));
}

#[test]
fn rejected_namespace_is_out_of_scope_without_poisoning_valid_candidates() {
    let mut observations = fixture_observations();
    observations[2].release = None;
    observations[2].axes.namespace = NamespaceStateV1::Rejected;
    observations[2].axes.publication = PublicationStateV1::Unknown;
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Present));
    assert_eq!(history.eligible_releases.len(), 1);
    assert_eq!(history.eligible_releases[0].version, "1.0");
}

#[test]
fn artifact_bound_and_observation_only_axes_must_match_artifact_presence() {
    let mut missing_artifact = fixture_observations();
    missing_artifact[0].artifact = None;
    let error = compose_snapshot(context(), missing_artifact).unwrap_err();
    assert!(matches!(error, EvidenceCompositionError::Invalid(_)));

    let mut unexpected_artifact = fixture_observations();
    unexpected_artifact[0].axes.occurrence = OccurrenceStateV1::ObservationOnly;
    let error = compose_snapshot(context(), unexpected_artifact).unwrap_err();
    assert!(matches!(error, EvidenceCompositionError::Invalid(_)));
}

#[test]
fn incomplete_semantics_never_becomes_eligible() {
    let mut observations = fixture_observations();
    for observation in &mut observations {
        observation.axes.semantics = SemanticsStateV1::Incomplete;
    }
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(history.eligible_releases.is_empty());
    assert!(matches!(history.state, LookupStateV1::Incomplete));
}

#[test]
fn source_and_observation_reordering_is_deterministic() {
    let observations = fixture_observations();
    let first = compose_snapshot(context(), observations.clone()).unwrap();
    let mut reordered = observations;
    reordered.reverse();
    let second = compose_snapshot(context(), reordered).unwrap();
    assert_eq!(first.sources.len(), second.sources.len());
    assert_eq!(first.histories.len(), second.histories.len());
    for (left, right) in first.histories.iter().zip(second.histories.iter()) {
        assert_eq!(
            encode_history(left).unwrap(),
            encode_history(right).unwrap()
        );
    }
}

#[test]
fn composition_is_accepted_by_the_snapshot_builder() {
    let input = compose_snapshot(context(), fixture_observations()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("generation.redb");
    crate::snapshot::SnapshotGenerationBuilder::new(input, destination)
        .build()
        .unwrap();
}

#[test]
fn dependency_order_and_duplicates_are_canonicalized_for_the_builder() {
    let mut observations = fixture_observations();
    let release = release_with_reordered_duplicate_dependencies();
    observations[0].release = Some(release.clone());
    observations[1].release = Some(release);
    observations[1].axes.publication = PublicationStateV1::Unknown;
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    let current = history
        .eligible_releases
        .iter()
        .find(|release| release.version == "1.0")
        .unwrap();
    assert_eq!(current.dependencies.len(), 1);
    assert_eq!(current.dependencies[0].clauses.len(), 2);
    assert_eq!(current.dependencies[0].clauses[0].version, "1.0");
    assert_eq!(current.dependencies[0].clauses[1].version, "2.0");
    let directory = tempfile::tempdir().unwrap();
    crate::snapshot::SnapshotGenerationBuilder::new(
        input,
        directory.path().join("generation.redb"),
    )
    .build()
    .unwrap();
}

#[test]
fn equivalent_dependency_version_spellings_merge_authoritative_observations() {
    let mut observations = fixture_observations();
    observations[0].release = Some(release_with_dependency_version_spelling("4.4"));
    observations[1].release = Some(release_with_dependency_version_spelling("4.4.0"));
    observations[1].axes.publication = PublicationStateV1::Unknown;
    let input = compose_snapshot(context(), observations).unwrap();
    let history = input
        .histories
        .iter()
        .find(|history| history.package == "P3MOverlay")
        .unwrap();
    assert!(matches!(history.state, LookupStateV1::Present));
    assert!(history.decisions.iter().any(|decision| {
        matches!(
            decision.code,
            crate::snapshot::DecisionCodeV1::EquivalentMerge
        ) && decision.observation_ids.len() == 2
    }));
}

#[test]
fn non_any_dependency_source_is_rejected_at_the_composition_boundary() {
    let mut observations = fixture_observations();
    observations[0].release = Some(release_with_non_any_dependency());
    let error = compose_snapshot(context(), observations).unwrap_err();
    assert!(matches!(error, EvidenceCompositionError::Invalid(_)));
}
