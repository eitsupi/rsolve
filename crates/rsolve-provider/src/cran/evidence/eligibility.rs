use std::collections::BTreeMap;

use super::types::*;
use rsolve_core::{PackageName, PackageRelease};

pub(super) fn compose_history(
    package: &PackageName,
    indexes: &[usize],
    observations: &[IndexedObservation],
    configured_registry: &rsolve_core::RegistryId,
) -> Result<PackageHistoryV1, EvidenceCompositionError> {
    let mut groups = BTreeMap::<IdentityKey, Vec<(usize, PackageRelease)>>::new();
    let mut package_incomplete = false;
    let mut decisions = Vec::new();
    for &index in indexes {
        let observation = &observations[index];
        if let CranCatalogRecordScope::RecommendedOverlay { runtime } = &observation.scope {
            decisions.push(DecisionV1 {
                code: crate::snapshot::DecisionCodeV1::RecommendedOverlaySuppressed,
                observation_ids: vec![index as u32],
                detail: format!(
                    "Recommended overlay for R {runtime} is retained as raw evidence but excluded from CRAN release eligibility"
                ),
            });
            continue;
        }
        if let Some((code, detail)) = completeness_failure(observation) {
            package_incomplete = true;
            decisions.push(DecisionV1 {
                code,
                observation_ids: vec![index as u32],
                detail: detail.into(),
            });
            continue;
        }
        if matches!(
            observation.axes.namespace,
            crate::snapshot::NamespaceStateV1::Rejected
        ) {
            continue;
        }
        let Some(release) = observation.release.clone() else {
            package_incomplete = true;
            decisions.push(DecisionV1 {
                code: crate::snapshot::DecisionCodeV1::IncompleteSemantics,
                observation_ids: vec![index as u32],
                detail: "observation has no validated release semantics".into(),
            });
            continue;
        };
        groups
            .entry((release.identity().name().clone(), release.version().clone()))
            .or_default()
            .push((index, release));
    }

    let mut eligible_releases = Vec::new();
    for ((_, version), entries) in groups {
        let authoritative = entries
            .iter()
            .filter(|(index, _)| semantics_authoritative(&observations[*index].axes))
            .collect::<Vec<_>>();
        let observation_ids = entries
            .iter()
            .map(|(index, _)| *index as u32)
            .collect::<Vec<_>>();
        if authoritative.is_empty() {
            package_incomplete = true;
            decisions.push(DecisionV1 {
                code: crate::snapshot::DecisionCodeV1::IncompleteSemantics,
                observation_ids,
                detail: format!("release {version} has no authoritative dependency semantics"),
            });
            continue;
        }
        let pending = match super::release::merge_release_group(
            &entries,
            &authoritative,
            observations,
            configured_registry,
        ) {
            Ok(pending) => pending,
            Err(error @ EvidenceCompositionError::Invalid(_)) => return Err(error),
            Err(error) => {
                package_incomplete = true;
                decisions.push(DecisionV1 {
                    code: crate::snapshot::DecisionCodeV1::SemanticConflict,
                    observation_ids,
                    detail: error.to_string(),
                });
                continue;
            }
        };
        if entries.len() > 1 {
            decisions.push(DecisionV1 {
                code: crate::snapshot::DecisionCodeV1::EquivalentMerge,
                observation_ids,
                detail: "same ReleaseIdentity observations were deterministically enriched".into(),
            });
        }
        eligible_releases.push((pending, version));
    }

    if package_incomplete {
        eligible_releases.clear();
    }
    eligible_releases.sort_by(|left, right| left.1.cmp(&right.1));
    let mut wire_releases = Vec::new();
    for (pending, _) in eligible_releases {
        wire_releases.push(super::projection::to_wire_release(&pending, indexes)?);
    }
    decisions.sort_by(|left, right| {
        (
            decision_rank(left.code),
            &left.observation_ids,
            &left.detail,
        )
            .cmp(&(
                decision_rank(right.code),
                &right.observation_ids,
                &right.detail,
            ))
    });
    let raw_observations = indexes
        .iter()
        .enumerate()
        .map(|(id, index)| RawObservationV1 {
            id: id as u32,
            source_index: observations[*index].source_index,
            record_index: observations[*index].record_index,
            fields: observations[*index].fields.clone(),
            artifact: observations[*index].artifact.clone(),
            axes: observations[*index].axes.clone(),
        })
        .collect();
    for decision in &mut decisions {
        for id in &mut decision.observation_ids {
            *id = indexes
                .iter()
                .position(|index| *index == *id as usize)
                .ok_or_else(|| {
                    EvidenceCompositionError::Invalid(
                        "decision observation escaped its package".into(),
                    )
                })? as u32;
        }
        decision.observation_ids.sort_unstable();
        decision.observation_ids.dedup();
    }
    Ok(PackageHistoryV1 {
        package: package.as_str().into(),
        state: if wire_releases.is_empty() {
            LookupStateV1::Incomplete
        } else {
            LookupStateV1::Present
        },
        observations: raw_observations,
        decisions,
        eligible_releases: wire_releases,
    })
}

pub(super) fn semantics_authoritative(axes: &EvidenceAxesV1) -> bool {
    matches!(
        axes.semantics,
        crate::snapshot::SemanticsStateV1::Complete
            | crate::snapshot::SemanticsStateV1::VerifiedEmpty
    )
}

pub(super) fn completeness_failure(
    observation: &IndexedObservation,
) -> Option<(crate::snapshot::DecisionCodeV1, &'static str)> {
    if matches!(
        observation.axes.namespace,
        crate::snapshot::NamespaceStateV1::Rejected
    ) {
        return None;
    }
    if matches!(
        observation.axes.parse,
        crate::snapshot::ParseStateV1::RecordInvalid
    ) {
        return Some((
            crate::snapshot::DecisionCodeV1::IncompleteSemantics,
            "observation record is invalid",
        ));
    }
    if matches!(
        observation.axes.namespace,
        crate::snapshot::NamespaceStateV1::Unresolved
    ) {
        return Some((
            crate::snapshot::DecisionCodeV1::UnresolvedNamespace,
            "observation namespace is unresolved",
        ));
    }
    match observation.axes.occurrence {
        crate::snapshot::OccurrenceStateV1::Unreachable => Some((
            crate::snapshot::DecisionCodeV1::UnreachableOccurrence,
            "observation occurrence is unreachable",
        )),
        crate::snapshot::OccurrenceStateV1::Conflicting => Some((
            crate::snapshot::DecisionCodeV1::UnreachableOccurrence,
            "observation occurrence is conflicting",
        )),
        crate::snapshot::OccurrenceStateV1::ArtifactBound
        | crate::snapshot::OccurrenceStateV1::ObservationOnly => {
            if matches!(
                observation.axes.publication,
                crate::snapshot::PublicationStateV1::Conflicting
            ) {
                return Some((
                    crate::snapshot::DecisionCodeV1::IncompleteSemantics,
                    "observation publication is conflicting",
                ));
            }
            match observation.axes.semantics {
                crate::snapshot::SemanticsStateV1::Incomplete => None,
                crate::snapshot::SemanticsStateV1::Invalid => Some((
                    crate::snapshot::DecisionCodeV1::IncompleteSemantics,
                    "observation semantics are invalid",
                )),
                crate::snapshot::SemanticsStateV1::Complete
                | crate::snapshot::SemanticsStateV1::VerifiedEmpty => None,
            }
        }
    }
}

fn decision_rank(code: crate::snapshot::DecisionCodeV1) -> u8 {
    code as u8
}
