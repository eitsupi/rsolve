//! Deterministic composition of validated CRAN observations into snapshot wire data.
//!
//! Acquisition and publication deliberately live outside this module.  The
//! inputs already carry validated domain releases and explicit source
//! evidence; this boundary only combines observations that describe the same
//! CRAN release identity.
// This provider-private composition pipeline is retained as the single
// validated input boundary for the crate-visible publication seam.
#![allow(dead_code)]

mod eligibility;
mod indexing;
mod projection;
mod release;
mod types;

#[cfg(test)]
pub(super) mod tests;

pub(crate) use types::*;

/// Compose already validated observations into deterministic snapshot input.
pub(crate) fn compose_snapshot(
    context: SnapshotCompositionContext,
    observations: Vec<CranEvidenceObservation>,
) -> Result<SnapshotBuildInput, EvidenceCompositionError> {
    if observations.is_empty() {
        return Err(EvidenceCompositionError::Invalid(
            "cannot compose an empty CRAN observation set".into(),
        ));
    }

    let indexed = indexing::index_observations(observations)?;
    let configured_registry = context.registry_id.clone();

    let mut histories = Vec::with_capacity(indexed.package_indexes.len());
    for (package, indexes) in &indexed.package_indexes {
        histories.push(eligibility::compose_history(
            package,
            indexes,
            &indexed.observations,
            &configured_registry,
        )?);
    }

    let mut coverage = context.coverage;
    if !coverage.source_ids.is_empty() && coverage.source_ids != indexed.source_ids {
        return Err(EvidenceCompositionError::Invalid(
            "coverage source ids do not match composed sources".into(),
        ));
    }
    coverage.source_ids = indexed.source_ids;
    Ok(SnapshotBuildInput {
        registry_id: context.registry_id,
        compatibility_profile: context.compatibility_profile,
        parser_schema: context.parser_schema,
        normalization_policy: context.normalization_policy,
        created_at: context.created_at,
        producer: context.producer,
        coverage,
        sources: indexed.sources.into_values().collect(),
        histories,
    })
}
