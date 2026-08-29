use std::collections::BTreeMap;

use super::types::*;
use rsolve_core::{
    DeclaredDependency, PackageRelease, ReleaseAggregation, ReleaseMetadata, ReleaseObservation,
};

pub(super) fn merge_release_group(
    entries: &[(usize, PackageRelease)],
    authoritative: &[&(usize, PackageRelease)],
    observations: &[IndexedObservation],
    configured_registry: &rsolve_core::RegistryId,
) -> Result<PendingRelease, EvidenceCompositionError> {
    let first = &entries[0].1;
    let identity = first.identity().clone();
    let identity_label = format!("{}@{}", identity.name(), first.version());
    let mut metadata = BTreeMap::<String, (String, String)>::new();
    for (_, release) in entries {
        for (field, value) in release.metadata().fields() {
            let normalized = field.to_ascii_lowercase();
            if let Some((_, existing)) = metadata.get(&normalized) {
                if existing != value {
                    return Err(EvidenceCompositionError::Conflict {
                        identity: identity_label,
                        field: "metadata",
                    });
                }
            } else {
                metadata.insert(normalized, (field.clone(), value.clone()));
            }
        }
    }
    let dependencies = authoritative[0].1.declared_dependencies().to_vec();
    let dependency_key = canonical_dependency_semantics(&dependencies)?;
    for (_, release) in authoritative.iter().skip(1) {
        if canonical_dependency_semantics(release.declared_dependencies())? != dependency_key {
            return Err(EvidenceCompositionError::Conflict {
                identity: identity_label,
                field: "dependencies",
            });
        }
    }
    let mut publication = None;
    for (_, release) in entries {
        if let Some(value) = release.publication() {
            if let Some(existing) = publication
                && existing != *value
            {
                return Err(EvidenceCompositionError::Conflict {
                    identity: identity_label,
                    field: "publication",
                });
            }
            publication = Some(*value);
        }
    }

    let mut distributions = Vec::new();
    let mut evidence = Vec::new();
    for (index, release) in entries {
        let authoritative_semantics =
            super::eligibility::semantics_authoritative(&observations[*index].axes);
        let observed_distributions = super::projection::distributions_for_observation(
            release,
            &observations[*index],
            configured_registry,
        )?;
        for distribution in &observed_distributions {
            merge_distribution(&mut distributions, distribution, &identity_label)?;
        }
        let mut roles = vec![EvidenceRoleV1::Identity];
        if observations[*index].artifact.is_some() && !observed_distributions.is_empty() {
            roles.push(EvidenceRoleV1::Artifact);
        }
        if matches!(
            observations[*index].axes.publication,
            crate::snapshot::PublicationStateV1::Dated
        ) {
            roles.push(EvidenceRoleV1::Publication);
        }
        if authoritative_semantics {
            roles.push(EvidenceRoleV1::Semantics);
        }
        roles.sort_by_key(|role| *role as u8);
        roles.dedup();
        evidence.push((*index, roles));
    }
    let currentness = if entries
        .iter()
        .any(|(index, _)| observations[*index].currentness == CandidateCurrentnessV1::Current)
    {
        CandidateCurrentnessV1::Current
    } else {
        CandidateCurrentnessV1::Historical
    };
    let merged_observation = ReleaseObservation {
        identity,
        observed_package: first.identity().name().clone(),
        observed_version: first.version().clone(),
        metadata: ReleaseMetadata::from_pairs(metadata.into_values()).map_err(|error| {
            EvidenceCompositionError::Invalid(format!("merged metadata is invalid: {error}"))
        })?,
        publication,
        declared_dependencies: dependencies,
        distributions: distributions.clone(),
    };
    let merged = PackageRelease::try_from(merged_observation).map_err(|error| {
        EvidenceCompositionError::Invalid(format!("merged CRAN release is invalid: {error}"))
    })?;
    let mut validation = ReleaseAggregation::new();
    validation
        .observe_release(merged.clone())
        .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
    Ok(PendingRelease {
        release: merged,
        distributions,
        observations: evidence,
        currentness,
    })
}

fn merge_distribution(
    distributions: &mut Vec<rsolve_core::Distribution>,
    incoming: &rsolve_core::Distribution,
    identity: &str,
) -> Result<(), EvidenceCompositionError> {
    let Some(existing) = distributions.iter_mut().find(|distribution| {
        distribution.registry == incoming.registry
            && distribution.channel == incoming.channel
            && distribution.snapshot == incoming.snapshot
    }) else {
        distributions.push(incoming.clone());
        return Ok(());
    };
    for (field, value) in &incoming.observed_metadata.fields {
        if let Some(existing_value) = existing.observed_metadata.fields.get(field)
            && existing_value != value
        {
            return Err(EvidenceCompositionError::Conflict {
                identity: identity.into(),
                field: "distribution metadata",
            });
        }
        existing
            .observed_metadata
            .fields
            .entry(field.clone())
            .or_insert_with(|| value.clone());
    }
    for artifact in &incoming.artifacts {
        if !existing.artifacts.contains(artifact) {
            existing.artifacts.push(artifact.clone());
        }
    }
    Ok(())
}

type DependencySemanticKey = (u8, String, Vec<(u8, Vec<u32>)>);

fn canonical_dependency_semantics(
    dependencies: &[DeclaredDependency],
) -> Result<Vec<DependencySemanticKey>, EvidenceCompositionError> {
    let mut keys = dependencies
        .iter()
        .map(|dependency| {
            let mut clauses = dependency
                .package
                .constraint()
                .clauses
                .iter()
                .map(|clause| {
                    let version = rsolve_core::RPackageVersion::parse(&clause.version.to_string())
                        .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
                    Ok((
                        relation_op_rank(relation_op(clause.op)),
                        version
                            .components()
                            .take(version.canonical_component_count())
                            .collect::<Vec<_>>(),
                    ))
                })
                .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
            clauses.sort();
            clauses.dedup();
            Ok((
                dependency.kind as u8,
                dependency.package.name().as_str().to_owned(),
                clauses,
            ))
        })
        .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn relation_op(op: rsolve_core::RelationOp) -> RelationOpV1 {
    match op {
        rsolve_core::RelationOp::Lt => RelationOpV1::Lt,
        rsolve_core::RelationOp::Le => RelationOpV1::Le,
        rsolve_core::RelationOp::Eq => RelationOpV1::Eq,
        rsolve_core::RelationOp::Ne => RelationOpV1::Ne,
        rsolve_core::RelationOp::Ge => RelationOpV1::Ge,
        rsolve_core::RelationOp::Gt => RelationOpV1::Gt,
    }
}

pub(super) fn relation_op_rank(op: RelationOpV1) -> u8 {
    op as u8
}
