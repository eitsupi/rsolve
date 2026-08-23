use std::collections::BTreeMap;

use rsolve_core::{DependencySourceConstraint, PackageName, PackageRelease};

use super::types::*;

pub(super) fn index_observations(
    observations: Vec<CranEvidenceObservation>,
) -> Result<IndexedInput, EvidenceCompositionError> {
    let mut sources = BTreeMap::<String, SourceInput>::new();
    for observation in &observations {
        let source = crate::snapshot::source_observation(&observation.source)
            .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
        if let Some(existing) = sources.get(&source.id) {
            if !same_source(existing, &observation.source) {
                return Err(EvidenceCompositionError::Invalid(format!(
                    "source id {} has conflicting descriptors",
                    source.id
                )));
            }
        } else {
            sources.insert(source.id, observation.source.clone());
        }
    }
    let source_ids = sources.keys().cloned().collect::<Vec<_>>();
    let source_indexes = source_ids
        .iter()
        .enumerate()
        .map(|(index, source)| (source.clone(), index as u32))
        .collect::<BTreeMap<_, _>>();

    let mut indexed = observations
        .into_iter()
        .map(|observation| {
            let source = crate::snapshot::source_observation(&observation.source)
                .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
            let source_index = *source_indexes.get(&source.id).ok_or_else(|| {
                EvidenceCompositionError::Invalid("source index was not allocated".into())
            })?;
            Ok(IndexedObservation {
                source_index,
                package: observation.package,
                record_index: observation.record_index,
                fields: observation.fields,
                artifact: observation.artifact,
                axes: observation.axes,
                release: observation.release,
                distribution_registry: observation.distribution_registry,
                scope: observation.scope,
            })
        })
        .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;

    for observation in &mut indexed {
        if let Some(artifact) = &mut observation.artifact {
            if artifact
                .checksums
                .iter()
                .any(|checksum| checksum.algorithm != checksum.algorithm.to_ascii_lowercase())
            {
                return Err(EvidenceCompositionError::Invalid(
                    "occurrence checksum algorithm must be lowercase".into(),
                ));
            }
            artifact.checksums.sort_by(|left, right| {
                (&left.algorithm, &left.value).cmp(&(&right.algorithm, &right.value))
            });
            artifact.checksums.dedup();
        }
    }
    indexed.sort_by(|left, right| {
        (
            left.source_index,
            left.record_index,
            serde_json::to_vec(&(&left.fields, &left.artifact)).unwrap_or_default(),
        )
            .cmp(&(
                right.source_index,
                right.record_index,
                serde_json::to_vec(&(&right.fields, &right.artifact)).unwrap_or_default(),
            ))
    });
    if indexed.windows(2).any(|pair| {
        pair[0].source_index == pair[1].source_index
            && pair[0].record_index == pair[1].record_index
            && pair[0].fields == pair[1].fields
            && pair[0].artifact == pair[1].artifact
    }) {
        return Err(EvidenceCompositionError::Invalid(
            "duplicate source observation ordinal and payload".into(),
        ));
    }

    let mut package_indexes = BTreeMap::<PackageName, Vec<usize>>::new();
    for (index, observation) in indexed.iter().enumerate() {
        match (observation.axes.occurrence, observation.artifact.is_some()) {
            (crate::snapshot::OccurrenceStateV1::ArtifactBound, false)
            | (crate::snapshot::OccurrenceStateV1::ObservationOnly, true) => {
                return Err(EvidenceCompositionError::Invalid(format!(
                    "observation {index} has inconsistent occurrence artifact axis"
                )));
            }
            _ => {}
        }
        validate_publication_axis(observation)?;
        package_indexes
            .entry(observation.package.clone())
            .or_default()
            .push(index);
        if let Some(release) = &observation.release {
            validate_release_identity(release, &observation.package)?;
            validate_dependency_sources(release)?;
        }
    }

    Ok(IndexedInput {
        sources,
        source_ids,
        observations: indexed,
        package_indexes,
    })
}

fn validate_publication_axis(
    observation: &IndexedObservation,
) -> Result<(), EvidenceCompositionError> {
    let has_publication = observation
        .release
        .as_ref()
        .and_then(PackageRelease::publication)
        .is_some();
    let consistent = match observation.axes.publication {
        crate::snapshot::PublicationStateV1::Dated => has_publication,
        crate::snapshot::PublicationStateV1::Unknown => !has_publication,
        crate::snapshot::PublicationStateV1::Conflicting => true,
    };
    if consistent {
        Ok(())
    } else {
        Err(EvidenceCompositionError::Invalid(
            "publication axis does not match validated release publication".into(),
        ))
    }
}

fn validate_release_identity(
    release: &PackageRelease,
    package: &PackageName,
) -> Result<(), EvidenceCompositionError> {
    if release.identity().name() != package
        || !matches!(
            release.identity().provenance(),
            rsolve_core::Provenance::RegistryRelease { namespace, .. }
                if namespace.as_str() == "cran"
        )
    {
        return Err(EvidenceCompositionError::Invalid(
            "observation release is not a CRAN registry identity for its package".into(),
        ));
    }
    Ok(())
}

fn validate_dependency_sources(release: &PackageRelease) -> Result<(), EvidenceCompositionError> {
    if release
        .dependencies()
        .iter()
        .any(|dependency| !matches!(dependency.source, DependencySourceConstraint::Any))
    {
        return Err(EvidenceCompositionError::Invalid(
            "CRAN snapshot dependencies must use the any source constraint".into(),
        ));
    }
    Ok(())
}

fn same_source(left: &SourceInput, right: &SourceInput) -> bool {
    left.kind == right.kind
        && left.representation == right.representation
        && left.content_sha256 == right.content_sha256
        && left.etag == right.etag
        && left.last_modified == right.last_modified
        && left.observed_at == right.observed_at
        && left.endpoint == right.endpoint
}
