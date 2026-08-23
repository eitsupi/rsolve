//! Deterministic composition of validated CRAN observations into snapshot wire data.
//!
//! Acquisition and publication deliberately live outside this module.  The
//! inputs already carry validated domain releases and explicit source
//! evidence; this boundary only combines observations that describe the same
//! CRAN release identity.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;

use rsolve_core::{
    Artifact, ArtifactLocator, DependencyRequirement, DependencySourceConstraint, Distribution,
    DistributionMetadata, PackageName, PackageRelease, Provenance, RPackageVersion, RelationOp,
    ReleaseAggregation, ReleaseMetadata, ReleaseObservation, Sha256Digest, SourceArtifact,
    UpstreamChecksum,
};

use snapshot_types::{
    ArtifactV1, ChecksumV1, ClauseV1, CoverageV1, DecisionV1, DependencyKindV1, DependencyV1,
    DistributionV1, EligibleReleaseV1, EvidenceAxesV1, EvidenceReferenceV1, EvidenceRoleV1,
    FieldV1, LookupStateV1, PackageHistoryV1, RawObservationV1, RelationOpV1, SnapshotBuildInput,
    SourceInput,
};

// Keep snapshot imports in one place.  `snapshot_types` is an alias module
// below so this file remains readable while the wire module stays private.

#[derive(Clone, Debug)]
pub(crate) struct CranEvidenceObservation {
    pub source: SourceInput,
    pub package: PackageName,
    pub record_index: u64,
    pub fields: Vec<FieldV1>,
    pub artifact: Option<snapshot_types::OccurrenceArtifactV1>,
    pub axes: EvidenceAxesV1,
    pub release: Option<PackageRelease>,
}

#[derive(Clone, Debug)]
pub(crate) struct SnapshotCompositionContext {
    pub registry_id: rsolve_core::RegistryId,
    pub compatibility_profile: u32,
    pub parser_schema: u32,
    pub normalization_policy: u32,
    pub created_at: String,
    pub producer: String,
    pub coverage: CoverageV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceCompositionError {
    Invalid(String),
    Conflict {
        identity: String,
        field: &'static str,
    },
}

impl fmt::Display for EvidenceCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Conflict { identity, field } => {
                write!(formatter, "conflicting {field} for CRAN release {identity}")
            }
        }
    }
}

impl std::error::Error for EvidenceCompositionError {}

#[derive(Clone)]
struct IndexedObservation {
    source_index: u32,
    package: PackageName,
    record_index: u64,
    fields: Vec<FieldV1>,
    artifact: Option<snapshot_types::OccurrenceArtifactV1>,
    axes: EvidenceAxesV1,
    release: Option<PackageRelease>,
}

#[derive(Clone)]
struct PendingRelease {
    release: PackageRelease,
    distributions: Vec<Distribution>,
    observations: Vec<(usize, Vec<EvidenceRoleV1>)>,
}

type IdentityKey = (PackageName, RPackageVersion);

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
            })
        })
        .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
    for observation in &mut indexed {
        if let Some(artifact) = &mut observation.artifact {
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

    let mut histories = Vec::with_capacity(package_indexes.len());
    for (package, indexes) in package_indexes {
        histories.push(compose_history(&package, &indexes, &indexed)?);
    }

    let mut coverage = context.coverage;
    if !coverage.source_ids.is_empty() && coverage.source_ids != source_ids {
        return Err(EvidenceCompositionError::Invalid(
            "coverage source ids do not match composed sources".into(),
        ));
    }
    coverage.source_ids = source_ids;
    Ok(SnapshotBuildInput {
        registry_id: context.registry_id,
        compatibility_profile: context.compatibility_profile,
        parser_schema: context.parser_schema,
        normalization_policy: context.normalization_policy,
        created_at: context.created_at,
        producer: context.producer,
        coverage,
        sources: sources.into_values().collect(),
        histories,
    })
}

fn compose_history(
    package: &PackageName,
    indexes: &[usize],
    observations: &[IndexedObservation],
) -> Result<PackageHistoryV1, EvidenceCompositionError> {
    let mut groups = BTreeMap::<IdentityKey, Vec<(usize, PackageRelease)>>::new();
    let mut package_incomplete = false;
    let mut decisions = Vec::new();
    for &index in indexes {
        let observation = &observations[index];
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
        let pending = match merge_release_group(&entries, &authoritative, observations) {
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
        wire_releases.push(to_wire_release(&pending, indexes)?);
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
    // Group-local indexes are contiguous because package_indexes was built in
    // the deterministic global observation order.
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

fn merge_release_group(
    entries: &[(usize, PackageRelease)],
    authoritative: &[&(usize, PackageRelease)],
    observations: &[IndexedObservation],
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
    let dependencies = authoritative[0].1.dependencies().to_vec();
    let dependency_key = canonical_dependency_semantics(&dependencies)?;
    for (_, release) in authoritative.iter().skip(1) {
        if canonical_dependency_semantics(release.dependencies())? != dependency_key {
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
        let authoritative_semantics = semantics_authoritative(&observations[*index].axes);
        let observed_distributions = distributions_for_observation(release, &observations[*index])?;
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
    let merged_observation = ReleaseObservation {
        identity,
        observed_package: first.identity().name().clone(),
        observed_version: first.version().clone(),
        metadata: ReleaseMetadata::from_pairs(metadata.into_values()).map_err(|error| {
            EvidenceCompositionError::Invalid(format!("merged metadata is invalid: {error}"))
        })?,
        publication,
        dependencies,
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
    })
}

fn to_wire_release(
    pending: &PendingRelease,
    package_indexes: &[usize],
) -> Result<EligibleReleaseV1, EvidenceCompositionError> {
    let release = &pending.release;
    let mut dependencies: Vec<DependencyV1> = release
        .dependencies()
        .iter()
        .map(|dependency| {
            let mut clauses = dependency
                .constraint
                .clauses
                .iter()
                .map(|clause| ClauseV1 {
                    op: relation_op(clause.op),
                    version: clause.version.to_string(),
                })
                .collect::<Vec<_>>();
            let mut keyed_clauses = clauses
                .drain(..)
                .map(|clause| {
                    let version = RPackageVersion::parse(&clause.version)
                        .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
                    Ok((
                        (
                            relation_op_rank(clause.op),
                            version
                                .components()
                                .take(version.canonical_component_count())
                                .collect::<Vec<_>>(),
                            clause.version.clone(),
                        ),
                        clause,
                    ))
                })
                .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
            keyed_clauses.sort_by(|left, right| left.0.cmp(&right.0));
            keyed_clauses.dedup_by(|left, right| left.0 == right.0);
            clauses = keyed_clauses
                .into_iter()
                .map(|(_, clause)| clause)
                .collect();
            Ok(DependencyV1 {
                kind: match dependency.kind {
                    rsolve_core::DependencyKind::Depends => DependencyKindV1::Depends,
                    rsolve_core::DependencyKind::Imports => DependencyKindV1::Imports,
                    rsolve_core::DependencyKind::LinkingTo => DependencyKindV1::LinkingTo,
                    rsolve_core::DependencyKind::Suggests => DependencyKindV1::Suggests,
                    rsolve_core::DependencyKind::Enhances => DependencyKindV1::Enhances,
                },
                package: dependency.name.as_str().into(),
                clauses,
            })
        })
        .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
    let mut keyed_dependencies = dependencies
        .drain(..)
        .map(|dependency| {
            let clauses = dependency
                .clauses
                .iter()
                .map(|clause| {
                    let version = RPackageVersion::parse(&clause.version)
                        .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
                    Ok((
                        relation_op_rank(clause.op),
                        version
                            .components()
                            .take(version.canonical_component_count())
                            .collect::<Vec<_>>(),
                        clause.version.clone(),
                    ))
                })
                .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
            Ok((
                (
                    dependency_kind_rank(dependency.kind),
                    dependency.package.clone(),
                    clauses,
                ),
                dependency,
            ))
        })
        .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
    keyed_dependencies.sort_by(|left, right| left.0.cmp(&right.0));
    keyed_dependencies.dedup_by(|left, right| left.0 == right.0);
    dependencies = keyed_dependencies
        .into_iter()
        .map(|(_, dependency)| dependency)
        .collect();
    let mut distributions = pending
        .distributions
        .iter()
        .map(distribution_to_wire)
        .collect::<Result<Vec<_>, _>>()?;
    distributions.sort_by(|left, right| {
        (&left.registry, &left.channel, &left.snapshot).cmp(&(
            &right.registry,
            &right.channel,
            &right.snapshot,
        ))
    });
    let metadata = release
        .metadata()
        .fields()
        .iter()
        .map(|(name, value)| FieldV1 {
            name: name.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    let mut metadata = metadata;
    metadata.sort_by(|left, right| left.name.cmp(&right.name));
    let evidence = pending
        .observations
        .iter()
        .map(|(index, roles)| {
            let observation_id = package_indexes
                .iter()
                .position(|candidate| candidate == index)
                .ok_or_else(|| {
                    EvidenceCompositionError::Invalid("release evidence escaped its package".into())
                })?;
            Ok(EvidenceReferenceV1 {
                observation_id: observation_id as u32,
                roles: roles.clone(),
            })
        })
        .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
    Ok(EligibleReleaseV1 {
        package: release.identity().name().as_str().into(),
        version: release.version().to_string(),
        namespace: "cran".into(),
        metadata,
        publication: release
            .publication()
            .map(|publication| publication.date().as_str()),
        dependencies,
        distributions,
        metadata_sha256: parse_digest(release.metadata_digest())?,
        evidence,
    })
}

fn distribution_to_wire(
    distribution: &Distribution,
) -> Result<DistributionV1, EvidenceCompositionError> {
    let mut artifacts = distribution
        .artifacts
        .iter()
        .map(|artifact| match artifact {
            Artifact::Source(source) => ArtifactV1 {
                locator: source.locator.as_str().into(),
                upstream_checksums: source
                    .upstream_checksums
                    .iter()
                    .map(checksum_to_wire)
                    .collect(),
                size: source.size,
            },
        })
        .collect::<Vec<_>>();
    for artifact in &mut artifacts {
        artifact.upstream_checksums.sort_by(|left, right| {
            (&left.algorithm, &left.value).cmp(&(&right.algorithm, &right.value))
        });
        artifact.upstream_checksums.dedup();
    }
    artifacts.sort_by_key(artifact_wire_key);
    artifacts.dedup();
    let mut metadata = distribution
        .observed_metadata
        .fields
        .iter()
        .map(|(name, value)| FieldV1 {
            name: name.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    metadata.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(DistributionV1 {
        registry: distribution.registry.as_str().into(),
        channel: distribution.channel.as_str().into(),
        snapshot: distribution
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.as_str().into()),
        artifacts,
        metadata,
    })
}

fn artifact_wire_key(artifact: &ArtifactV1) -> (String, Vec<(String, String)>, Option<u64>) {
    (
        artifact.locator.clone(),
        artifact
            .upstream_checksums
            .iter()
            .map(|checksum| (checksum.algorithm.clone(), checksum.value.clone()))
            .collect(),
        artifact.size,
    )
}

fn distributions_for_observation(
    release: &PackageRelease,
    observation: &IndexedObservation,
) -> Result<Vec<Distribution>, EvidenceCompositionError> {
    if !matches!(
        observation.axes.occurrence,
        crate::snapshot::OccurrenceStateV1::ArtifactBound
    ) {
        return Ok(Vec::new());
    }
    let Some(artifact) = &observation.artifact else {
        return Ok(Vec::new());
    };
    let mut distributions = release
        .distributions()
        .iter()
        .cloned()
        .map(|mut distribution| {
            distribution.artifacts.clear();
            distribution
        })
        .collect::<Vec<_>>();
    if distributions.is_empty() {
        distributions.push(Distribution {
            registry: rsolve_core::RegistryId::new("cran").expect("fixed registry is valid"),
            channel: rsolve_core::DistributionChannel::new("source")
                .expect("fixed channel is valid"),
            snapshot: None,
            artifacts: Vec::new(),
            observed_metadata: DistributionMetadata::default(),
        });
    }
    let locator = ArtifactLocator::new(&artifact.locator)
        .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
    let upstream_checksums = artifact
        .checksums
        .iter()
        .map(|checksum| {
            if checksum.algorithm == "sha256" {
                Ok(UpstreamChecksum::Sha256(
                    Sha256Digest::new(&checksum.value)
                        .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?,
                ))
            } else if checksum.algorithm == "md5" {
                Ok(UpstreamChecksum::Md5(checksum.value.clone().into()))
            } else {
                Ok(UpstreamChecksum::Other {
                    algorithm: checksum.algorithm.clone().into(),
                    value: checksum.value.clone().into(),
                })
            }
        })
        .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
    let source_artifact = Artifact::Source(SourceArtifact {
        locator,
        upstream_checksums,
        size: artifact.size,
    });
    if !distributions[0].artifacts.contains(&source_artifact) {
        distributions[0].artifacts.push(source_artifact);
    }
    Ok(distributions)
}

fn merge_distribution(
    distributions: &mut Vec<Distribution>,
    incoming: &Distribution,
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

fn checksum_to_wire(checksum: &UpstreamChecksum) -> ChecksumV1 {
    match checksum {
        UpstreamChecksum::Md5(value) => ChecksumV1 {
            algorithm: "md5".into(),
            value: value.to_string(),
        },
        UpstreamChecksum::Sha256(value) => ChecksumV1 {
            algorithm: "sha256".into(),
            value: value.as_str().into(),
        },
        UpstreamChecksum::Other { algorithm, value } => ChecksumV1 {
            algorithm: algorithm.to_string(),
            value: value.to_string(),
        },
    }
}

fn parse_digest(value: &Sha256Digest) -> Result<[u8; 32], EvidenceCompositionError> {
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value.as_str()[index * 2..index * 2 + 2], 16)
            .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
    }
    Ok(output)
}

fn relation_op(op: RelationOp) -> RelationOpV1 {
    match op {
        RelationOp::Lt => RelationOpV1::Lt,
        RelationOp::Le => RelationOpV1::Le,
        RelationOp::Eq => RelationOpV1::Eq,
        RelationOp::Ne => RelationOpV1::Ne,
        RelationOp::Ge => RelationOpV1::Ge,
        RelationOp::Gt => RelationOpV1::Gt,
    }
}

fn dependency_kind_rank(kind: DependencyKindV1) -> u8 {
    kind as u8
}

fn relation_op_rank(op: RelationOpV1) -> u8 {
    op as u8
}

type DependencySemanticKey = (u8, String, Vec<(u8, Vec<u32>, String)>);

fn canonical_dependency_semantics(
    dependencies: &[DependencyRequirement],
) -> Result<Vec<DependencySemanticKey>, EvidenceCompositionError> {
    let mut keys = dependencies
        .iter()
        .map(|dependency| {
            let mut clauses = dependency
                .constraint
                .clauses
                .iter()
                .map(|clause| {
                    let version = RPackageVersion::parse(&clause.version.to_string())
                        .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
                    Ok((
                        relation_op_rank(relation_op(clause.op)),
                        version
                            .components()
                            .take(version.canonical_component_count())
                            .collect::<Vec<_>>(),
                        clause.version.to_string(),
                    ))
                })
                .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
            clauses.sort();
            clauses.dedup();
            Ok((
                dependency.kind as u8,
                dependency.name.as_str().to_owned(),
                clauses,
            ))
        })
        .collect::<Result<Vec<_>, EvidenceCompositionError>>()?;
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn semantics_authoritative(axes: &EvidenceAxesV1) -> bool {
    matches!(
        axes.semantics,
        crate::snapshot::SemanticsStateV1::Complete
            | crate::snapshot::SemanticsStateV1::VerifiedEmpty
    )
}

fn completeness_failure(
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
            Provenance::RegistryRelease { namespace, .. } if namespace.as_str() == "cran"
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

fn decision_rank(code: crate::snapshot::DecisionCodeV1) -> u8 {
    code as u8
}

// Aliases make the private snapshot wire types explicit at this boundary.
mod snapshot_types {
    pub(super) use crate::snapshot::{
        ArtifactV1, ChecksumV1, ClauseV1, CoverageV1, DecisionV1, DependencyKindV1, DependencyV1,
        DistributionV1, EligibleReleaseV1, EvidenceAxesV1, EvidenceReferenceV1, EvidenceRoleV1,
        FieldV1, LookupStateV1, OccurrenceArtifactV1, PackageHistoryV1, RawObservationV1,
        RelationOpV1, SnapshotBuildInput, SourceInput,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{
        ChecksumV1, CoverageV1, FreshnessStateV1, NamespaceStateV1, OccurrenceArtifactV1,
        OccurrenceStateV1, ParseStateV1, PublicationStateV1, SemanticsStateV1, encode_history,
    };
    use rsolve_core::{
        Artifact, ArtifactLocator, DependencyKind, DependencyRequirement,
        DependencySourceConstraint, PackageNamespace, PackageRelease, RPackageVersion, RegistryId,
        RelationOp, SourceArtifact, VersionClause, VersionConstraint,
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
                locator: ArtifactLocator::new("https://unobserved.example/preexisting.tar.gz")
                    .unwrap(),
                upstream_checksums: vec![],
                size: None,
            }));
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

    fn context() -> SnapshotCompositionContext {
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

    fn fixture_observations() -> Vec<CranEvidenceObservation> {
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
        let (old_package, old_raw, old_artifact) =
            raw(&old_fields, "https://cran.example/0.9.tar.gz");
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
        assert_eq!(merged.distributions[0].artifacts.len(), 2);
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
    fn non_any_dependency_source_is_rejected_at_the_composition_boundary() {
        let mut observations = fixture_observations();
        observations[0].release = Some(release_with_non_any_dependency());
        let error = compose_snapshot(context(), observations).unwrap_err();
        assert!(matches!(error, EvidenceCompositionError::Invalid(_)));
    }
}
