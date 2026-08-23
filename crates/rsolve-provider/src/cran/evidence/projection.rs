use super::types::*;
use rsolve_core::{
    Artifact, ArtifactLocator, Distribution, DistributionMetadata, PackageRelease, RPackageVersion,
    RegistryId, RelationOp, Sha256Digest, SourceArtifact, UpstreamChecksum,
};

pub(super) fn to_wire_release(
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

pub(super) fn distribution_to_wire(
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

pub(super) fn artifact_wire_key(
    artifact: &ArtifactV1,
) -> (String, Vec<(String, String)>, Option<u64>) {
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

pub(super) fn checksum_to_wire(checksum: &UpstreamChecksum) -> ChecksumV1 {
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

pub(super) fn parse_digest(value: &Sha256Digest) -> Result<[u8; 32], EvidenceCompositionError> {
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value.as_str()[index * 2..index * 2 + 2], 16)
            .map_err(|error| EvidenceCompositionError::Invalid(error.to_string()))?;
    }
    Ok(output)
}

pub(super) fn relation_op(op: RelationOp) -> RelationOpV1 {
    match op {
        RelationOp::Lt => RelationOpV1::Lt,
        RelationOp::Le => RelationOpV1::Le,
        RelationOp::Eq => RelationOpV1::Eq,
        RelationOp::Ne => RelationOpV1::Ne,
        RelationOp::Ge => RelationOpV1::Ge,
        RelationOp::Gt => RelationOpV1::Gt,
    }
}

pub(super) fn dependency_kind_rank(kind: DependencyKindV1) -> u8 {
    kind as u8
}

pub(super) fn relation_op_rank(op: RelationOpV1) -> u8 {
    op as u8
}

pub(super) fn distributions_for_observation(
    release: &PackageRelease,
    observation: &IndexedObservation,
    configured_registry: &RegistryId,
) -> Result<Vec<rsolve_core::Distribution>, EvidenceCompositionError> {
    if !matches!(
        observation.axes.occurrence,
        crate::snapshot::OccurrenceStateV1::ArtifactBound
    ) {
        return Ok(Vec::new());
    }
    let Some(artifact) = &observation.artifact else {
        return Ok(Vec::new());
    };
    let registry = observation
        .distribution_registry
        .resolve(configured_registry);
    let mut distributions = release
        .distributions()
        .iter()
        .cloned()
        .map(|mut distribution| {
            distribution.registry = registry.clone();
            distribution.artifacts.clear();
            distribution
        })
        .collect::<Vec<_>>();
    if distributions.is_empty() {
        distributions.push(Distribution {
            registry: registry.clone(),
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
                    rsolve_core::Sha256Digest::new(&checksum.value)
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
