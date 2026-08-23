use super::*;
use crate::constraints::{
    DependencyKind, DependencyRequirement, DependencySourceConstraint, RelationOp,
    VersionConstraint,
};
use crate::identity::{
    Artifact, Distribution, DistributionMetadata, Provenance, ReleaseIdentity, SourceArtifact,
};
use crate::names::{
    ArtifactLocator, BioconductorRelease, DistributionChannel, GitCommitId, NormalizedGitUrl,
    PackageName, PackageNamespace, RegistryId, Sha256Digest, SnapshotId, SourceScheme,
};
use crate::publication::{PublicationDate, ReleasePublication};
use crate::r_versions::RPackageVersion;
use std::collections::{BTreeMap, HashSet};

fn version(value: &str) -> RPackageVersion {
    RPackageVersion::parse(value).unwrap()
}

fn package(value: &str) -> PackageName {
    PackageName::new(value).unwrap()
}

fn identity(provenance: Provenance) -> ReleaseIdentity {
    ReleaseIdentity::new(package("Matrix"), provenance)
}

fn source_distribution(label: &str) -> Distribution {
    Distribution {
        registry: RegistryId::new("cran").unwrap(),
        channel: DistributionChannel::new("source").unwrap(),
        snapshot: Some(SnapshotId::new(label).unwrap()),
        artifacts: vec![Artifact::Source(SourceArtifact {
            locator: ArtifactLocator::new(label).unwrap(),
            upstream_checksums: vec![],
            size: None,
        })],
        observed_metadata: DistributionMetadata::default(),
    }
}

fn observation(
    identity: ReleaseIdentity,
    release_version: &str,
    distribution: Distribution,
) -> ReleaseObservation {
    ReleaseObservation {
        observed_package: identity.name().clone(),
        identity,
        observed_version: version(release_version),
        metadata: ReleaseMetadata::default(),
        publication: None,
        dependencies: vec![],
        distributions: vec![distribution],
    }
}

fn digest_dependency(name: &str, kind: DependencyKind) -> DependencyRequirement {
    DependencyRequirement::new(
        kind,
        package(name),
        DependencySourceConstraint::Any,
        VersionConstraint::from_clause(RelationOp::Ge, version("1.0")),
    )
}

mod aggregation;
mod construction;
mod digest;
