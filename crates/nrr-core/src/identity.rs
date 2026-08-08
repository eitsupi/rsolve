use std::collections::BTreeMap;

use crate::names::{
    ArtifactLocator, BioconductorRelease, DistributionChannel, GitCommitId, NormalizedGitUrl,
    PackageName, PackageNamespace, RegistryId, RepositorySubdir, Sha256Digest, SnapshotId,
    SourceScheme,
};
use crate::r_versions::RPackageVersion;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Provenance {
    RegistryRelease {
        namespace: PackageNamespace,
        version: RPackageVersion,
    },
    GitCommit {
        repository: NormalizedGitUrl,
        commit: GitCommitId,
        subdirectory: Option<RepositorySubdir>,
    },
    BioconductorRelease {
        namespace: PackageNamespace,
        release: BioconductorRelease,
        version: RPackageVersion,
    },
    ImmutableSource {
        scheme: SourceScheme,
        digest: Sha256Digest,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ReleaseIdentity {
    name: PackageName,
    provenance: Provenance,
}

impl ReleaseIdentity {
    pub fn new(name: PackageName, provenance: Provenance) -> Self {
        Self { name, provenance }
    }

    pub fn name(&self) -> &PackageName {
        &self.name
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum UpstreamChecksum {
    Md5(Box<str>),
    Sha256(Sha256Digest),
    Other {
        algorithm: Box<str>,
        value: Box<str>,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SourceArtifact {
    pub locator: ArtifactLocator,
    pub upstream_checksums: Vec<UpstreamChecksum>,
    pub size: Option<u64>,
}

/// Artifacts are typed separately from release identity.  The first slice
/// models source artifacts only; adding binary variants later does not change
/// the `ReleaseIdentity` coordinate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Artifact {
    Source(SourceArtifact),
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct DistributionMetadata {
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Distribution {
    pub registry: RegistryId,
    pub channel: DistributionChannel,
    pub snapshot: Option<SnapshotId>,
    pub artifacts: Vec<Artifact>,
    pub observed_metadata: DistributionMetadata,
}
