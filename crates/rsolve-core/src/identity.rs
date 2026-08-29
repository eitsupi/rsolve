use std::collections::BTreeMap;

use crate::names::{
    ArtifactLocator, BioconductorRelease, DistributionChannel, GitCommitId, NormalizedGitUrl,
    PackageName, PackageNamespace, RegistryId, RepositorySubdir, Sha256Digest, SnapshotId,
    SourceScheme,
};
use crate::r_versions::RPackageVersion;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Provenance {
    /// A base package supplied by the selected R runtime rather than a CRAN
    /// distribution. The R version is part of its release identity.
    RBasePackage { r_version: RPackageVersion },
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

impl Provenance {
    pub fn is_r_base_package(&self) -> bool {
        matches!(self, Self::RBasePackage { .. })
    }
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

/// Canonicalizes distribution evidence without making the artifact model's
/// ordering part of the public API. The tagged, length-delimited key includes
/// every public field, including artifact locators, checksums, and metadata.
pub(crate) fn canonicalize_distributions(distributions: &mut Vec<Distribution>) {
    let mut keyed = distributions
        .drain(..)
        .map(|distribution| (distribution_key(&distribution), distribution))
        .collect::<Vec<_>>();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    *distributions = keyed
        .into_iter()
        .map(|(_, distribution)| distribution)
        .collect();
}

fn distribution_key(distribution: &Distribution) -> Vec<u8> {
    let mut key = Vec::new();
    key_field(&mut key, 1, distribution.registry.as_str().as_bytes());
    key_field(&mut key, 2, distribution.channel.as_str().as_bytes());
    match &distribution.snapshot {
        Some(snapshot) => {
            key_field(&mut key, 3, &[1]);
            key_field(&mut key, 4, snapshot.as_str().as_bytes());
        }
        None => key_field(&mut key, 3, &[0]),
    }

    key_field(
        &mut key,
        5,
        &(distribution.artifacts.len() as u64).to_be_bytes(),
    );
    for artifact in &distribution.artifacts {
        let mut artifact_key = Vec::new();
        match artifact {
            Artifact::Source(source) => {
                key_field(&mut artifact_key, 0, b"Source");
                key_field(&mut artifact_key, 1, source.locator.as_str().as_bytes());
                key_field(
                    &mut artifact_key,
                    2,
                    &(source.upstream_checksums.len() as u64).to_be_bytes(),
                );
                for checksum in &source.upstream_checksums {
                    let mut checksum_key = Vec::new();
                    match checksum {
                        UpstreamChecksum::Md5(value) => {
                            key_field(&mut checksum_key, 1, value.as_bytes());
                        }
                        UpstreamChecksum::Sha256(value) => {
                            key_field(&mut checksum_key, 2, value.as_str().as_bytes());
                        }
                        UpstreamChecksum::Other { algorithm, value } => {
                            key_field(&mut checksum_key, 3, algorithm.as_bytes());
                            key_field(&mut checksum_key, 4, value.as_bytes());
                        }
                    }
                    key_field(&mut artifact_key, 3, &checksum_key);
                }
                match source.size {
                    Some(size) => {
                        key_field(&mut artifact_key, 4, &[1]);
                        key_field(&mut artifact_key, 5, &size.to_be_bytes());
                    }
                    None => key_field(&mut artifact_key, 4, &[0]),
                }
            }
        }
        key_field(&mut key, 6, &artifact_key);
    }

    key_field(
        &mut key,
        7,
        &(distribution.observed_metadata.fields.len() as u64).to_be_bytes(),
    );
    for (field, value) in &distribution.observed_metadata.fields {
        let mut metadata_key = Vec::new();
        key_field(&mut metadata_key, 1, field.as_bytes());
        key_field(&mut metadata_key, 2, value.as_bytes());
        key_field(&mut key, 8, &metadata_key);
    }
    key
}

fn key_field(key: &mut Vec<u8>, tag: u8, value: &[u8]) {
    key.push(tag);
    key.extend_from_slice(&(value.len() as u64).to_be_bytes());
    key.extend_from_slice(value);
}
