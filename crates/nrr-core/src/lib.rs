//! Domain model and provider-facing ports for nrr.
//!
//! This crate intentionally contains no transport, runtime, parser, solver,
//! cache, or CLI implementation details.

mod constraints;
mod identity;
mod metadata;
mod names;
mod r_versions;
mod target;

pub use constraints::{
    DependencyKind, DependencyRequirement, DependencySourceConstraint, RelationOp, VersionClause,
    VersionConstraint,
};
pub use identity::{
    Artifact, Distribution, DistributionMetadata, Provenance, ReleaseIdentity, SourceArtifact,
    UpstreamChecksum,
};
pub use metadata::{
    PackageRelease, PackageReleaseError, ReleaseAggregation, ReleaseMetadata, ReleaseMetadataError,
    ReleaseObservation,
};
pub use names::{
    ArtifactLocator, BioconductorRelease, DigestError, DistributionChannel, GitCommitId,
    GitCommitIdError, GitHashAlgorithm, IdentifierError, NormalizedGitUrl, NormalizedGitUrlError,
    PackageName, PackageNameError, PackageNamespace, RegistryId, RepositorySubdir, Sha256Digest,
    SnapshotId, SourceScheme,
};
pub use r_versions::{RPackageVersion, RPackageVersionError};
pub use target::{ResolutionTarget, Target};
