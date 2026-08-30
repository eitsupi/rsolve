//! Domain model and provider-facing ports for rsolve.
//!
//! This crate intentionally contains no transport, runtime, parser, solver,
//! cache, or CLI implementation details.

mod candidates;
mod constraints;
mod environment;
mod identity;
mod metadata;
mod names;
mod publication;
mod r_versions;
mod request;
mod resolution;
mod target;

pub use candidates::{
    CandidateAvailability, CandidateCurrentness, NonRepositoryExposure, PreparedCandidate,
    PreparedCandidateError, PreparedCandidateSet, PreparedCandidateSetError, RepositoryOccurrence,
    RepositoryOccurrenceError,
};
pub use constraints::{
    DeclaredDependency, DependencyKind, DependencySourceConstraint, EffectiveDependencyKind,
    PackageRequirement, PackageRequirementError, RelationOp, ResolvedDependencyEdge,
    RootCompositionError, RootExpansionPolicy, RootRequirement, VersionClause, VersionConstraint,
    combine_root_requirements,
};
pub use environment::{EnvironmentId, EnvironmentIdError};
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
    PackageName, PackageNameError, PackageNamespace, RegistryId, RepositoryId, RepositoryRank,
    RepositorySubdir, RepositorySubdirError, Sha256Digest, SnapshotId, SourceScheme,
};
pub use publication::{
    PublicationCutoff, PublicationDate, PublicationDateError, ReleasePublication,
};
pub use r_versions::{RPackageVersion, RPackageVersionError};
pub use request::{LockedIdentities, ResolutionRequest, SolverKey};
pub use resolution::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoadResult, CandidateLoader,
    QuarantinedCandidate, Resolution, ResolvedPackage,
};
pub use target::ResolutionTarget;
