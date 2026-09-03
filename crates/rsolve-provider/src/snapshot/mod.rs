//! Provider-private persistent metadata snapshot generation.
//!
//! A generation is built in a temporary redb database, validated through the
//! same wire decoders used for publication, compacted, closed, and reopened
//! read-only before it is returned. This module deliberately does not manage
//! the cache `current` pointer or any CLI paths.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{
    CompactionError, Database, DatabaseError, ReadOnlyDatabase, ReadableDatabase, ReadableTable,
    ReadableTableMetadata, TableDefinition,
};
use rsolve_core::{
    Artifact, ArtifactLocator, CandidateLoadError, CandidateLoadErrorCategory, DeclaredDependency,
    DependencyKind, DependencySourceConstraint, Distribution, DistributionChannel,
    DistributionMetadata, GitCommitId, NormalizedGitUrl, PackageName, PackageNamespace,
    PackageRelease, Provenance, PublicationDate, QuarantinedCandidate, RPackageVersion, RegistryId,
    RelationOp, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, ReleasePublication,
    RepositorySubdir, Sha256Digest, SnapshotId, SolverKey, SourceArtifact, UpstreamChecksum,
    VersionClause, VersionConstraint,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod wire;
pub use wire::*;
use wire::{HEADER_KEY, HISTORY_MAGIC, HISTORY_PREFIX_LEN, PostcardHistoryV1};

mod validation;
use validation::*;

mod codec;
pub(crate) use codec::encode_history;
pub(crate) use codec::replace_file;
pub use codec::{decode_header, decode_history, encode_header};
use codec::{
    history_manifest, read_generation_header, sync_directory, sync_file, validate_generation,
    write_generation, write_generation_unvalidated,
};
#[cfg(test)]
pub(crate) use codec::{reset_validation_count, validation_count};

mod generation;
pub(super) use generation::PreparedGeneration;
#[cfg(test)]
use generation::destination_parent;
pub(crate) use generation::source_observation;
#[allow(unused_imports)]
pub use generation::{
    ReadOnlySnapshotCandidateLoader, SnapshotGenerationBuilder, ValidatedGeneration,
};

mod cache;
pub(crate) use cache::SnapshotPublishError;
pub(crate) use cache::SnapshotRefreshGuard;
pub use cache::{SnapshotStore, SnapshotStoreError};
pub(crate) use cache::{ViewValidationV1, view_validation_revision_token};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn test_present_input() -> SnapshotBuildInput {
    tests::present_input()
}
