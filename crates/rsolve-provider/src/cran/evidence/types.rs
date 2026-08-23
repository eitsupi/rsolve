use std::fmt;

use rsolve_core::{PackageName, PackageRelease, RPackageVersion};

pub(super) use crate::snapshot::{
    ArtifactV1, ChecksumV1, ClauseV1, CoverageV1, DecisionV1, DependencyKindV1, DependencyV1,
    DistributionV1, EligibleReleaseV1, EvidenceAxesV1, EvidenceReferenceV1, EvidenceRoleV1,
    FieldV1, LookupStateV1, OccurrenceArtifactV1, PackageHistoryV1, RawObservationV1, RelationOpV1,
    SnapshotBuildInput, SourceInput,
};

#[derive(Clone, Debug)]
pub(crate) struct CranEvidenceObservation {
    pub(crate) source: SourceInput,
    pub(crate) package: PackageName,
    pub(crate) record_index: u64,
    pub(crate) fields: Vec<FieldV1>,
    pub(crate) artifact: Option<OccurrenceArtifactV1>,
    pub(crate) axes: EvidenceAxesV1,
    pub(crate) release: Option<PackageRelease>,
}

#[derive(Clone, Debug)]
pub(crate) struct SnapshotCompositionContext {
    pub(crate) registry_id: rsolve_core::RegistryId,
    pub(crate) compatibility_profile: u32,
    pub(crate) parser_schema: u32,
    pub(crate) normalization_policy: u32,
    pub(crate) created_at: String,
    pub(crate) producer: String,
    pub(crate) coverage: CoverageV1,
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
pub(super) struct IndexedObservation {
    pub(super) source_index: u32,
    pub(super) package: PackageName,
    pub(super) record_index: u64,
    pub(super) fields: Vec<FieldV1>,
    pub(super) artifact: Option<OccurrenceArtifactV1>,
    pub(super) axes: EvidenceAxesV1,
    pub(super) release: Option<PackageRelease>,
}

#[derive(Clone)]
pub(super) struct PendingRelease {
    pub(super) release: PackageRelease,
    pub(super) distributions: Vec<rsolve_core::Distribution>,
    pub(super) observations: Vec<(usize, Vec<EvidenceRoleV1>)>,
}

pub(super) type IdentityKey = (PackageName, RPackageVersion);

pub(super) struct IndexedInput {
    pub(super) sources: std::collections::BTreeMap<String, SourceInput>,
    pub(super) source_ids: Vec<String>,
    pub(super) observations: Vec<IndexedObservation>,
    pub(super) package_indexes: std::collections::BTreeMap<PackageName, Vec<usize>>,
}
