use super::*;

pub const HEADER_LIMIT: usize = 16 * 1024 * 1024;
pub const HISTORY_LIMIT: usize = 64 * 1024 * 1024;
pub const HEADER_SOURCE_LIMIT: usize = 65_536;
pub const OBSERVATION_LIMIT: usize = 1_000_000;
pub const DECISION_LIMIT: usize = 1_000_000;
pub const ELIGIBLE_RELEASE_LIMIT: usize = 100_000;
pub const MEMBER_LIMIT: usize = 65_536;
pub const STRING_LIMIT: usize = 16 * 1024 * 1024;

pub const SNAPSHOT_HEADER: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshot_header");
pub const PACKAGE_HISTORIES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("package_histories");
pub(super) const HEADER_KEY: &str = "header";
pub(super) const HISTORY_ENCODING: u32 = 2;
pub(super) const HISTORY_MAGIC: &[u8; 8] = b"RSLVHST2";
pub(super) const HISTORY_PREFIX_LEN: usize = 48;

#[derive(Debug)]
pub enum SnapshotError {
    Io(std::io::Error),
    Database(redb::Error),
    DatabaseOpen(DatabaseError),
    Compaction(CompactionError),
    Table(redb::TableError),
    Transaction(redb::TransactionError),
    Commit(redb::CommitError),
    Storage(redb::StorageError),
    Json(serde_json::Error),
    Postcard(postcard::Error),
    Invalid(String),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "snapshot I/O error: {e}"),
            Self::Database(e) => write!(f, "snapshot database error: {e}"),
            Self::DatabaseOpen(e) => write!(f, "snapshot database open error: {e}"),
            Self::Compaction(e) => write!(f, "snapshot compaction error: {e}"),
            Self::Table(e) => write!(f, "snapshot table error: {e}"),
            Self::Transaction(e) => write!(f, "snapshot transaction error: {e}"),
            Self::Commit(e) => write!(f, "snapshot commit error: {e}"),
            Self::Storage(e) => write!(f, "snapshot storage error: {e}"),
            Self::Json(e) => write!(f, "snapshot JSON error: {e}"),
            Self::Postcard(e) => write!(f, "snapshot history encoding error: {e}"),
            Self::Invalid(e) => f.write_str(e),
        }
    }
}
impl std::error::Error for SnapshotError {}
impl From<std::io::Error> for SnapshotError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<redb::Error> for SnapshotError {
    fn from(e: redb::Error) -> Self {
        Self::Database(e)
    }
}
impl From<DatabaseError> for SnapshotError {
    fn from(e: DatabaseError) -> Self {
        Self::DatabaseOpen(e)
    }
}
impl From<CompactionError> for SnapshotError {
    fn from(e: CompactionError) -> Self {
        Self::Compaction(e)
    }
}
impl From<redb::TableError> for SnapshotError {
    fn from(e: redb::TableError) -> Self {
        Self::Table(e)
    }
}
impl From<redb::TransactionError> for SnapshotError {
    fn from(e: redb::TransactionError) -> Self {
        Self::Transaction(e)
    }
}
impl From<redb::CommitError> for SnapshotError {
    fn from(e: redb::CommitError) -> Self {
        Self::Commit(e)
    }
}
impl From<redb::StorageError> for SnapshotError {
    fn from(e: redb::StorageError) -> Self {
        Self::Storage(e)
    }
}
impl From<serde_json::Error> for SnapshotError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
impl From<postcard::Error> for SnapshotError {
    fn from(e: postcard::Error) -> Self {
        Self::Postcard(e)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageV1 {
    pub state: String,
    pub scope: String,
    pub freshness: String,
    pub source_ids: Vec<String>,
    pub missing_evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceObservationV1 {
    pub id: String,
    pub kind: String,
    pub representation: String,
    pub content_sha256: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub observed_at: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotHeaderV1 {
    pub format: String,
    pub version: u32,
    pub history_encoding: u32,
    pub normalization_policy: u32,
    pub compatibility_profile: u32,
    pub parser_schema: u32,
    pub registry_id: String,
    pub generation: String,
    pub created_at: String,
    pub producer: String,
    pub coverage: CoverageV1,
    pub sources: Vec<SourceObservationV1>,
    pub package_count: u64,
    pub observation_count: u64,
    pub eligible_release_count: u64,
    pub incomplete_package_count: u64,
    pub history_manifest_sha256: String,
}

#[derive(Clone, Debug)]
pub struct SourceInput {
    pub kind: String,
    pub representation: String,
    pub content_sha256: [u8; 32],
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub observed_at: String,
    pub endpoint: String,
}

#[derive(Clone, Debug)]
pub struct SnapshotBuildInput {
    pub registry_id: RegistryId,
    pub compatibility_profile: u32,
    pub parser_schema: u32,
    pub normalization_policy: u32,
    pub created_at: String,
    pub producer: String,
    pub coverage: CoverageV1,
    pub sources: Vec<SourceInput>,
    pub histories: Vec<PackageHistoryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldV1 {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChecksumV1 {
    pub algorithm: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OccurrenceArtifactV1 {
    pub locator: String,
    pub checksums: Vec<ChecksumV1>,
    pub size: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ParseStateV1 {
    Valid,
    RecordInvalid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NamespaceStateV1 {
    Established,
    Rejected,
    Unresolved,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OccurrenceStateV1 {
    ArtifactBound,
    ObservationOnly,
    Unreachable,
    Conflicting,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SemanticsStateV1 {
    Complete,
    VerifiedEmpty,
    Incomplete,
    Invalid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PublicationStateV1 {
    Dated,
    Unknown,
    Conflicting,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FreshnessStateV1 {
    CurrentGeneration,
    BulkGeneration,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceAxesV1 {
    pub parse: ParseStateV1,
    pub namespace: NamespaceStateV1,
    pub occurrence: OccurrenceStateV1,
    pub semantics: SemanticsStateV1,
    pub publication: PublicationStateV1,
    pub freshness: FreshnessStateV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RawObservationV1 {
    pub id: u32,
    pub source_index: u32,
    pub record_index: u64,
    pub fields: Vec<FieldV1>,
    pub artifact: Option<OccurrenceArtifactV1>,
    pub axes: EvidenceAxesV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DecisionCodeV1 {
    EquivalentMerge,
    CurrentOnly,
    SemanticConflict,
    UnresolvedNamespace,
    UnreachableOccurrence,
    IncompleteSemantics,
    RecommendedOverlaySuppressed,
    QuarantinedRelease,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionV1 {
    pub code: DecisionCodeV1,
    pub observation_ids: Vec<u32>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LookupStateV1 {
    Present,
    Incomplete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DependencyKindV1 {
    Depends,
    Imports,
    LinkingTo,
    Suggests,
    Enhances,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RelationOpV1 {
    Lt,
    Le,
    Eq,
    Ne,
    Ge,
    Gt,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClauseV1 {
    pub op: RelationOpV1,
    pub version: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DependencyV1 {
    pub kind: DependencyKindV1,
    pub package: String,
    pub clauses: Vec<ClauseV1>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactV1 {
    pub locator: String,
    pub upstream_checksums: Vec<ChecksumV1>,
    pub size: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DistributionV1 {
    pub registry: String,
    pub channel: String,
    pub snapshot: Option<String>,
    pub artifacts: Vec<ArtifactV1>,
    pub metadata: Vec<FieldV1>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EvidenceRoleV1 {
    Artifact,
    Identity,
    Publication,
    Semantics,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceReferenceV1 {
    pub observation_id: u32,
    pub roles: Vec<EvidenceRoleV1>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EligibleReleaseV1 {
    pub package: String,
    pub version: String,
    pub namespace: String,
    pub metadata: Vec<FieldV1>,
    pub publication: Option<String>,
    pub dependencies: Vec<DependencyV1>,
    pub distributions: Vec<DistributionV1>,
    pub metadata_sha256: [u8; 32],
    pub evidence: Vec<EvidenceReferenceV1>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageHistoryV1 {
    pub package: String,
    pub state: LookupStateV1,
    pub observations: Vec<RawObservationV1>,
    pub decisions: Vec<DecisionV1>,
    pub eligible_releases: Vec<EligibleReleaseV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PostcardHistoryV1(pub(super) PackageHistoryV1);
