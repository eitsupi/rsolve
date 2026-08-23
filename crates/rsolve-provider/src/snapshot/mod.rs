//! Provider-private persistent metadata snapshot generation.
//!
//! A generation is built in a temporary redb database, validated through the
//! same wire decoders used for publication, compacted, closed, and reopened
//! read-only before it is returned.  This module deliberately does not manage
//! the cache `current` pointer or any CLI paths.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{
    CompactionError, Database, DatabaseError, ReadOnlyDatabase, ReadableDatabase, ReadableTable,
    ReadableTableMetadata, TableDefinition,
};
use rsolve_core::{
    Artifact, ArtifactLocator, CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader,
    DependencyKind, DependencyRequirement, DependencySourceConstraint, Distribution,
    DistributionChannel, DistributionMetadata, PackageName, PackageNamespace, PackageRelease,
    Provenance, PublicationDate, RPackageVersion, RegistryId, RelationOp, ReleaseIdentity,
    ReleaseMetadata, ReleaseObservation, ReleasePublication, Sha256Digest, SnapshotId, SolverKey,
    SourceArtifact, UpstreamChecksum, VersionClause, VersionConstraint,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
const HEADER_KEY: &str = "header";
const HISTORY_MAGIC: &[u8; 8] = b"RSLVHST1";
const HISTORY_PREFIX_LEN: usize = 48;

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
struct PostcardHistoryV1(PackageHistoryV1);

#[derive(Clone, Debug)]
pub struct ValidatedGeneration {
    path: PathBuf,
    generation: String,
    header: SnapshotHeaderV1,
    header_bytes: Vec<u8>,
}

/// A transport-free candidate loader backed by one immutable redb generation.
///
/// The database is opened read-only and remains pinned for the lifetime of the
/// loader.  No refresh, pointer publication, repair, or endpoint state is
/// reachable through this resolver-facing capability.
pub struct ReadOnlySnapshotCandidateLoader {
    database: ReadOnlyDatabase,
    header: SnapshotHeaderV1,
    source_indexes: BTreeMap<String, u32>,
}

impl ReadOnlySnapshotCandidateLoader {
    /// Opens and validates the generation-global coordinates for a configured
    /// registry.  Package histories remain lazy and are validated when looked
    /// up.  The configured registry identity is checked against the immutable
    /// header before the loader is returned.
    pub fn open(
        path: impl AsRef<Path>,
        configured_registry_id: RegistryId,
    ) -> Result<Self, CandidateLoadError> {
        let database = ReadOnlyDatabase::open(path.as_ref()).map_err(snapshot_invalid)?;
        let read = database.begin_read().map_err(snapshot_invalid)?;
        let header_table = read.open_table(SNAPSHOT_HEADER).map_err(snapshot_invalid)?;
        let stored_header = header_table
            .get(HEADER_KEY)
            .map_err(snapshot_invalid)?
            .ok_or_else(|| snapshot_invalid("snapshot header is missing"))?;
        let header_bytes = stored_header.value();
        let header = decode_header(header_bytes).map_err(snapshot_invalid)?;
        if header.registry_id != configured_registry_id.as_str() {
            return Err(snapshot_invalid(format!(
                "snapshot registry {:?} does not match configured registry {:?}",
                header.registry_id,
                configured_registry_id.as_str()
            )));
        }
        let source_indexes = header
            .sources
            .iter()
            .enumerate()
            .map(|(index, source)| (source.id.clone(), index as u32))
            .collect::<BTreeMap<_, _>>();
        let history_table = read
            .open_table(PACKAGE_HISTORIES)
            .map_err(snapshot_invalid)?;
        if history_table.len().map_err(snapshot_invalid)? != header.package_count {
            return Err(snapshot_invalid("snapshot package count mismatch"));
        }
        drop(history_table);
        drop(header_table);
        drop(read);
        Ok(Self {
            database,
            header,
            source_indexes,
        })
    }

    fn releases_for_name(
        &self,
        name: &PackageName,
    ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let read = self.database.begin_read().map_err(snapshot_invalid)?;
        let table = read
            .open_table(PACKAGE_HISTORIES)
            .map_err(snapshot_invalid)?;
        let Some(value) = table.get(name.as_str()).map_err(snapshot_invalid)? else {
            return if self.header.coverage.state == "complete" {
                Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    format!("CRAN snapshot has no candidates for {name}"),
                ))
            } else {
                Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("CRAN snapshot is partial for missing package {name}"),
                ))
            };
        };
        let history = decode_history(value.value()).map_err(package_metadata_invalid)?;
        if history.package != name.as_str() {
            return Err(package_metadata_invalid("history key/package mismatch"));
        }
        validate_history(&history, &self.source_indexes, self.header.sources.len())
            .map_err(package_metadata_invalid)?;
        if !matches!(history.state, LookupStateV1::Present) {
            return Err(package_metadata_invalid(
                "package history is incomplete and cannot provide candidates",
            ));
        }
        history
            .eligible_releases
            .iter()
            .map(release_to_domain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(package_metadata_invalid)
    }
}

impl CandidateLoader for ReadOnlySnapshotCandidateLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot does not support solver key {package:?}"),
            ));
        };
        self.releases_for_name(name)
    }
}

fn snapshot_invalid(error: impl fmt::Display) -> CandidateLoadError {
    CandidateLoadError::new(
        CandidateLoadErrorCategory::SnapshotInvalid,
        error.to_string(),
    )
}

fn package_metadata_invalid(error: impl fmt::Display) -> CandidateLoadError {
    CandidateLoadError::new(
        CandidateLoadErrorCategory::MetadataInvalid,
        error.to_string(),
    )
}
impl ValidatedGeneration {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
    pub fn header(&self) -> &SnapshotHeaderV1 {
        &self.header
    }
    pub fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }
}

pub struct SnapshotGenerationBuilder {
    input: SnapshotBuildInput,
    destination: PathBuf,
}

struct TemporaryGeneration {
    path: PathBuf,
}

impl Drop for TemporaryGeneration {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn create_temporary_generation(parent: &Path) -> Result<TemporaryGeneration, SnapshotError> {
    let pid = std::process::id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SnapshotError::Invalid("system clock is before UNIX epoch".into()))?
        .as_nanos();
    for _ in 0..128 {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".rsolve-generation-{pid}-{timestamp}-{sequence}.tmp"
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(TemporaryGeneration { path }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(SnapshotError::Invalid(
        "unable to allocate a unique temporary generation".into(),
    ))
}

impl SnapshotGenerationBuilder {
    pub fn new(input: SnapshotBuildInput, destination: impl Into<PathBuf>) -> Self {
        Self {
            input,
            destination: destination.into(),
        }
    }
    pub fn build(self) -> Result<ValidatedGeneration, SnapshotError> {
        let (mut header, histories) = prepare(&self.input)?;
        let generation = generation_id(&self.input, &header);
        header.generation = generation.clone();
        let header_bytes = encode_header(&header)?;
        let parent = destination_parent(&self.destination);
        fs::create_dir_all(parent)?;
        let temp = create_temporary_generation(parent)?;
        write_generation(&temp.path, &header_bytes, &histories)?;
        fs::hard_link(&temp.path, &self.destination).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                SnapshotError::Invalid("generation destination already exists".into())
            } else {
                error.into()
            }
        })?;
        Ok(ValidatedGeneration {
            path: self.destination,
            generation,
            header,
            header_bytes,
        })
    }
}

fn destination_parent(destination: &Path) -> &Path {
    destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn prepare(
    input: &SnapshotBuildInput,
) -> Result<(SnapshotHeaderV1, BTreeMap<String, Vec<u8>>), SnapshotError> {
    validate_registry_id(&input.registry_id)?;
    if input.sources.len() > HEADER_SOURCE_LIMIT {
        return Err(SnapshotError::Invalid("too many snapshot sources".into()));
    }
    let mut sources = input
        .sources
        .iter()
        .enumerate()
        .map(|(input_index, source)| -> Result<_, SnapshotError> {
            Ok((input_index, source_observation(source)?))
        })
        .collect::<Result<Vec<_>, _>>()?;
    sources.sort_by(|a, b| a.1.id.cmp(&b.1.id));
    if sources.windows(2).any(|w| w[0].1.id == w[1].1.id) {
        return Err(SnapshotError::Invalid("duplicate source id".into()));
    }
    let mut source_index_remap = vec![0_u32; sources.len()];
    for (sorted_index, (input_index, _)) in sources.iter().enumerate() {
        source_index_remap[*input_index] = sorted_index as u32;
    }
    let sources = sources
        .into_iter()
        .map(|(_, source)| source)
        .collect::<Vec<_>>();
    let source_indexes = sources
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.clone(), i as u32))
        .collect::<BTreeMap<_, _>>();
    let mut histories = BTreeMap::new();
    for history in &input.histories {
        let mut canonical_history = history.clone();
        for observation in &mut canonical_history.observations {
            let input_index = usize::try_from(observation.source_index).map_err(|_| {
                SnapshotError::Invalid("observation source index is out of range".into())
            })?;
            observation.source_index = *source_index_remap.get(input_index).ok_or_else(|| {
                SnapshotError::Invalid("observation source index is out of range".into())
            })?;
        }
        validate_history(&canonical_history, &source_indexes, sources.len())?;
        let encoded = encode_history(&canonical_history)?;
        if histories
            .insert(canonical_history.package.clone(), encoded)
            .is_some()
        {
            return Err(SnapshotError::Invalid("duplicate package history".into()));
        }
    }
    let manifest = history_manifest(&histories);
    let observation_count = input
        .histories
        .iter()
        .map(|h| h.observations.len() as u64)
        .sum();
    let eligible_count = input
        .histories
        .iter()
        .map(|h| h.eligible_releases.len() as u64)
        .sum();
    let incomplete_count = input
        .histories
        .iter()
        .filter(|h| matches!(h.state, LookupStateV1::Incomplete))
        .count() as u64;
    let mut coverage = input.coverage.clone();
    coverage.source_ids.sort();
    coverage.source_ids.dedup();
    coverage.missing_evidence.sort();
    coverage.missing_evidence.dedup();
    let expected_source_ids = sources
        .iter()
        .map(|source| source.id.clone())
        .collect::<Vec<_>>();
    if coverage.source_ids != expected_source_ids {
        return Err(SnapshotError::Invalid(
            "coverage source_ids must match the configured source observations".into(),
        ));
    }
    let header = SnapshotHeaderV1 {
        format: "rsolve-metadata-snapshot".into(),
        version: 1,
        history_encoding: 1,
        normalization_policy: input.normalization_policy,
        compatibility_profile: input.compatibility_profile,
        parser_schema: input.parser_schema,
        registry_id: input.registry_id.to_string(),
        generation: String::new(),
        created_at: input.created_at.clone(),
        producer: input.producer.clone(),
        coverage,
        sources,
        package_count: histories.len() as u64,
        observation_count,
        eligible_release_count: eligible_count,
        incomplete_package_count: incomplete_count,
        history_manifest_sha256: hex(&manifest),
    };
    Ok((header, histories))
}

fn source_observation(input: &SourceInput) -> Result<SourceObservationV1, SnapshotError> {
    let content = hex(&input.content_sha256);
    let id = hex(&hash_parts(
        b"rsolve.metadata-source-id\0v1",
        [&input.kind, &input.representation, &content],
    ));
    Ok(SourceObservationV1 {
        id,
        kind: input.kind.clone(),
        representation: input.representation.clone(),
        content_sha256: content,
        etag: input.etag.clone(),
        last_modified: input.last_modified.clone(),
        observed_at: input.observed_at.clone(),
        endpoint: input.endpoint.clone(),
    })
}

fn validate_registry_id(value: &RegistryId) -> Result<(), SnapshotError> {
    if value.as_str().is_empty() {
        Err(SnapshotError::Invalid("registry id is empty".into()))
    } else {
        Ok(())
    }
}
fn validate_history(
    history: &PackageHistoryV1,
    sources: &BTreeMap<String, u32>,
    source_count: usize,
) -> Result<(), SnapshotError> {
    let package =
        PackageName::new(&history.package).map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    if history.observations.len() > OBSERVATION_LIMIT
        || history.decisions.len() > DECISION_LIMIT
        || history.eligible_releases.len() > ELIGIBLE_RELEASE_LIMIT
    {
        return Err(SnapshotError::Invalid(format!(
            "history {package} exceeds count limit"
        )));
    }
    if matches!(history.state, LookupStateV1::Present) && history.eligible_releases.is_empty() {
        return Err(SnapshotError::Invalid(
            "present history has no eligible release".into(),
        ));
    }
    if matches!(history.state, LookupStateV1::Incomplete) && !history.eligible_releases.is_empty() {
        return Err(SnapshotError::Invalid(
            "incomplete history has eligible releases".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, observation) in history.observations.iter().enumerate() {
        if observation.id != index as u32 {
            return Err(SnapshotError::Invalid(
                "observation ids are not contiguous".into(),
            ));
        }
        if observation.source_index as usize >= source_count {
            return Err(SnapshotError::Invalid(
                "observation source index is out of range".into(),
            ));
        }
        if !ids.insert(observation.id) {
            return Err(SnapshotError::Invalid("duplicate observation id".into()));
        }
    }
    for decision in &history.decisions {
        for id in &decision.observation_ids {
            if !ids.contains(id) {
                return Err(SnapshotError::Invalid(
                    "decision references unknown observation".into(),
                ));
            }
        }
    }
    for release in &history.eligible_releases {
        if release.package != history.package {
            return Err(SnapshotError::Invalid(
                "release package does not match history key".into(),
            ));
        }
        for evidence in &release.evidence {
            if !ids.contains(&evidence.observation_id) {
                return Err(SnapshotError::Invalid(
                    "release references unknown observation".into(),
                ));
            }
        }
        let _ = release_to_domain(release)?;
    }
    validate_canonical_history(history)?;
    let _ = sources;
    Ok(())
}

fn validate_header(header: &SnapshotHeaderV1) -> Result<(), SnapshotError> {
    if header.format != "rsolve-metadata-snapshot"
        || header.version != 1
        || header.history_encoding != 1
        || header.normalization_policy != 1
        || header.compatibility_profile != 1
        || header.parser_schema != 1
    {
        return Err(SnapshotError::Invalid(
            "unknown snapshot header format or version".into(),
        ));
    }
    if !matches!(header.coverage.state.as_str(), "complete" | "partial") {
        return Err(SnapshotError::Invalid("invalid coverage state".into()));
    }
    for value in [
        &header.registry_id,
        &header.generation,
        &header.created_at,
        &header.producer,
        &header.coverage.scope,
        &header.coverage.freshness,
    ] {
        validate_string(value, true, "required header string")?;
    }
    RegistryId::new(&header.registry_id)
        .map_err(|error| SnapshotError::Invalid(error.to_string()))?;
    parse_hex_32(&header.generation)?;
    if header.generation != generation_id_from_header(header) {
        return Err(SnapshotError::Invalid(
            "snapshot generation does not match header fields".into(),
        ));
    }
    if !is_rfc3339_seconds(&header.created_at) {
        return Err(SnapshotError::Invalid(
            "header created_at is not UTC RFC 3339 seconds".into(),
        ));
    }
    if header.sources.len() > HEADER_SOURCE_LIMIT {
        return Err(SnapshotError::Invalid("too many snapshot sources".into()));
    }
    let mut source_ids = Vec::with_capacity(header.sources.len());
    for source in &header.sources {
        for value in [
            &source.id,
            &source.kind,
            &source.representation,
            &source.content_sha256,
            &source.observed_at,
            &source.endpoint,
        ] {
            validate_string(value, true, "source string")?;
        }
        if source
            .etag
            .as_ref()
            .is_some_and(|value| value.len() > STRING_LIMIT)
            || source
                .last_modified
                .as_ref()
                .is_some_and(|value| value.len() > STRING_LIMIT)
        {
            return Err(SnapshotError::Invalid(
                "source validator exceeds string limit".into(),
            ));
        }
        if !is_rfc3339_seconds(&source.observed_at) {
            return Err(SnapshotError::Invalid(
                "source observed_at is not UTC RFC 3339 seconds".into(),
            ));
        }
        let content = parse_hex_32(&source.content_sha256)?;
        let expected = hex(&hash_parts(
            b"rsolve.metadata-source-id\0v1",
            [&source.kind, &source.representation, &hex(&content)],
        ));
        if expected != source.id {
            return Err(SnapshotError::Invalid(
                "source id does not match source content".into(),
            ));
        }
        source_ids.push(source.id.clone());
    }
    if source_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "snapshot sources are not sorted and unique".into(),
        ));
    }
    if header
        .coverage
        .source_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || header
            .coverage
            .missing_evidence
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(SnapshotError::Invalid(
            "coverage arrays are not sorted and unique".into(),
        ));
    }
    if header.coverage.source_ids != source_ids {
        return Err(SnapshotError::Invalid(
            "coverage source_ids must enumerate all header sources".into(),
        ));
    }
    for id in &header.coverage.source_ids {
        validate_string(id, true, "coverage source id")?;
    }
    for evidence in &header.coverage.missing_evidence {
        validate_string(evidence, true, "coverage missing evidence")?;
    }
    if header
        .coverage
        .source_ids
        .iter()
        .any(|id| !source_ids.contains(id))
    {
        return Err(SnapshotError::Invalid(
            "coverage references unknown source".into(),
        ));
    }
    let _ = parse_hex_32(&header.history_manifest_sha256)?;
    Ok(())
}

fn is_rfc3339_seconds(value: &str) -> bool {
    value.len() == 20
        && value.ends_with('Z')
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[19] == b'Z'
        && value.parse::<jiff::Timestamp>().is_ok()
}

fn validate_string(value: &str, required: bool, label: &str) -> Result<(), SnapshotError> {
    if (required && value.is_empty()) || value.len() > STRING_LIMIT {
        return Err(SnapshotError::Invalid(format!(
            "{label} is empty or too long"
        )));
    }
    Ok(())
}

fn validate_history_limits(history: &PackageHistoryV1) -> Result<(), SnapshotError> {
    if history.package.len() > STRING_LIMIT
        || history.observations.len() > OBSERVATION_LIMIT
        || history.decisions.len() > DECISION_LIMIT
        || history.eligible_releases.len() > ELIGIBLE_RELEASE_LIMIT
    {
        return Err(SnapshotError::Invalid(
            "history exceeds its count or string limit".into(),
        ));
    }
    for observation in &history.observations {
        if observation.fields.len() > MEMBER_LIMIT {
            return Err(SnapshotError::Invalid(
                "observation has too many fields".into(),
            ));
        }
        for field in &observation.fields {
            validate_string(&field.name, false, "observation field name")?;
            validate_string(&field.value, false, "observation field value")?;
        }
        if let Some(artifact) = &observation.artifact
            && (artifact.locator.len() > STRING_LIMIT || artifact.checksums.len() > MEMBER_LIMIT)
        {
            return Err(SnapshotError::Invalid(
                "observation artifact exceeds limits".into(),
            ));
        }
        if let Some(artifact) = &observation.artifact {
            validate_string(&artifact.locator, true, "observation artifact locator")?;
            for checksum in &artifact.checksums {
                validate_string(&checksum.algorithm, true, "observation checksum algorithm")?;
                validate_string(&checksum.value, true, "observation checksum value")?;
            }
        }
    }
    for decision in &history.decisions {
        if decision.observation_ids.len() > MEMBER_LIMIT || decision.detail.len() > STRING_LIMIT {
            return Err(SnapshotError::Invalid("decision exceeds its limits".into()));
        }
    }
    for release in &history.eligible_releases {
        if release.package.len() > STRING_LIMIT
            || release.version.len() > STRING_LIMIT
            || release.namespace.len() > STRING_LIMIT
            || release.metadata.len() > MEMBER_LIMIT
            || release.dependencies.len() > MEMBER_LIMIT
            || release.distributions.len() > MEMBER_LIMIT
            || release.evidence.len() > MEMBER_LIMIT
        {
            return Err(SnapshotError::Invalid(
                "eligible release exceeds its limits".into(),
            ));
        }
        validate_string(&release.package, true, "release package")?;
        validate_string(&release.version, true, "release version")?;
        validate_string(&release.namespace, true, "release namespace")?;
        for field in &release.metadata {
            validate_string(&field.name, false, "release metadata name")?;
            validate_string(&field.value, false, "release metadata value")?;
        }
        for dependency in &release.dependencies {
            if dependency.package.len() > STRING_LIMIT || dependency.clauses.len() > MEMBER_LIMIT {
                return Err(SnapshotError::Invalid(
                    "dependency exceeds its limits".into(),
                ));
            }
            validate_string(&dependency.package, true, "dependency package")?;
            for clause in &dependency.clauses {
                if clause.version.len() > STRING_LIMIT {
                    return Err(SnapshotError::Invalid(
                        "dependency clause exceeds its limits".into(),
                    ));
                }
                validate_string(&clause.version, true, "dependency clause version")?;
            }
        }
        for distribution in &release.distributions {
            if distribution.registry.len() > STRING_LIMIT
                || distribution.channel.len() > STRING_LIMIT
                || distribution
                    .snapshot
                    .as_ref()
                    .is_some_and(|s| s.len() > STRING_LIMIT)
                || distribution.artifacts.len() > MEMBER_LIMIT
                || distribution.metadata.len() > MEMBER_LIMIT
            {
                return Err(SnapshotError::Invalid(
                    "distribution exceeds its limits".into(),
                ));
            }
            validate_string(&distribution.registry, true, "distribution registry")?;
            validate_string(&distribution.channel, true, "distribution channel")?;
            if let Some(snapshot) = &distribution.snapshot {
                validate_string(snapshot, true, "distribution snapshot")?;
            }
            for field in &distribution.metadata {
                validate_string(&field.name, false, "distribution metadata name")?;
                validate_string(&field.value, false, "distribution metadata value")?;
            }
            for artifact in &distribution.artifacts {
                if artifact.locator.len() > STRING_LIMIT
                    || artifact.upstream_checksums.len() > MEMBER_LIMIT
                {
                    return Err(SnapshotError::Invalid(
                        "distribution artifact exceeds its limits".into(),
                    ));
                }
                validate_string(&artifact.locator, true, "distribution artifact locator")?;
                for checksum in &artifact.upstream_checksums {
                    validate_string(&checksum.algorithm, true, "distribution checksum algorithm")?;
                    validate_string(&checksum.value, true, "distribution checksum value")?;
                }
            }
        }
        for evidence in &release.evidence {
            if evidence.roles.len() > MEMBER_LIMIT {
                return Err(SnapshotError::Invalid(
                    "release evidence exceeds its limits".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_canonical_history(history: &PackageHistoryV1) -> Result<(), SnapshotError> {
    validate_history_limits(history)?;

    let observation_keys = history
        .observations
        .iter()
        .map(observation_order_key)
        .collect::<Result<Vec<_>, _>>()?;
    if observation_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "observations are not canonically ordered".into(),
        ));
    }
    let decision_keys = history
        .decisions
        .iter()
        .map(decision_order_key)
        .collect::<Vec<_>>();
    if decision_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "decisions are not canonically ordered".into(),
        ));
    }
    for decision in &history.decisions {
        if decision
            .observation_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(SnapshotError::Invalid(
                "decision observation IDs are not sorted and unique".into(),
            ));
        }
    }
    validate_release_order(&history.eligible_releases)?;
    for observation in &history.observations {
        if let Some(artifact) = &observation.artifact {
            validate_checksums(&artifact.checksums)?;
        }
    }
    for release in &history.eligible_releases {
        validate_fields(&release.metadata, "release metadata")?;
        let dependency_keys = release
            .dependencies
            .iter()
            .map(dependency_order_key)
            .collect::<Result<Vec<_>, _>>()?;
        if dependency_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SnapshotError::Invalid(
                "dependencies are not canonically ordered".into(),
            ));
        }
        for dependency in &release.dependencies {
            let clause_keys = dependency
                .clauses
                .iter()
                .map(clause_order_key)
                .collect::<Result<Vec<_>, _>>()?;
            if clause_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SnapshotError::Invalid(
                    "dependency clauses are not sorted and unique".into(),
                ));
            }
        }
        let distribution_keys = release
            .distributions
            .iter()
            .map(distribution_order_key)
            .collect::<Vec<_>>();
        if distribution_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SnapshotError::Invalid(
                "distributions are not canonically ordered".into(),
            ));
        }
        for distribution in &release.distributions {
            validate_fields(&distribution.metadata, "distribution metadata")?;
            let artifact_keys = distribution
                .artifacts
                .iter()
                .map(artifact_order_key)
                .collect::<Result<Vec<_>, _>>()?;
            if artifact_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SnapshotError::Invalid(
                    "artifacts are not canonically ordered".into(),
                ));
            }
            for artifact in &distribution.artifacts {
                validate_checksums(&artifact.upstream_checksums)?;
            }
        }
        let evidence_keys = release
            .evidence
            .iter()
            .map(|e| {
                (
                    e.observation_id,
                    e.roles
                        .iter()
                        .map(|role| role_rank(*role))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        if evidence_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SnapshotError::Invalid(
                "evidence is not canonically ordered".into(),
            ));
        }
        for evidence in &release.evidence {
            let roles = evidence
                .roles
                .iter()
                .map(|role| role_rank(*role))
                .collect::<Vec<_>>();
            if roles.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SnapshotError::Invalid(
                    "evidence roles are not sorted and unique".into(),
                ));
            }
        }
    }
    Ok(())
}

type VersionOrderKey = (Vec<u32>, String);
type DependencyOrderKey<'a> = (u8, &'a str, Vec<(u8, VersionOrderKey)>);
type ArtifactOrderKey = (String, Vec<(String, String)>, Option<u64>);

fn observation_order_key(
    observation: &RawObservationV1,
) -> Result<(u32, u64, Vec<u8>), SnapshotError> {
    Ok((
        observation.source_index,
        observation.record_index,
        serde_json::to_vec(&(&observation.fields, &observation.artifact))?,
    ))
}
fn decision_order_key(decision: &DecisionV1) -> (u8, Vec<u32>, &str) {
    (
        decision_rank(decision.code),
        decision.observation_ids.clone(),
        decision.detail.as_str(),
    )
}
fn dependency_order_key(
    dependency: &DependencyV1,
) -> Result<DependencyOrderKey<'_>, SnapshotError> {
    Ok((
        dependency_rank(dependency.kind),
        dependency.package.as_str(),
        dependency
            .clauses
            .iter()
            .map(clause_order_key)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}
fn clause_order_key(clause: &ClauseV1) -> Result<(u8, VersionOrderKey), SnapshotError> {
    let version = RPackageVersion::parse(&clause.version)
        .map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    Ok((
        relation_rank(clause.op),
        (
            canonical_version_components(&version),
            clause.version.clone(),
        ),
    ))
}

fn canonical_version_components(version: &RPackageVersion) -> Vec<u32> {
    version
        .components()
        .take(version.canonical_component_count())
        .collect()
}

fn validate_release_order(releases: &[EligibleReleaseV1]) -> Result<(), SnapshotError> {
    let keys = releases
        .iter()
        .map(|release| {
            let version = RPackageVersion::parse(&release.version)
                .map_err(|error| SnapshotError::Invalid(error.to_string()))?;
            Ok((
                canonical_version_components(&version),
                release.version.clone(),
                release.metadata_sha256,
            ))
        })
        .collect::<Result<Vec<_>, SnapshotError>>()?;
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "eligible releases are not canonically ordered".into(),
        ));
    }
    if keys.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(SnapshotError::Invalid(
            "duplicate eligible release version".into(),
        ));
    }
    Ok(())
}
fn distribution_order_key(distribution: &DistributionV1) -> (&str, &str, Option<&str>) {
    (
        distribution.registry.as_str(),
        distribution.channel.as_str(),
        distribution.snapshot.as_deref(),
    )
}
fn artifact_order_key(artifact: &ArtifactV1) -> Result<ArtifactOrderKey, SnapshotError> {
    validate_checksums(&artifact.upstream_checksums)?;
    Ok((
        artifact.locator.clone(),
        artifact
            .upstream_checksums
            .iter()
            .map(|c| (c.algorithm.clone(), c.value.clone()))
            .collect(),
        artifact.size,
    ))
}
fn validate_fields(fields: &[FieldV1], label: &str) -> Result<(), SnapshotError> {
    let keys = fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>();
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(format!(
            "{label} is not sorted and unique"
        )));
    }
    Ok(())
}
fn validate_checksums(checksums: &[ChecksumV1]) -> Result<(), SnapshotError> {
    let keys = checksums
        .iter()
        .map(|c| (c.algorithm.as_str(), c.value.as_str()))
        .collect::<Vec<_>>();
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "checksums are not sorted and unique".into(),
        ));
    }
    for checksum in checksums {
        if checksum.algorithm != checksum.algorithm.to_ascii_lowercase() {
            return Err(SnapshotError::Invalid(
                "checksum algorithm is not lowercase".into(),
            ));
        }
        if checksum.algorithm == "sha256" {
            parse_hex_32(&checksum.value)?;
        }
    }
    Ok(())
}
fn decision_rank(code: DecisionCodeV1) -> u8 {
    code as u8
}
fn dependency_rank(kind: DependencyKindV1) -> u8 {
    kind as u8
}
fn relation_rank(op: RelationOpV1) -> u8 {
    op as u8
}
fn role_rank(role: EvidenceRoleV1) -> u8 {
    role as u8
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], SnapshotError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SnapshotError::Invalid(
            "expected lowercase SHA-256 digest".into(),
        ));
    }
    let mut result = [0_u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| SnapshotError::Invalid("invalid SHA-256 digest".into()))?;
    }
    if value != value.to_ascii_lowercase() {
        return Err(SnapshotError::Invalid(
            "digest must use lowercase hexadecimal".into(),
        ));
    }
    Ok(result)
}

fn encode_history(history: &PackageHistoryV1) -> Result<Vec<u8>, SnapshotError> {
    let payload = postcard::to_stdvec(&PostcardHistoryV1(history.clone()))?;
    if payload.len() > HISTORY_LIMIT - HISTORY_PREFIX_LEN {
        return Err(SnapshotError::Invalid(
            "history payload exceeds its byte limit".into(),
        ));
    }
    let mut output = Vec::with_capacity(HISTORY_PREFIX_LEN + payload.len());
    output.extend_from_slice(HISTORY_MAGIC);
    output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    output.extend_from_slice(&Sha256::digest(&payload));
    output.extend_from_slice(&payload);
    Ok(output)
}

pub fn decode_history(bytes: &[u8]) -> Result<PackageHistoryV1, SnapshotError> {
    if bytes.len() < HISTORY_PREFIX_LEN
        || bytes.len() > HISTORY_LIMIT
        || &bytes[..8] != HISTORY_MAGIC
    {
        return Err(SnapshotError::Invalid("invalid history envelope".into()));
    }
    let length = usize::try_from(u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| SnapshotError::Invalid("invalid history length".into()))?,
    ))
    .map_err(|_| SnapshotError::Invalid("history length does not fit usize".into()))?;
    if length != bytes.len() - HISTORY_PREFIX_LEN {
        return Err(SnapshotError::Invalid(
            "history payload length mismatch".into(),
        ));
    }
    let digest: [u8; 32] = bytes[16..48]
        .try_into()
        .map_err(|_| SnapshotError::Invalid("invalid history digest".into()))?;
    let payload = &bytes[48..];
    if Sha256::digest(payload).as_slice() != digest {
        return Err(SnapshotError::Invalid(
            "history payload digest mismatch".into(),
        ));
    }
    let (decoded, remainder): (PostcardHistoryV1, &[u8]) = postcard::take_from_bytes(payload)?;
    if !remainder.is_empty() || postcard::to_stdvec(&decoded)? != payload {
        return Err(SnapshotError::Invalid(
            "non-canonical history payload".into(),
        ));
    }
    validate_history_limits(&decoded.0)?;
    Ok(decoded.0)
}

/// Encode a snapshot header using the strict canonical JSON representation.
pub fn encode_header(header: &SnapshotHeaderV1) -> Result<Vec<u8>, SnapshotError> {
    let bytes = canonical_json(header)?;
    if bytes.len() > HEADER_LIMIT {
        return Err(SnapshotError::Invalid(
            "snapshot header exceeds its byte limit".into(),
        ));
    }
    Ok(bytes)
}

/// Decode and canonicality-check a snapshot header without consulting redb.
pub fn decode_header(bytes: &[u8]) -> Result<SnapshotHeaderV1, SnapshotError> {
    if bytes.len() > HEADER_LIMIT {
        return Err(SnapshotError::Invalid(
            "snapshot header exceeds its byte limit".into(),
        ));
    }
    let header: SnapshotHeaderV1 = serde_json::from_slice(bytes)?;
    if canonical_json(&header)? != bytes {
        return Err(SnapshotError::Invalid(
            "snapshot header is not canonical JSON".into(),
        ));
    }
    validate_header(&header)?;
    Ok(header)
}

fn write_generation(
    path: &Path,
    header: &[u8],
    histories: &BTreeMap<String, Vec<u8>>,
) -> Result<(), SnapshotError> {
    let mut database = Database::create(path)?;
    {
        let tx = database.begin_write()?;
        {
            let mut table = tx.open_table(SNAPSHOT_HEADER)?;
            table.insert(HEADER_KEY, header)?;
        }
        {
            let mut table = tx.open_table(PACKAGE_HISTORIES)?;
            for (package, value) in histories {
                table.insert(package.as_str(), value.as_slice())?;
            }
        }
        tx.commit()?;
    }
    database.compact()?;
    drop(database);
    let readonly = ReadOnlyDatabase::open(path)?;
    let read = readonly.begin_read()?;
    let header_table = read.open_table(SNAPSHOT_HEADER)?;
    let stored = header_table
        .get(HEADER_KEY)?
        .ok_or_else(|| SnapshotError::Invalid("snapshot header was not published".into()))?;
    if stored.value() != header {
        return Err(SnapshotError::Invalid(
            "snapshot header changed after compact".into(),
        ));
    }
    let parsed_header = decode_header(stored.value())?;
    let history_table = read.open_table(PACKAGE_HISTORIES)?;
    let mut count = 0_u64;
    let mut observation_count = 0_u64;
    let mut eligible_count = 0_u64;
    let mut incomplete_count = 0_u64;
    let mut manifest_entries = BTreeMap::new();
    for row in history_table.iter()? {
        let (key, value) = row?;
        let key = key.value();
        let history = decode_history(value.value())?;
        if history.package != key {
            return Err(SnapshotError::Invalid(
                "history key/package mismatch".into(),
            ));
        }
        validate_history(
            &history,
            &parsed_header
                .sources
                .iter()
                .enumerate()
                .map(|(i, source)| (source.id.clone(), i as u32))
                .collect(),
            parsed_header.sources.len(),
        )?;
        observation_count += history.observations.len() as u64;
        eligible_count += history.eligible_releases.len() as u64;
        incomplete_count += u64::from(matches!(history.state, LookupStateV1::Incomplete));
        manifest_entries.insert(key.to_owned(), value.value().to_vec());
        count += 1;
    }
    if count != histories.len() as u64
        || parsed_header.package_count != count
        || parsed_header.observation_count != observation_count
        || parsed_header.eligible_release_count != eligible_count
        || parsed_header.incomplete_package_count != incomplete_count
        || parsed_header.history_manifest_sha256 != hex(&history_manifest(&manifest_entries))
        || parsed_header.generation != generation_id_from_header(&parsed_header)
    {
        return Err(SnapshotError::Invalid("history count mismatch".into()));
    }
    Ok(())
}

fn history_manifest(histories: &BTreeMap<String, Vec<u8>>) -> [u8; 32] {
    let mut input = Vec::new();
    append_part(&mut input, b"rsolve.metadata-history-manifest\0v1");
    append_part(&mut input, histories.len().to_string().as_bytes());
    for (package, bytes) in histories {
        append_part(&mut input, package.as_bytes());
        append_part(&mut input, &Sha256::digest(bytes));
    }
    Sha256::digest(input).into()
}
fn generation_id(input: &SnapshotBuildInput, header: &SnapshotHeaderV1) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, b"rsolve.metadata-generation\0v1");
    for value in [
        input.registry_id.as_str(),
        &header.version.to_string(),
        &header.history_encoding.to_string(),
        &header.normalization_policy.to_string(),
        &header.compatibility_profile.to_string(),
        &header.parser_schema.to_string(),
        &header.coverage.state,
        &header.coverage.scope,
        &header.coverage.freshness,
    ] {
        append_part(&mut bytes, value.as_bytes());
    }
    for value in &header.coverage.missing_evidence {
        append_part(&mut bytes, value.as_bytes());
    }
    for source in &header.sources {
        append_part(&mut bytes, source.id.as_bytes());
    }
    append_part(&mut bytes, header.history_manifest_sha256.as_bytes());
    hex(&Sha256::digest(bytes))
}

fn generation_id_from_header(header: &SnapshotHeaderV1) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, b"rsolve.metadata-generation\0v1");
    for value in [
        header.registry_id.as_str(),
        &header.version.to_string(),
        &header.history_encoding.to_string(),
        &header.normalization_policy.to_string(),
        &header.compatibility_profile.to_string(),
        &header.parser_schema.to_string(),
        &header.coverage.state,
        &header.coverage.scope,
        &header.coverage.freshness,
    ] {
        append_part(&mut bytes, value.as_bytes());
    }
    for value in &header.coverage.missing_evidence {
        append_part(&mut bytes, value.as_bytes());
    }
    for source in &header.sources {
        append_part(&mut bytes, source.id.as_bytes());
    }
    append_part(&mut bytes, header.history_manifest_sha256.as_bytes());
    hex(&Sha256::digest(bytes))
}
fn append_part(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}
fn hash_parts(domain: &[u8], parts: [&String; 3]) -> [u8; 32] {
    let mut bytes = Vec::new();
    append_part(&mut bytes, domain);
    for part in parts {
        append_part(&mut bytes, part.as_bytes());
    }
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, SnapshotError> {
    Ok(serde_json::to_vec(value)?)
}

fn release_to_domain(wire: &EligibleReleaseV1) -> Result<PackageRelease, SnapshotError> {
    if wire.namespace != "cran" {
        return Err(SnapshotError::Invalid(
            "history v1 only supports the cran namespace".into(),
        ));
    }
    let package =
        PackageName::new(&wire.package).map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    let version =
        RPackageVersion::parse(&wire.version).map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    let identity = ReleaseIdentity::new(
        package.clone(),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran")
                .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
            version: version.clone(),
        },
    );
    let metadata = ReleaseMetadata::from_pairs(
        wire.metadata
            .iter()
            .map(|x| (x.name.clone(), x.value.clone())),
    )
    .map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    let publication = wire
        .publication
        .as_ref()
        .map(PublicationDate::parse)
        .transpose()
        .map_err(|e| SnapshotError::Invalid(e.to_string()))?
        .map(ReleasePublication::new);
    let dependencies = wire
        .dependencies
        .iter()
        .map(|dependency| {
            let kind = match dependency.kind {
                DependencyKindV1::Depends => DependencyKind::Depends,
                DependencyKindV1::Imports => DependencyKind::Imports,
                DependencyKindV1::LinkingTo => DependencyKind::LinkingTo,
                DependencyKindV1::Suggests => DependencyKind::Suggests,
                DependencyKindV1::Enhances => DependencyKind::Enhances,
            };
            let clauses = dependency
                .clauses
                .iter()
                .map(|clause| {
                    let op = match clause.op {
                        RelationOpV1::Lt => RelationOp::Lt,
                        RelationOpV1::Le => RelationOp::Le,
                        RelationOpV1::Eq => RelationOp::Eq,
                        RelationOpV1::Ne => RelationOp::Ne,
                        RelationOpV1::Ge => RelationOp::Ge,
                        RelationOpV1::Gt => RelationOp::Gt,
                    };
                    Ok(VersionClause::new(
                        op,
                        RPackageVersion::parse(&clause.version)
                            .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                    ))
                })
                .collect::<Result<Vec<_>, SnapshotError>>()?;
            Ok(DependencyRequirement::new(
                kind,
                PackageName::new(&dependency.package)
                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                DependencySourceConstraint::Any,
                VersionConstraint::new(clauses),
            ))
        })
        .collect::<Result<Vec<_>, SnapshotError>>()?;
    let distributions = wire
        .distributions
        .iter()
        .map(|distribution| {
            let artifacts = distribution
                .artifacts
                .iter()
                .map(|artifact| {
                    let checksums = artifact
                        .upstream_checksums
                        .iter()
                        .map(|checksum| match checksum.algorithm.as_str() {
                            "sha256" => Ok(UpstreamChecksum::Sha256(
                                Sha256Digest::new(&checksum.value)
                                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                            )),
                            "md5" => Ok(UpstreamChecksum::Md5(checksum.value.clone().into())),
                            _ => Ok(UpstreamChecksum::Other {
                                algorithm: checksum.algorithm.clone().into(),
                                value: checksum.value.clone().into(),
                            }),
                        })
                        .collect::<Result<Vec<_>, SnapshotError>>()?;
                    Ok(Artifact::Source(SourceArtifact {
                        locator: ArtifactLocator::new(&artifact.locator)
                            .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                        upstream_checksums: checksums,
                        size: artifact.size,
                    }))
                })
                .collect::<Result<Vec<_>, SnapshotError>>()?;
            Ok(Distribution {
                registry: RegistryId::new(&distribution.registry)
                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                channel: DistributionChannel::new(&distribution.channel)
                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                snapshot: distribution
                    .snapshot
                    .as_ref()
                    .map(SnapshotId::new)
                    .transpose()
                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                artifacts,
                observed_metadata: DistributionMetadata {
                    fields: distribution
                        .metadata
                        .iter()
                        .map(|x| (x.name.clone(), x.value.clone()))
                        .collect(),
                },
            })
        })
        .collect::<Result<Vec<_>, SnapshotError>>()?;
    let release = PackageRelease::try_from(ReleaseObservation {
        identity,
        observed_package: package,
        observed_version: version,
        metadata,
        publication,
        dependencies,
        distributions,
    })
    .map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    if hex_digest(release.metadata_digest().as_str()) != hex(&wire.metadata_sha256) {
        return Err(SnapshotError::Invalid(
            "eligible release metadata digest mismatch".into(),
        ));
    }
    Ok(release)
}

fn hex_digest(value: &str) -> String {
    value.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn input() -> SnapshotBuildInput {
        let source = SourceInput {
            kind: "current-packages".into(),
            representation: "gzip-dcf".into(),
            content_sha256: [7; 32],
            etag: None,
            last_modified: None,
            observed_at: "2026-08-23T00:00:00Z".into(),
            endpoint: "https://example.test/PACKAGES.gz".into(),
        };
        let source_id = source_observation(&source).unwrap().id;
        SnapshotBuildInput {
            registry_id: RegistryId::new("cran").unwrap(),
            compatibility_profile: 1,
            parser_schema: 1,
            normalization_policy: 1,
            created_at: "2026-08-23T00:00:00Z".into(),
            producer: "test".into(),
            coverage: CoverageV1 {
                state: "complete".into(),
                scope: "test".into(),
                freshness: "current".into(),
                source_ids: vec![source_id],
                missing_evidence: vec![],
            },
            sources: vec![source],
            histories: vec![PackageHistoryV1 {
                package: "foo".into(),
                state: LookupStateV1::Incomplete,
                observations: vec![RawObservationV1 {
                    id: 0,
                    source_index: 0,
                    record_index: 0,
                    fields: vec![FieldV1 {
                        name: "Package".into(),
                        value: "foo".into(),
                    }],
                    artifact: None,
                    axes: EvidenceAxesV1 {
                        parse: ParseStateV1::Valid,
                        namespace: NamespaceStateV1::Established,
                        occurrence: OccurrenceStateV1::ObservationOnly,
                        semantics: SemanticsStateV1::Incomplete,
                        publication: PublicationStateV1::Unknown,
                        freshness: FreshnessStateV1::CurrentGeneration,
                    },
                }],
                decisions: vec![],
                eligible_releases: vec![],
            }],
        }
    }

    fn two_source_input() -> (SnapshotBuildInput, [String; 2]) {
        let mut input = input();
        input.sources.push(SourceInput {
            kind: "archive-packages".into(),
            representation: "gzip-dcf".into(),
            content_sha256: [8; 32],
            etag: None,
            last_modified: None,
            observed_at: "2026-08-23T00:00:00Z".into(),
            endpoint: "https://example.test/Archive/PACKAGES.gz".into(),
        });
        let source_ids = input
            .sources
            .iter()
            .map(|source| source_observation(source).unwrap().id)
            .collect::<Vec<_>>();
        input.coverage.source_ids = source_ids.clone();
        let mut second_observation = input.histories[0].observations[0].clone();
        second_observation.id = 1;
        second_observation.source_index = 1;
        second_observation.record_index = 1;
        input.histories[0].observations.push(second_observation);
        (input, [source_ids[0].clone(), source_ids[1].clone()])
    }

    fn present_input() -> SnapshotBuildInput {
        let mut input = input();
        let package = PackageName::new("foo").unwrap();
        let version = RPackageVersion::parse("1.0").unwrap();
        let release = PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                package.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: package,
            observed_version: version,
            metadata: ReleaseMetadata::default(),
            publication: None,
            dependencies: vec![],
            distributions: vec![],
        })
        .unwrap();
        input.histories[0].state = LookupStateV1::Present;
        input.histories[0].eligible_releases = vec![EligibleReleaseV1 {
            package: "foo".into(),
            version: "1.0".into(),
            namespace: "cran".into(),
            metadata: vec![],
            publication: None,
            dependencies: vec![],
            distributions: vec![],
            metadata_sha256: parse_hex_32(release.metadata_digest().as_str()).unwrap(),
            evidence: vec![],
        }];
        input
    }

    fn two_present_input() -> SnapshotBuildInput {
        let mut input = present_input();
        let mut second = input.histories[0].clone();
        second.package = "bar".into();
        second.eligible_releases[0].package = "bar".into();
        let package = PackageName::new("bar").unwrap();
        let version = RPackageVersion::parse("1.0").unwrap();
        let release = PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                package.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: package,
            observed_version: version,
            metadata: ReleaseMetadata::default(),
            publication: None,
            dependencies: vec![],
            distributions: vec![],
        })
        .unwrap();
        second.eligible_releases[0].metadata_sha256 =
            parse_hex_32(release.metadata_digest().as_str()).unwrap();
        input.histories.push(second);
        input
    }

    fn stored_history(path: &Path) -> PackageHistoryV1 {
        let database = ReadOnlyDatabase::open(path).unwrap();
        let read = database.begin_read().unwrap();
        let table = read.open_table(PACKAGE_HISTORIES).unwrap();
        let bytes = table.get("foo").unwrap().unwrap();
        decode_history(bytes.value()).unwrap()
    }

    fn rewrite_stored_history(
        path: &Path,
        package: &str,
        mutate: impl FnOnce(&mut PackageHistoryV1),
    ) {
        let database = Database::create(path).unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(PACKAGE_HISTORIES).unwrap();
            let current = table.get(package).unwrap().unwrap().value().to_vec();
            let mut history = decode_history(&current).unwrap();
            mutate(&mut history);
            let encoded = encode_history(&history).unwrap();
            table.insert(package, encoded.as_slice()).unwrap();
        }
        write.commit().unwrap();
    }

    fn rewrite_stored_header(path: &Path, mutate: impl FnOnce(&mut SnapshotHeaderV1)) {
        let database = Database::create(path).unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(SNAPSHOT_HEADER).unwrap();
            let current = table.get(HEADER_KEY).unwrap().unwrap().value().to_vec();
            let mut header: SnapshotHeaderV1 = serde_json::from_slice(&current).unwrap();
            mutate(&mut header);
            let encoded = encode_header(&header).unwrap();
            table.insert(HEADER_KEY, encoded.as_slice()).unwrap();
        }
        write.commit().unwrap();
    }

    fn delete_stored_history(path: &Path, package: &str) {
        let database = Database::create(path).unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(PACKAGE_HISTORIES).unwrap();
            table.remove(package).unwrap();
        }
        write.commit().unwrap();
    }
    #[test]
    fn build_reopens_and_is_deterministic() {
        let dir = tempdir().unwrap();
        let one = dir.path().join("one.redb");
        let two = dir.path().join("two.redb");
        let a = SnapshotGenerationBuilder::new(input(), &one)
            .build()
            .unwrap();
        let b = SnapshotGenerationBuilder::new(input(), &two)
            .build()
            .unwrap();
        assert_eq!(
            a.generation(),
            "425c12be202fdc0ad84dda4f327a42202a185345f90068b56c0dec8e13ac1241"
        );
        assert_eq!(a.generation(), b.generation());
        assert_eq!(a.header_bytes(), b.header_bytes());
    }

    #[test]
    fn source_reordering_remaps_observations_without_mutating_input() {
        let dir = tempdir().unwrap();
        let (canonical_input, input_source_ids) = two_source_input();
        let mut reversed_input = canonical_input.clone();
        reversed_input.sources.reverse();
        reversed_input.histories[0].observations[0].source_index = 1;
        reversed_input.histories[0].observations[1].source_index = 0;

        let first = SnapshotGenerationBuilder::new(
            canonical_input.clone(),
            dir.path().join("canonical.redb"),
        )
        .build()
        .unwrap();
        let second = SnapshotGenerationBuilder::new(
            reversed_input.clone(),
            dir.path().join("reversed.redb"),
        )
        .build()
        .unwrap();

        assert_eq!(first.generation(), second.generation());
        assert_eq!(first.header_bytes(), second.header_bytes());
        assert_eq!(canonical_input.histories[0].observations[0].source_index, 0);
        assert_eq!(canonical_input.histories[0].observations[1].source_index, 1);
        let history = stored_history(second.path());
        for (observation, input_source_id) in history.observations.iter().zip(input_source_ids) {
            assert_eq!(
                second.header().sources[observation.source_index as usize].id,
                input_source_id
            );
        }
    }

    #[test]
    fn bare_destination_uses_current_directory_without_changing_it() {
        assert_eq!(
            destination_parent(Path::new("generation.redb")),
            Path::new(".")
        );
        assert_eq!(
            destination_parent(Path::new("nested/generation.redb")),
            Path::new("nested")
        );
    }

    #[test]
    fn read_only_loader_maps_present_and_missing_states_without_io() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("present.redb");
        SnapshotGenerationBuilder::new(present_input(), &path)
            .build()
            .unwrap();
        let loader =
            ReadOnlySnapshotCandidateLoader::open(&path, RegistryId::new("cran").unwrap()).unwrap();
        let releases = loader
            .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
            .unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version().to_string(), "1.0");
        let missing = loader
            .releases(&SolverKey::InstalledName(PackageName::new("bar").unwrap()))
            .unwrap_err();
        assert_eq!(missing.category(), CandidateLoadErrorCategory::NotFound);
        let unsupported = loader.releases(&SolverKey::R).unwrap_err();
        assert_eq!(unsupported.category(), CandidateLoadErrorCategory::NotFound);
    }

    #[test]
    fn read_only_loader_maps_partial_and_incomplete_missing_states() {
        let dir = tempdir().unwrap();
        let mut partial = input();
        partial.coverage.state = "partial".into();
        let partial_path = dir.path().join("partial.redb");
        SnapshotGenerationBuilder::new(partial, &partial_path)
            .build()
            .unwrap();
        let partial_loader =
            ReadOnlySnapshotCandidateLoader::open(&partial_path, RegistryId::new("cran").unwrap())
                .unwrap();
        let partial_error = partial_loader
            .releases(&SolverKey::InstalledName(PackageName::new("bar").unwrap()))
            .unwrap_err();
        assert_eq!(
            partial_error.category(),
            CandidateLoadErrorCategory::MetadataInvalid
        );

        let incomplete_path = dir.path().join("incomplete.redb");
        SnapshotGenerationBuilder::new(input(), &incomplete_path)
            .build()
            .unwrap();
        let incomplete_loader = ReadOnlySnapshotCandidateLoader::open(
            &incomplete_path,
            RegistryId::new("cran").unwrap(),
        )
        .unwrap();
        let incomplete_error = incomplete_loader
            .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
            .unwrap_err();
        assert_eq!(
            incomplete_error.category(),
            CandidateLoadErrorCategory::MetadataInvalid
        );
    }

    #[test]
    fn read_only_loader_rejects_registry_and_wire_revision_mismatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("snapshot.redb");
        SnapshotGenerationBuilder::new(input(), &path)
            .build()
            .unwrap();
        let wrong_registry =
            ReadOnlySnapshotCandidateLoader::open(&path, RegistryId::new("private").unwrap())
                .err()
                .unwrap();
        assert_eq!(
            wrong_registry.category(),
            CandidateLoadErrorCategory::SnapshotInvalid
        );

        let revision_path = dir.path().join("revision.redb");
        SnapshotGenerationBuilder::new(input(), &revision_path)
            .build()
            .unwrap();
        rewrite_stored_header(&revision_path, |header| {
            header.compatibility_profile = 2;
        });
        let revision_error =
            ReadOnlySnapshotCandidateLoader::open(&revision_path, RegistryId::new("cran").unwrap())
                .err()
                .unwrap();
        assert_eq!(
            revision_error.category(),
            CandidateLoadErrorCategory::SnapshotInvalid
        );

        let count_path = dir.path().join("count.redb");
        SnapshotGenerationBuilder::new(input(), &count_path)
            .build()
            .unwrap();
        delete_stored_history(&count_path, "foo");
        let count_error =
            ReadOnlySnapshotCandidateLoader::open(&count_path, RegistryId::new("cran").unwrap())
                .err()
                .unwrap();
        assert_eq!(
            count_error.category(),
            CandidateLoadErrorCategory::SnapshotInvalid
        );
    }

    #[test]
    fn read_only_loader_rejects_corrupt_or_inconsistent_history() {
        fn bad_digest(history: &mut PackageHistoryV1) {
            history.eligible_releases[0].metadata_sha256 = [0; 32];
        }
        fn bad_key(history: &mut PackageHistoryV1) {
            history.package = "foo".into();
        }
        fn bad_source(history: &mut PackageHistoryV1) {
            history.observations[0].source_index = 1;
        }
        fn bad_namespace(history: &mut PackageHistoryV1) {
            history.eligible_releases[0].namespace = "bioc".into();
        }
        let cases = [
            ("digest", bad_digest as fn(&mut PackageHistoryV1)),
            ("key", bad_key),
            ("source", bad_source),
            ("namespace", bad_namespace),
        ];
        for (label, mutate) in cases {
            let dir = tempdir().unwrap();
            let path = dir.path().join(format!("{label}.redb"));
            SnapshotGenerationBuilder::new(two_present_input(), &path)
                .build()
                .unwrap();
            rewrite_stored_history(&path, "bar", mutate);
            let loader =
                ReadOnlySnapshotCandidateLoader::open(&path, RegistryId::new("cran").unwrap())
                    .unwrap();
            assert_eq!(
                loader
                    .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
                    .unwrap()
                    .len(),
                1
            );
            let error = loader
                .releases(&SolverKey::InstalledName(PackageName::new("bar").unwrap()))
                .err()
                .unwrap();
            assert_eq!(
                error.category(),
                CandidateLoadErrorCategory::MetadataInvalid
            );
        }
    }
    #[test]
    fn envelope_rejects_trailing_and_corruption() {
        let history = input().histories.remove(0);
        let bytes = encode_history(&history).unwrap();
        assert!(decode_history(&[bytes.as_slice(), &[0]].concat()).is_err());
        let mut corrupt = bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(decode_history(&corrupt).is_err());
    }

    #[test]
    fn header_decoder_rejects_unknown_fields_versions_and_noncanonical_bytes() {
        let dir = tempdir().unwrap();
        let generation = SnapshotGenerationBuilder::new(input(), dir.path().join("a.redb"))
            .build()
            .unwrap();
        let header = generation.header_bytes();
        assert!(decode_header(&[header, b"\n"].concat()).is_err());
        let mut unknown: serde_json::Value = serde_json::from_slice(header).unwrap();
        unknown["unknown"] = serde_json::Value::Bool(true);
        assert!(decode_header(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let mut version: SnapshotHeaderV1 = serde_json::from_slice(header).unwrap();
        version.version = 2;
        assert!(decode_header(&encode_header(&version).unwrap()).is_err());
    }

    #[test]
    fn builder_rejects_bad_source_reference_and_state() {
        let dir = tempdir().unwrap();
        let mut bad_source = input();
        bad_source.histories[0].observations[0].source_index = 1;
        assert!(
            SnapshotGenerationBuilder::new(bad_source, dir.path().join("source.redb"))
                .build()
                .is_err()
        );

        let mut bad_state = input();
        bad_state.histories[0].state = LookupStateV1::Present;
        assert!(
            SnapshotGenerationBuilder::new(bad_state, dir.path().join("state.redb"))
                .build()
                .is_err()
        );
    }

    #[test]
    fn readback_validation_rejects_manifest_mismatch() {
        let dir = tempdir().unwrap();
        let generation = SnapshotGenerationBuilder::new(input(), dir.path().join("a.redb"))
            .build()
            .unwrap();
        let mut header = generation.header().clone();
        header.history_manifest_sha256 = "0".repeat(64);
        let bytes = encode_header(&header).unwrap();
        let histories = BTreeMap::new();
        assert!(write_generation(&dir.path().join("bad.redb"), &bytes, &histories).is_err());
    }

    #[test]
    fn destination_is_never_clobbered_and_failed_temp_is_cleaned() {
        let dir = tempdir().unwrap();
        let orphan = dir.path().join(".rsolve-generation-other.tmp");
        std::fs::write(&orphan, b"invalid temporary generation").unwrap();
        let destination = dir.path().join("existing.redb");
        std::fs::write(&destination, b"sentinel").unwrap();
        let result = SnapshotGenerationBuilder::new(input(), &destination).build();
        assert!(result.is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"sentinel");
        assert_eq!(
            std::fs::read(&orphan).unwrap(),
            b"invalid temporary generation"
        );
        SnapshotGenerationBuilder::new(input(), dir.path().join("new.redb"))
            .build()
            .unwrap();
        assert_eq!(
            std::fs::read(&orphan).unwrap(),
            b"invalid temporary generation"
        );
        let temporary_files = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".rsolve-generation-")
            })
            .count();
        assert_eq!(temporary_files, 1);
    }

    #[test]
    fn nested_collections_and_limits_must_be_canonical() {
        let dir = tempdir().unwrap();
        let mut unsorted = input();
        unsorted.histories[0].decisions = vec![DecisionV1 {
            code: DecisionCodeV1::CurrentOnly,
            observation_ids: vec![0, 0],
            detail: String::new(),
        }];
        assert!(
            SnapshotGenerationBuilder::new(unsorted, dir.path().join("unsorted.redb"))
                .build()
                .is_err()
        );

        let mut oversized = input();
        oversized.histories[0].observations[0].fields = (0..=MEMBER_LIMIT)
            .map(|index| FieldV1 {
                name: format!("f{index:05}"),
                value: "v".into(),
            })
            .collect();
        assert!(
            SnapshotGenerationBuilder::new(oversized, dir.path().join("oversized.redb"))
                .build()
                .is_err()
        );
    }

    #[test]
    fn versions_use_numeric_components_and_reject_logical_duplicates() {
        let one_nine = RPackageVersion::parse("1.9").unwrap();
        let one_ten = RPackageVersion::parse("1.10").unwrap();
        assert!(canonical_version_components(&one_nine) < canonical_version_components(&one_ten));
        let clause_nine = ClauseV1 {
            op: RelationOpV1::Ge,
            version: "1.9".into(),
        };
        let clause_ten = ClauseV1 {
            op: RelationOpV1::Ge,
            version: "1.10".into(),
        };
        assert!(clause_order_key(&clause_nine).unwrap() < clause_order_key(&clause_ten).unwrap());
        let releases = vec![
            EligibleReleaseV1 {
                package: "foo".into(),
                version: "1.0".into(),
                namespace: "cran".into(),
                metadata: vec![],
                publication: None,
                dependencies: vec![],
                distributions: vec![],
                metadata_sha256: [1; 32],
                evidence: vec![],
            },
            EligibleReleaseV1 {
                package: "foo".into(),
                version: "1.0.0".into(),
                namespace: "cran".into(),
                metadata: vec![],
                publication: None,
                dependencies: vec![],
                distributions: vec![],
                metadata_sha256: [2; 32],
                evidence: vec![],
            },
        ];
        assert!(validate_release_order(&releases).is_err());
    }

    #[test]
    fn header_rejects_observation_timestamp_generation_and_revision_mismatch() {
        let dir = tempdir().unwrap();
        let mut bad_timestamp = input();
        bad_timestamp.sources[0].observed_at = "not-a-timestamp".into();
        assert!(
            SnapshotGenerationBuilder::new(bad_timestamp, dir.path().join("timestamp.redb"))
                .build()
                .is_err()
        );

        let generation = SnapshotGenerationBuilder::new(input(), dir.path().join("valid.redb"))
            .build()
            .unwrap();
        let mut bad_generation = generation.header().clone();
        bad_generation.generation = "0".repeat(64);
        assert!(decode_header(&encode_header(&bad_generation).unwrap()).is_err());

        let mut bad_revision = input();
        bad_revision.compatibility_profile = 2;
        assert!(
            SnapshotGenerationBuilder::new(bad_revision, dir.path().join("revision.redb"))
                .build()
                .is_err()
        );
    }
}
