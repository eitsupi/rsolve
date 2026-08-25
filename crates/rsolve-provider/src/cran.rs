//! CRAN-compatible input formats.

mod archive_index;
mod catalog;
mod dcf;
pub(crate) mod evidence;
mod history;
pub(crate) mod provider;
pub(crate) mod publish;

pub use archive_index::CranArchiveIndexError;
pub use catalog::{
    CranCatalog, CranCatalogError, CranDiagnostic, CranRecordError, DependencyParseError,
};
pub use dcf::{DcfDocument, DcfError, DcfField, DcfRecord};
pub use history::{ArchiveEntry, CranHistoryError, enumerate_archive_rds};
pub use provider::{
    CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA,
    CranCandidateSnapshot, CranCurrentIndexRepresentation, CranFastPathStatus, CranMetadataConfig,
    CranRefreshDiagnostic, CranRefreshSource, CranSnapshotCacheDiagnostic, CranSnapshotCachePolicy,
    CranSnapshotCacheResult, CranSnapshotCacheStatus, CranSnapshotRefresher,
    CranSnapshotRefresherError, DEFAULT_ALLPACKAGES_FEED_ENDPOINT,
    DEFAULT_COMPATIBLE_GENERATION_TTL, inspect_cran_snapshot_cache,
};

pub use publish::CranSnapshotPublishError;
