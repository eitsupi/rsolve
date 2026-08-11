//! CRAN-compatible input formats.

mod archive_index;
mod catalog;
mod dcf;
mod history;
pub(crate) mod provider;

pub use archive_index::CranArchiveIndexError;
pub use catalog::{
    CranCatalog, CranCatalogError, CranDiagnostic, CranRecordError, DependencyParseError,
};
pub use dcf::{DcfDocument, DcfError, DcfField, DcfRecord};
pub use history::{ArchiveEntry, CranHistoryError, enumerate_archive_rds};
pub use provider::{
    CranCandidateLoader, CranCandidateLoaderError, CranCandidateSnapshot,
    CranCurrentIndexRepresentation, CranFastPathStatus, CranRefreshDiagnostic, CranRefreshSource,
};
