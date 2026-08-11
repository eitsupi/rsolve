//! CRAN-compatible input formats.

mod archive_index;
mod catalog;
mod dcf;

pub use archive_index::CranArchiveIndexError;
pub use catalog::{
    CranCatalog, CranCatalogError, CranDiagnostic, CranRecordError, DependencyParseError,
};
pub use dcf::{DcfDocument, DcfError, DcfField, DcfRecord};
