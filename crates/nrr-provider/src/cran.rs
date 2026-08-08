//! CRAN-compatible input formats.

mod dcf;

pub use dcf::{DcfDocument, DcfError, DcfField, DcfRecord};
