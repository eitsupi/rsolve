//! Read-only conversion of an archive package index RDS matrix.

use std::error::Error;
use std::fmt;

use rd_rds::{file::ReadOptions, package::PackagesMatrix};

use super::catalog::{
    CranCatalog, CranDiagnostic, catalog_from_observations, observation_from_fields,
};

/// A structural or semantic failure while reading and validating an archive
/// package index.
#[derive(Debug)]
pub enum CranArchiveIndexError {
    Decode(rd_rds::file::ReadError),
    Matrix(rd_rds::package::ViewError),
    MissingColumn(&'static str),
    Semantic(Box<[CranDiagnostic]>),
}

impl CranArchiveIndexError {
    /// Returns all semantic row diagnostics in source order.
    pub fn diagnostics(&self) -> &[CranDiagnostic] {
        match self {
            Self::Semantic(diagnostics) => diagnostics,
            Self::Decode(_) | Self::Matrix(_) | Self::MissingColumn(_) => &[],
        }
    }
}

impl fmt::Display for CranArchiveIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "invalid archive index RDS: {error}"),
            Self::Matrix(error) => write!(formatter, "invalid archive index matrix: {error}"),
            Self::MissingColumn(column) => {
                write!(
                    formatter,
                    "archive index matrix is missing required column {column}"
                )
            }
            Self::Semantic(diagnostics) => {
                if diagnostics.is_empty() {
                    return formatter.write_str("semantic archive index records are invalid");
                }
                write!(
                    formatter,
                    "{} semantic archive index record(s) are invalid: {}",
                    diagnostics.len(),
                    diagnostics[0]
                )?;
                if diagnostics.len() > 1 {
                    write!(
                        formatter,
                        ", and {} additional diagnostic(s)",
                        diagnostics.len() - 1
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl Error for CranArchiveIndexError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Matrix(error) => Some(error),
            Self::MissingColumn(_) => None,
            Self::Semantic(_) => None,
        }
    }
}

impl CranCatalog {
    /// Reads an archive package index RDS byte stream into the ordinary CRAN
    /// candidate catalog. Upstream observations are that these rows are in
    /// archival order rather than semantic-version order and that the current
    /// package version is excluded; neither observation is a reader
    /// guarantee, and this reader preserves every row it receives.
    pub fn from_archive_index_rds(input: &[u8]) -> Result<Self, CranArchiveIndexError> {
        Self::from_archive_index_rds_with_options(input, &ReadOptions::default())
    }

    /// Alias for [`Self::from_archive_index_rds`].
    pub fn from_archive_packages_rds(input: &[u8]) -> Result<Self, CranArchiveIndexError> {
        Self::from_archive_index_rds(input)
    }

    /// Reads an archive package index with caller-selected RDS size limits.
    pub fn from_archive_index_rds_with_options(
        input: &[u8],
        options: &ReadOptions,
    ) -> Result<Self, CranArchiveIndexError> {
        let object = rd_rds::file::from_bytes_with_options(input, options)
            .map_err(CranArchiveIndexError::Decode)?;
        let matrix = PackagesMatrix::from_object(&object).map_err(CranArchiveIndexError::Matrix)?;
        for column in ["Package", "Version"] {
            if matrix.column(column).is_none() {
                return Err(CranArchiveIndexError::MissingColumn(column));
            }
        }

        let observations = matrix.rows().map(|row| {
            let package = row.get("Package").flatten().map(str::to_owned);
            let fields = matrix
                .column_names()
                .filter_map(|column| {
                    row.get(column)
                        .flatten()
                        .map(|value| (column.to_owned(), value.to_owned()))
                })
                .collect::<Vec<_>>();
            let field_refs = fields
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            (row.index(), package, observation_from_fields(&field_refs))
        });

        catalog_from_observations(observations).map_err(CranArchiveIndexError::Semantic)
    }
}
