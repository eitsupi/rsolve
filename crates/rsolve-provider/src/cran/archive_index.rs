//! Read-only conversion of an archive package index RDS matrix.

#[cfg(test)]
use std::cell::Cell;
use std::error::Error;
use std::fmt;

use rd_rds::{NativeEncodingPolicy, file::ReadOptions, package::PackagesMatrix};

use super::catalog::{
    CranArchiveReleaseRejection, CranCatalog, CranCatalogObservation, CranCatalogRecordContext,
    CranCatalogRecordScope, CranDiagnostic, CranProviderObservationProjection, CranRecordError,
    provider_observations_from_fields, validated_observations_from_fields,
};

#[cfg(test)]
thread_local! {
    static ARCHIVE_IMPORT_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_archive_import_count() {
    ARCHIVE_IMPORT_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn archive_import_count() -> usize {
    ARCHIVE_IMPORT_COUNT.with(Cell::get)
}

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

/// Options used at the provider's CRAN-compatible repository boundary.
///
/// To match the existing DCF reader, rsolve treats this boundary as UTF-8,
/// including format-2 RDS streams whose headers do not carry a native
/// encoding marker. Public option-taking APIs remain caller-controlled; this
/// helper is only for the provider's repository boundary.
pub(crate) fn provider_rds_read_options() -> ReadOptions {
    ReadOptions::default().native_encoding_policy(NativeEncodingPolicy::AssumeUtf8)
}

pub(crate) struct CranArchiveIndexProviderProjection {
    pub(crate) catalog: CranCatalog,
    pub(crate) observations: Vec<CranCatalogObservation>,
    pub(crate) rejections: Vec<CranArchiveReleaseRejection>,
}

#[derive(Debug)]
pub(crate) enum CranArchiveIndexProviderError {
    Structural(CranArchiveIndexError),
    Identity(Box<[CranDiagnostic]>),
    AllSemantic(Box<[CranDiagnostic]>),
}

impl fmt::Display for CranArchiveIndexProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structural(error) => error.fmt(formatter),
            Self::Identity(diagnostics) => write_provider_diagnostics(
                formatter,
                "archive index identity records are invalid",
                diagnostics,
            ),
            Self::AllSemantic(diagnostics) => write_provider_diagnostics(
                formatter,
                "all archive index releases have invalid semantics",
                diagnostics,
            ),
        }
    }
}

fn write_provider_diagnostics(
    formatter: &mut fmt::Formatter<'_>,
    prefix: &str,
    diagnostics: &[CranDiagnostic],
) -> fmt::Result {
    write!(formatter, "{prefix}: ")?;
    if let Some(first) = diagnostics.first() {
        write!(formatter, "{first}")?;
        if diagnostics.len() > 1 {
            write!(
                formatter,
                ", and {} additional diagnostic(s)",
                diagnostics.len() - 1
            )?;
        }
    } else {
        formatter.write_str("no diagnostics")?;
    }
    Ok(())
}

/// Reads an archive index for the provider boundary. Release-local semantic
/// failures are quarantined, while structural and identity failures reject
/// the whole response so they cannot be misattributed to a sibling release.
pub(crate) fn provider_archive_index_rds(
    input: &[u8],
    expected_package: &rsolve_core::PackageName,
) -> Result<CranArchiveIndexProviderProjection, CranArchiveIndexProviderError> {
    let object = rd_rds::file::from_bytes_with_options(input, &provider_rds_read_options())
        .map_err(CranArchiveIndexError::Decode)
        .map_err(CranArchiveIndexProviderError::Structural)?;
    let matrix = PackagesMatrix::from_object(&object)
        .map_err(CranArchiveIndexError::Matrix)
        .map_err(CranArchiveIndexProviderError::Structural)?;
    for column in ["Package", "Version"] {
        if matrix.column(column).is_none() {
            return Err(CranArchiveIndexProviderError::Structural(
                CranArchiveIndexError::MissingColumn(column),
            ));
        }
    }
    let records = matrix
        .rows()
        .map(|row| {
            let package = row.get("Package").flatten().map(str::to_owned);
            let fields = matrix
                .column_names()
                .filter_map(|column| {
                    row.get(column)
                        .flatten()
                        .map(|value| (column.to_owned(), value.to_owned()))
                })
                .collect::<Vec<_>>();
            (row.index(), package, fields)
        })
        .collect();
    let CranProviderObservationProjection {
        observations,
        rejections,
    } = provider_observations_from_fields(
        records,
        CranCatalogRecordContext::PackagesIndex,
        Some(expected_package),
    );
    let hard = rejections
        .iter()
        .filter(|diagnostic| provider_rejection_is_hard(diagnostic, expected_package))
        .map(CranArchiveReleaseRejection::diagnostic)
        .collect::<Vec<_>>();
    if !hard.is_empty() {
        return Err(CranArchiveIndexProviderError::Identity(
            hard.into_boxed_slice(),
        ));
    }
    // A structurally valid archive matrix may legitimately contain no
    // releases (for example, while a package has no archived versions).
    // Only an archive made entirely of rejected rows is semantically invalid.
    if observations.is_empty() && !rejections.is_empty() {
        return Err(CranArchiveIndexProviderError::AllSemantic(
            rejections
                .iter()
                .map(CranArchiveReleaseRejection::diagnostic)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ));
    }
    Ok(CranArchiveIndexProviderProjection {
        catalog: CranCatalog::from_provider_observations(&observations),
        observations,
        rejections,
    })
}

fn provider_rejection_is_hard(
    rejection: &CranArchiveReleaseRejection,
    expected_package: &rsolve_core::PackageName,
) -> bool {
    if rejection.package().is_none() || rejection.scope().is_none() {
        return true;
    }
    if rejection.version().is_none() {
        return !matches!(
            (rejection.error(), rejection.package(), rejection.scope()),
            (
                CranRecordError::InvalidVersion(_),
                Some(package),
                Some(CranCatalogRecordScope::Root),
            ) if package == expected_package
        );
    }
    match rejection.error() {
        CranRecordError::MissingField("Package")
        | CranRecordError::MissingField("Version")
        | CranRecordError::InvalidPackageName(_)
        | CranRecordError::InvalidVersion(_)
        | CranRecordError::UnexpectedPackage { .. } => true,
        CranRecordError::DuplicateField(field) => matches!(
            field.to_ascii_lowercase().as_str(),
            "package" | "version" | "path"
        ),
        CranRecordError::Domain(rsolve_core::PackageReleaseError::InvalidDependency { .. }) => {
            false
        }
        CranRecordError::Dependency { .. } => false,
        CranRecordError::InvalidPath { .. } => true,
        CranRecordError::Domain(_) => true,
        _ => false,
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
        Self::from_archive_index_rds_with_observations(input, options).map(|(catalog, _)| catalog)
    }

    pub(crate) fn from_archive_index_rds_with_observations(
        input: &[u8],
        options: &ReadOptions,
    ) -> Result<(Self, Vec<CranCatalogObservation>), CranArchiveIndexError> {
        #[cfg(test)]
        ARCHIVE_IMPORT_COUNT.with(|count| count.set(count.get() + 1));
        let object = rd_rds::file::from_bytes_with_options(input, options)
            .map_err(CranArchiveIndexError::Decode)?;
        let matrix = PackagesMatrix::from_object(&object).map_err(CranArchiveIndexError::Matrix)?;
        for column in ["Package", "Version"] {
            if matrix.column(column).is_none() {
                return Err(CranArchiveIndexError::MissingColumn(column));
            }
        }

        let records = matrix
            .rows()
            .map(|row| {
                let package = row.get("Package").flatten().map(str::to_owned);
                let fields = matrix
                    .column_names()
                    .filter_map(|column| {
                        row.get(column)
                            .flatten()
                            .map(|value| (column.to_owned(), value.to_owned()))
                    })
                    .collect::<Vec<_>>();
                (row.index(), package, fields)
            })
            .collect();

        let observations =
            validated_observations_from_fields(records).map_err(|error| match error {
                super::catalog::CranCatalogError::Dcf(_) => {
                    CranArchiveIndexError::Semantic(Box::new([]))
                }
                super::catalog::CranCatalogError::Semantic(diagnostics) => {
                    CranArchiveIndexError::Semantic(diagnostics)
                }
            })?;
        let catalog = CranCatalog::from_provider_observations(&observations);
        Ok((catalog, observations))
    }

    #[cfg(test)]
    pub(crate) fn observations_from_archive_index_rds(
        input: &[u8],
    ) -> Result<Vec<CranCatalogObservation>, CranArchiveIndexError> {
        Self::from_archive_index_rds_with_observations(input, &provider_rds_read_options())
            .map(|(_, observations)| observations)
    }
}

#[cfg(test)]
mod tests {
    use super::{CranArchiveIndexProviderError, provider_archive_index_rds};
    use crate::cran::catalog::{CranCatalogRecordScope, CranRecordError};
    use rsolve_core::PackageName;

    const MATRIX_ARCHIVE: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-PACKAGES.rds"
    );
    const EMPTY_MATRIX_ARCHIVE: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-empty-matrix-archive-PACKAGES.rds"
    );
    const NLME_ARCHIVE: &[u8] =
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-nlme-archive-PACKAGES.rds");
    const NLME_INVALID_ARCHIVE: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-nlme-invalid-archive-PACKAGES.rds"
    );
    const NLME_INVALID_IDENTITY_ARCHIVE: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-nlme-invalid-identity-archive-PACKAGES.rds"
    );
    const NLME_INVALID_VERSION_ARCHIVE: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-nlme-invalid-version-archive-PACKAGES.rds"
    );
    const NLME_ALL_INVALID_VERSION_ARCHIVE: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-nlme-all-invalid-version-archive-PACKAGES.rds"
    );
    const INVALID_PATH_ARCHIVE: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-invalid-path-PACKAGES.rds"
    );

    #[test]
    fn provider_archive_projection_enforces_expected_package() {
        let package = PackageName::new("Matrix").unwrap();
        let projection = provider_archive_index_rds(MATRIX_ARCHIVE, &package)
            .expect("Matrix archive projection");
        assert_eq!(projection.catalog.candidate_count(), 2);
        assert!(projection.rejections.is_empty());
    }

    #[test]
    fn provider_archive_projection_accepts_empty_matrix() {
        let package = PackageName::new("Matrix").unwrap();
        let projection = provider_archive_index_rds(EMPTY_MATRIX_ARCHIVE, &package)
            .expect("empty Matrix archive projection");
        assert_eq!(projection.catalog.candidate_count(), 0);
        assert!(projection.observations.is_empty());
        assert!(projection.rejections.is_empty());
    }

    #[test]
    fn provider_archive_projection_quarantines_invalid_dependency_versions() {
        let package = PackageName::new("nlme").unwrap();
        let projection = provider_archive_index_rds(NLME_ARCHIVE, &package)
            .expect("valid nlme siblings must survive a semantic rejection");
        assert_eq!(projection.catalog.candidate_count(), 2);
        assert_eq!(projection.observations.len(), 2);
        assert_eq!(projection.rejections.len(), 1);
        let rejection = &projection.rejections[0];
        assert_eq!(rejection.record_index(), 2);
        assert_eq!(rejection.package().unwrap().as_str(), "nlme");
        assert_eq!(rejection.version().unwrap().as_str(), "3.1-166");
        assert!(matches!(
            rejection.scope(),
            Some(CranCatalogRecordScope::Root)
        ));
        assert!(matches!(
            rejection.error(),
            CranRecordError::Dependency {
                field: "Depends",
                ..
            }
        ));
        assert!(
            rejection
                .fields()
                .iter()
                .any(|(name, value)| { name == "Package" && value == "nlme" })
        );
        assert!(
            rejection
                .fields()
                .iter()
                .any(|(name, value)| { name == "Version" && value == "3.1-166" })
        );
        assert!(
            rejection
                .fields()
                .iter()
                .any(|(name, value)| { name == "Depends" && value == "R (>= 3.6.x)" })
        );
    }

    #[test]
    fn provider_archive_projection_rejects_all_semantically_invalid_rows() {
        let package = PackageName::new("nlme").unwrap();
        let error = match provider_archive_index_rds(NLME_INVALID_ARCHIVE, &package) {
            Ok(_) => panic!("an archive with no valid releases must fail closed"),
            Err(error) => error,
        };
        let CranArchiveIndexProviderError::AllSemantic(diagnostics) = error else {
            panic!("expected all-semantic rejection");
        };
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].to_string().contains("nlme"));
        assert!(diagnostics[0].to_string().contains("3.6.x"));
    }

    #[test]
    fn provider_archive_projection_keeps_pathless_identity_failures_hard() {
        let package = PackageName::new("nlme").unwrap();
        let error = match provider_archive_index_rds(NLME_INVALID_IDENTITY_ARCHIVE, &package) {
            Ok(_) => panic!("invalid package identity must fail closed"),
            Err(error) => error,
        };
        let CranArchiveIndexProviderError::Identity(diagnostics) = error else {
            panic!("expected identity rejection");
        };
        assert_eq!(diagnostics.len(), 1);
        assert!(
            diagnostics[0]
                .to_string()
                .contains("package name has an invalid character")
        );
    }

    #[test]
    fn provider_archive_projection_quarantines_pathless_invalid_version() {
        let package = PackageName::new("nlme").unwrap();
        let projection = provider_archive_index_rds(NLME_INVALID_VERSION_ARCHIVE, &package)
            .expect("valid siblings must survive an invalid raw Version");
        assert_eq!(projection.catalog.candidate_count(), 2);
        assert_eq!(projection.rejections.len(), 1);
        let rejection = &projection.rejections[0];
        assert_eq!(rejection.package().unwrap().as_str(), "nlme");
        assert!(rejection.version().is_none());
        assert!(matches!(
            rejection.scope(),
            Some(CranCatalogRecordScope::Root)
        ));
        assert!(matches!(
            rejection.error(),
            CranRecordError::InvalidVersion(_)
        ));
        assert!(
            rejection
                .fields()
                .iter()
                .any(|(name, value)| { name == "Version" && value == "3.1-2 (1999/12/23)" })
        );
    }

    #[test]
    fn provider_archive_projection_rejects_all_pathless_invalid_versions() {
        let package = PackageName::new("nlme").unwrap();
        let error = match provider_archive_index_rds(NLME_ALL_INVALID_VERSION_ARCHIVE, &package) {
            Ok(_) => panic!("all invalid Version rows must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CranArchiveIndexProviderError::AllSemantic(_)
        ));
    }

    #[test]
    fn provider_archive_projection_keeps_invalid_recommended_path_hard() {
        let package = PackageName::new("Matrix").unwrap();
        let error = match provider_archive_index_rds(INVALID_PATH_ARCHIVE, &package) {
            Ok(_) => panic!("invalid Recommended Path must fail closed"),
            Err(error) => error,
        };
        let CranArchiveIndexProviderError::Identity(diagnostics) = error else {
            panic!("expected invalid Path identity rejection");
        };
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].to_string().contains("NotRecommended"));
    }
}
