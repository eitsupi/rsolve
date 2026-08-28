//! Conversion of a current CRAN `PACKAGES` DCF index into domain candidates.

#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt;

use rsolve_core::{
    DeclaredDependency, DependencyKind, DependencySourceConstraint, Distribution,
    DistributionChannel, DistributionMetadata, PackageName, PackageNameError, PackageRelease,
    PackageReleaseError, Provenance, PublicationDate, RPackageVersion, RPackageVersionError,
    RegistryId, RelationOp, ReleaseAggregation, ReleaseIdentity, ReleaseMetadata,
    ReleaseMetadataError, ReleaseObservation, VersionConstraint,
};

use super::{DcfDocument, DcfError};

mod dependency;
mod import;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use import::observation_from_fields;
pub(crate) use import::{
    allpackages_observations_from_fields, provider_observations_from_fields,
    validated_observations_from_fields,
};
use import::{
    observation_from_fields_with_context, observation_scope,
    validated_observations_from_fields_with_context,
};

const CRAN_NAMESPACE: &str = "cran";
const SOURCE_CHANNEL: &str = "source";

#[cfg(test)]
thread_local! {
    static PACKAGES_IMPORT_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_packages_import_count() {
    PACKAGES_IMPORT_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn packages_import_count() -> usize {
    PACKAGES_IMPORT_COUNT.with(Cell::get)
}

/// A candidate catalog produced from one pinned current CRAN index.
#[derive(Clone, Debug, Default)]
pub struct CranCatalog {
    candidates: BTreeMap<PackageName, Vec<PackageRelease>>,
}

/// One validated CRAN catalog record together with its lossless source fields.
#[derive(Clone, Debug)]
pub(crate) struct CranCatalogObservation {
    record_index: usize,
    package: PackageName,
    fields: Vec<(String, String)>,
    release: PackageRelease,
    scope: CranCatalogRecordScope,
}

#[derive(Clone, Debug)]
pub(crate) struct CranArchiveReleaseRejection {
    record_index: usize,
    package: Option<PackageName>,
    version: Option<RPackageVersion>,
    scope: Option<CranCatalogRecordScope>,
    fields: Vec<(String, String)>,
    error: CranRecordError,
}

impl CranArchiveReleaseRejection {
    pub(crate) fn record_index(&self) -> usize {
        self.record_index
    }

    pub(crate) fn package(&self) -> Option<&PackageName> {
        self.package.as_ref()
    }

    pub(crate) fn version(&self) -> Option<&RPackageVersion> {
        self.version.as_ref()
    }

    pub(crate) fn scope(&self) -> Option<&CranCatalogRecordScope> {
        self.scope.as_ref()
    }

    pub(crate) fn fields(&self) -> &[(String, String)] {
        &self.fields
    }

    pub(crate) fn error(&self) -> &CranRecordError {
        &self.error
    }

    pub(crate) fn diagnostic(&self) -> CranDiagnostic {
        CranDiagnostic {
            record_index: self.record_index,
            package: self.package.as_ref().map(ToString::to_string),
            error: self.error.clone(),
        }
    }
}

/// Provider-facing archive projection that keeps valid releases separate from
/// release-local semantic rejections. Structural and identity failures remain
/// diagnostics for the caller to reject as a whole.
pub(crate) struct CranProviderObservationProjection {
    pub(crate) observations: Vec<CranCatalogObservation>,
    pub(crate) rejections: Vec<CranArchiveReleaseRejection>,
}

/// The semantic scope of a CRAN package-index record.
///
/// A record under `R/Recommended` describes an R-runtime-specific occurrence,
/// not the registry release in the CRAN root index.  Keeping this distinction
/// here makes catalog and evidence selection use the same classification.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum CranCatalogRecordScope {
    Root,
    RecommendedOverlay { runtime: RPackageVersion },
}

type CatalogRecord = (usize, Option<String>, Vec<(String, String)>);

/// Identifies the source format whose records are being parsed.
///
/// CRAN's `PACKAGES` indexes use `Path` to identify Recommended overlays and
/// therefore require strict validation. A package archive's `DESCRIPTION` may
/// contain an unrelated `Path` metadata field, so it must remain a root
/// release without applying the index-only overlay interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CranCatalogRecordContext {
    PackagesIndex,
    Description,
}

impl CranCatalogObservation {
    pub(crate) fn record_index(&self) -> usize {
        self.record_index
    }

    pub(crate) fn package(&self) -> &PackageName {
        &self.package
    }

    pub(crate) fn fields(&self) -> &[(String, String)] {
        &self.fields
    }

    pub(crate) fn release(&self) -> &PackageRelease {
        &self.release
    }

    pub(crate) fn scope(&self) -> &CranCatalogRecordScope {
        &self.scope
    }
}

impl CranCatalog {
    pub(crate) fn from_provider_observations(observations: &[CranCatalogObservation]) -> Self {
        let mut aggregation = ReleaseAggregation::new();
        for observation in observations {
            if matches!(
                observation.scope,
                CranCatalogRecordScope::RecommendedOverlay { .. }
            ) {
                continue;
            }
            aggregation
                .observe_release(observation.release.clone())
                .expect("provider projection validated release aggregation");
        }
        let mut candidates: BTreeMap<PackageName, Vec<PackageRelease>> = BTreeMap::new();
        for release in aggregation.releases() {
            candidates
                .entry(release.identity().name().clone())
                .or_default()
                .push(release.clone());
        }
        for releases in candidates.values_mut() {
            releases.sort_by(|left, right| left.version().cmp(right.version()));
        }
        Self { candidates }
    }

    /// Parses and converts a plain `src/contrib/PACKAGES` snapshot.
    ///
    /// DCF syntax errors fail the operation because record boundaries cannot
    /// be trusted. A semantically malformed record rejects the catalog, with
    /// all record diagnostics retained in source order.
    pub fn from_packages(input: &[u8]) -> Result<Self, CranCatalogError> {
        Self::from_packages_with_observations(input).map(|(catalog, _)| catalog)
    }

    /// Parses and validates a plain PACKAGES index once, returning both the
    /// candidate catalog and the lossless observations projected from it.
    pub(crate) fn from_packages_with_observations(
        input: &[u8],
    ) -> Result<(Self, Vec<CranCatalogObservation>), CranCatalogError> {
        #[cfg(test)]
        PACKAGES_IMPORT_COUNT.with(|count| count.set(count.get() + 1));
        let document = DcfDocument::parse(input).map_err(CranCatalogError::Dcf)?;
        let records = document
            .records()
            .iter()
            .enumerate()
            .map(|(record_index, record)| {
                let package = record
                    .field("Package")
                    .map(|field| field.value().to_owned());
                let fields = record
                    .fields()
                    .iter()
                    .map(|field| (field.name().to_owned(), field.value().to_owned()))
                    .collect();
                (record_index, package, fields)
            })
            .collect();
        let observations = validated_observations_from_fields_with_context(
            records,
            CranCatalogRecordContext::PackagesIndex,
        )?;
        let catalog = Self::from_provider_observations(&observations);
        Ok((catalog, observations))
    }

    /// Alias for [`Self::from_packages`].
    pub fn parse(input: &[u8]) -> Result<Self, CranCatalogError> {
        Self::from_packages(input)
    }

    /// Parses a package archive's `DESCRIPTION` DCF record.
    ///
    /// Unlike a `PACKAGES` index, a `DESCRIPTION` record treats `Path` as
    /// ordinary package metadata. Archive descriptions are root releases and
    /// do not describe Recommended overlays.
    pub(crate) fn from_description(input: &[u8]) -> Result<Self, CranCatalogError> {
        let document = DcfDocument::parse(input).map_err(CranCatalogError::Dcf)?;
        let observations = document
            .records()
            .iter()
            .enumerate()
            .map(|(record_index, record)| {
                let package = record
                    .field("Package")
                    .map(|field| field.value().to_owned());
                let fields = record
                    .fields()
                    .iter()
                    .map(|field| (field.name(), field.value()))
                    .collect::<Vec<_>>();
                (
                    record_index,
                    package,
                    observation_from_fields_with_context(
                        &fields,
                        CranCatalogRecordContext::Description,
                    ),
                )
            });
        catalog_from_observations_with_context(observations, CranCatalogRecordContext::Description)
            .map_err(CranCatalogError::Semantic)
    }

    #[cfg(test)]
    pub(crate) fn observations_from_packages(
        input: &[u8],
    ) -> Result<Vec<CranCatalogObservation>, CranCatalogError> {
        Self::observations_from_dcf(input, CranCatalogRecordContext::PackagesIndex)
    }

    pub(crate) fn observations_from_description(
        input: &[u8],
    ) -> Result<Vec<CranCatalogObservation>, CranCatalogError> {
        Self::observations_from_dcf(input, CranCatalogRecordContext::Description)
    }

    fn observations_from_dcf(
        input: &[u8],
        context: CranCatalogRecordContext,
    ) -> Result<Vec<CranCatalogObservation>, CranCatalogError> {
        let document = DcfDocument::parse(input).map_err(CranCatalogError::Dcf)?;
        let records = document
            .records()
            .iter()
            .enumerate()
            .map(|(record_index, record)| {
                let package = record
                    .field("Package")
                    .map(|field| field.value().to_owned());
                let fields = record
                    .fields()
                    .iter()
                    .map(|field| (field.name().to_owned(), field.value().to_owned()))
                    .collect();
                (record_index, package, fields)
            })
            .collect();
        validated_observations_from_fields_with_context(records, context)
    }

    /// Returns all candidates for a canonical package name in version order.
    pub fn candidates(&self, name: &PackageName) -> &[PackageRelease] {
        self.candidates.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Returns candidates by their textual package name, or `None` when the
    /// name is not a valid R package name.
    pub fn candidates_named(&self, name: &str) -> Option<&[PackageRelease]> {
        let name = PackageName::new(name).ok()?;
        Some(self.candidates(&name))
    }

    /// Returns the catalog's package-to-candidates entries in deterministic
    /// package-name order.
    pub fn packages(&self) -> impl Iterator<Item = (&PackageName, &[PackageRelease])> {
        self.candidates
            .iter()
            .map(|(name, releases)| (name, releases.as_slice()))
    }

    pub fn package_count(&self) -> usize {
        self.candidates.len()
    }

    pub fn candidate_count(&self) -> usize {
        self.candidates.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}
/// A failure while parsing the index as DCF syntax or converting parsed
/// records into validated catalog entries.
#[derive(Debug)]
pub enum CranCatalogError {
    Dcf(DcfError),
    Semantic(Box<[CranDiagnostic]>),
}

impl CranCatalogError {
    /// Returns all semantic record diagnostics in source order.
    pub fn diagnostics(&self) -> &[CranDiagnostic] {
        match self {
            Self::Semantic(diagnostics) => diagnostics,
            Self::Dcf(_) => &[],
        }
    }
}

impl fmt::Display for CranCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dcf(error) => write!(f, "invalid CRAN PACKAGES DCF: {error}"),
            Self::Semantic(diagnostics) => {
                if diagnostics.is_empty() {
                    return f.write_str("semantic CRAN PACKAGES records are invalid");
                }
                write!(
                    f,
                    "{} semantic CRAN PACKAGES record(s) are invalid: {}",
                    diagnostics.len(),
                    diagnostics[0]
                )?;
                if diagnostics.len() > 1 {
                    write!(
                        f,
                        ", and {} additional diagnostic(s)",
                        diagnostics.len() - 1
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl Error for CranCatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Dcf(error) => Some(error),
            Self::Semantic(_) => None,
        }
    }
}

/// A semantic record that was rejected while building a catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CranDiagnostic {
    record_index: usize,
    package: Option<String>,
    error: CranRecordError,
}

impl CranDiagnostic {
    pub fn record_index(&self) -> usize {
        self.record_index
    }

    pub fn package(&self) -> Option<&str> {
        self.package.as_deref()
    }

    pub fn error(&self) -> &CranRecordError {
        &self.error
    }
}

impl fmt::Display for CranDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.package() {
            Some(package) => write!(
                f,
                "record {} ({package}): {}",
                self.record_index, self.error
            ),
            None => write!(f, "record {}: {}", self.record_index, self.error),
        }
    }
}

/// Reasons a syntactically valid DCF record cannot become a candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranRecordError {
    MissingField(&'static str),
    DuplicateField(String),
    InvalidPackageName(PackageNameError),
    InvalidVersion(RPackageVersionError),
    UnexpectedPackage {
        expected: String,
        actual: String,
    },
    InvalidPath {
        value: String,
        diagnostic: String,
    },
    InvalidPublicationDate {
        value: String,
        diagnostic: String,
    },
    InvalidMetadata(ReleaseMetadataError),
    InvalidDependency(String),
    Dependency {
        field: &'static str,
        entry: String,
        source: DependencyParseError,
    },
    Domain(PackageReleaseError),
}

impl fmt::Display for CranRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required field {field}"),
            Self::DuplicateField(field) => write!(f, "duplicate field {field}"),
            Self::InvalidPackageName(error) => error.fmt(f),
            Self::InvalidVersion(error) => error.fmt(f),
            Self::UnexpectedPackage { expected, actual } => {
                write!(
                    f,
                    "archive row belongs to package {actual}, expected {expected}"
                )
            }
            Self::InvalidPath { value, diagnostic } => {
                write!(f, "invalid Path value {value:?}: {diagnostic}")
            }
            Self::InvalidPublicationDate { value, diagnostic } => {
                write!(f, "invalid Published value {value:?}: {diagnostic}")
            }
            Self::InvalidMetadata(error) => error.fmt(f),
            Self::InvalidDependency(error) => write!(f, "invalid dependency: {error}"),
            Self::Dependency {
                field,
                entry,
                source,
            } => write!(f, "invalid {field} entry {entry:?}: {source}"),
            Self::Domain(error) => error.fmt(f),
        }
    }
}

impl Error for CranRecordError {}

/// A malformed comma-separated dependency entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyParseError {
    EmptyEntry,
    InvalidPackageName(PackageNameError),
    InvalidConstraintSyntax,
    MissingConstraintVersion,
    InvalidVersion(RPackageVersionError),
}

impl fmt::Display for DependencyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEntry => f.write_str("dependency entry is empty"),
            Self::InvalidPackageName(error) => error.fmt(f),
            Self::InvalidConstraintSyntax => f.write_str("invalid version constraint syntax"),
            Self::MissingConstraintVersion => f.write_str("version constraint has no version"),
            Self::InvalidVersion(error) => error.fmt(f),
        }
    }
}

impl Error for DependencyParseError {}

pub(super) fn catalog_from_observations_with_context<I>(
    observations: I,
    context: CranCatalogRecordContext,
) -> Result<CranCatalog, Box<[CranDiagnostic]>>
where
    I: IntoIterator<
        Item = (
            usize,
            Option<String>,
            Result<ReleaseObservation, CranRecordError>,
        ),
    >,
{
    let observations = observations.into_iter().collect::<Vec<_>>();
    let (_, aggregation) = select_and_aggregate(observations, context)?;

    let mut candidates: BTreeMap<PackageName, Vec<PackageRelease>> = BTreeMap::new();
    for release in aggregation.releases() {
        candidates
            .entry(release.identity().name().clone())
            .or_default()
            .push(release.clone());
    }
    for releases in candidates.values_mut() {
        releases.sort_by(|left, right| left.version().cmp(right.version()));
    }
    Ok(CranCatalog { candidates })
}

type ParsedCatalogObservation = (
    usize,
    Option<String>,
    Result<ReleaseObservation, CranRecordError>,
);
type SelectedCatalogObservation = (usize, Option<String>, ReleaseObservation);

fn select_and_aggregate(
    observations: Vec<ParsedCatalogObservation>,
    context: CranCatalogRecordContext,
) -> Result<(Vec<SelectedCatalogObservation>, ReleaseAggregation), Box<[CranDiagnostic]>> {
    let mut diagnostics = Vec::new();
    let mut selected = Vec::new();
    let mut aggregation = ReleaseAggregation::new();

    for (record_index, package, observation) in observations {
        match observation {
            Ok(observation) => {
                if matches!(
                    observation_scope(&observation, context),
                    CranCatalogRecordScope::RecommendedOverlay { .. }
                ) {
                    continue;
                }
                if let Err(error) = aggregation.observe(observation.clone()) {
                    diagnostics.push(CranDiagnostic {
                        record_index,
                        package,
                        error: CranRecordError::Domain(error),
                    });
                } else {
                    selected.push((record_index, package, observation));
                }
            }
            Err(error) => diagnostics.push(CranDiagnostic {
                record_index,
                package,
                error,
            }),
        }
    }

    if !diagnostics.is_empty() {
        return Err(diagnostics.into_boxed_slice());
    }
    Ok((selected, aggregation))
}
