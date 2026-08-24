//! Conversion of a current CRAN `PACKAGES` DCF index into domain candidates.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt;

use rsolve_core::{
    DependencyKind, DependencyRequirement, DependencySourceConstraint, Distribution,
    DistributionChannel, DistributionMetadata, PackageName, PackageNameError, PackageRelease,
    PackageReleaseError, Provenance, PublicationDate, RPackageVersion, RPackageVersionError,
    RegistryId, RelationOp, ReleaseAggregation, ReleaseIdentity, ReleaseMetadata,
    ReleaseMetadataError, ReleaseObservation, VersionConstraint,
};

use super::{DcfDocument, DcfError};

const CRAN_NAMESPACE: &str = "cran";
const SOURCE_CHANNEL: &str = "source";

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
        let document = DcfDocument::parse(input).map_err(CranCatalogError::Dcf)?;
        Self::from_document(document)
    }

    /// Alias for [`Self::from_packages`].
    pub fn parse(input: &[u8]) -> Result<Self, CranCatalogError> {
        Self::from_packages(input)
    }

    fn from_document(document: DcfDocument) -> Result<Self, CranCatalogError> {
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
                        CranCatalogRecordContext::PackagesIndex,
                    ),
                )
            });
        catalog_from_observations_with_context(
            observations,
            CranCatalogRecordContext::PackagesIndex,
        )
        .map_err(CranCatalogError::Semantic)
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

pub(crate) fn validated_observations_from_fields(
    records: Vec<CatalogRecord>,
) -> Result<Vec<CranCatalogObservation>, CranCatalogError> {
    validated_observations_from_fields_with_context(
        records,
        CranCatalogRecordContext::PackagesIndex,
    )
}

pub(crate) fn validated_observations_from_fields_with_context(
    records: Vec<CatalogRecord>,
    context: CranCatalogRecordContext,
) -> Result<Vec<CranCatalogObservation>, CranCatalogError> {
    let fields_by_index = records
        .iter()
        .map(|(record_index, _, fields)| (*record_index, fields.clone()))
        .collect::<HashMap<_, _>>();
    let parsed = records
        .iter()
        .map(|(record_index, package, fields)| {
            let field_refs = fields
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            (
                *record_index,
                package.clone(),
                observation_from_fields_with_context(&field_refs, context),
            )
        })
        .collect::<Vec<_>>();
    // Validate root records through the ordinary aggregation boundary, while
    // retaining every valid overlay for lossless evidence persistence.  The
    // aggregation function deliberately excludes overlays from candidate
    // selection, so an overlay can never create a metadata conflict with its
    // root release.
    select_and_aggregate(parsed.clone(), context).map_err(CranCatalogError::Semantic)?;

    Ok(parsed
        .into_iter()
        .filter_map(|(record_index, _, observation)| {
            let observation = observation.ok()?;
            let scope = observation_scope(&observation, context);
            let package = observation.identity.name().clone();
            let release = PackageRelease::try_from(observation)
                .expect("catalog validation already accepted the observation");
            Some(CranCatalogObservation {
                record_index,
                package,
                fields: fields_by_index
                    .get(&record_index)
                    .cloned()
                    .expect("selected catalog record must have source fields"),
                release,
                scope,
            })
        })
        .collect::<Vec<_>>())
}

pub(crate) fn provider_observations_from_fields(
    records: Vec<CatalogRecord>,
    context: CranCatalogRecordContext,
    expected_package: Option<&PackageName>,
) -> CranProviderObservationProjection {
    let fields_by_index = records
        .iter()
        .map(|(record_index, _, fields)| (*record_index, fields.clone()))
        .collect::<HashMap<_, _>>();
    let mut observations = Vec::new();
    let mut rejections = Vec::new();
    let mut aggregation = ReleaseAggregation::new();
    let mut seen_identities = HashMap::<ProviderIdentityKey, bool>::new();

    for (record_index, _package, fields) in records {
        let field_refs = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let package_hint =
            field(&field_refs, "Package").and_then(|value| PackageName::new(value.trim()).ok());
        let version_hint = field(&field_refs, "Version")
            .and_then(|value| RPackageVersion::parse(value.trim()).ok());
        let scope_hint = match context {
            CranCatalogRecordContext::PackagesIndex => match field(&field_refs, "Path") {
                Some(path) => classify_path(path).ok(),
                None => Some(CranCatalogRecordScope::Root),
            },
            CranCatalogRecordContext::Description => Some(CranCatalogRecordScope::Root),
        };
        let identity = match provider_identity_from_fields(&field_refs, context) {
            Ok(identity) => identity,
            Err(error) => {
                rejections.push(CranArchiveReleaseRejection {
                    record_index,
                    package: package_hint.clone(),
                    version: version_hint,
                    scope: scope_hint,
                    fields,
                    error,
                });
                continue;
            }
        };
        if let Some(expected) = expected_package
            && identity.0 != *expected
        {
            rejections.push(CranArchiveReleaseRejection {
                record_index,
                package: Some(identity.0.clone()),
                version: Some(identity.1.clone()),
                scope: Some(identity.2.clone()),
                fields,
                error: CranRecordError::UnexpectedPackage {
                    expected: expected.to_string(),
                    actual: identity.0.to_string(),
                },
            });
            continue;
        }
        let identity_key = provider_identity_key(&identity.0, &identity.1, &identity.2);
        let parsed = observation_from_fields_with_context(&field_refs, context);
        let observation = match parsed {
            Ok(observation) => observation,
            Err(error) => {
                let was_rejected = seen_identities.insert(identity_key, true);
                if was_rejected.is_some() {
                    rejections.push(CranArchiveReleaseRejection {
                        record_index,
                        package: Some(identity.0),
                        version: Some(identity.1),
                        scope: Some(identity.2),
                        fields,
                        error: CranRecordError::Domain(PackageReleaseError::ConflictingMetadata {
                            field: "duplicate identity",
                        }),
                    });
                } else {
                    rejections.push(CranArchiveReleaseRejection {
                        record_index,
                        package: Some(identity.0),
                        version: Some(identity.1),
                        scope: Some(identity.2),
                        fields,
                        error,
                    });
                }
                continue;
            }
        };
        let scope = observation_scope(&observation, context);
        let package_name = observation.identity.name().clone();
        let release = match PackageRelease::try_from(observation.clone()) {
            Ok(release) => release,
            Err(error) => {
                let was_rejected = seen_identities.insert(identity_key, true);
                let rejection_error = if was_rejected.is_some() {
                    CranRecordError::Domain(PackageReleaseError::ConflictingMetadata {
                        field: "duplicate identity",
                    })
                } else {
                    CranRecordError::Domain(error)
                };
                rejections.push(CranArchiveReleaseRejection {
                    record_index,
                    package: Some(package_name),
                    version: Some(identity.1),
                    scope: Some(identity.2),
                    fields,
                    error: rejection_error,
                });
                continue;
            }
        };
        let was_rejected = seen_identities.insert(identity_key, false);
        if was_rejected == Some(true) {
            rejections.push(CranArchiveReleaseRejection {
                record_index,
                package: Some(package_name),
                version: Some(identity.1),
                scope: Some(identity.2),
                fields,
                error: CranRecordError::Domain(PackageReleaseError::ConflictingMetadata {
                    field: "duplicate identity",
                }),
            });
            continue;
        }
        if matches!(scope, CranCatalogRecordScope::Root)
            && let Err(error) = aggregation.observe_release(release.clone())
        {
            rejections.push(CranArchiveReleaseRejection {
                record_index,
                package: Some(package_name),
                version: Some(identity.1),
                scope: Some(identity.2),
                fields,
                error: CranRecordError::Domain(error),
            });
            continue;
        }
        observations.push(CranCatalogObservation {
            record_index,
            package: package_name,
            fields: fields_by_index
                .get(&record_index)
                .cloned()
                .expect("provider record fields must be retained"),
            release,
            scope,
        });
    }

    CranProviderObservationProjection {
        observations,
        rejections,
    }
}

fn provider_identity_from_fields(
    fields: &[(&str, &str)],
    context: CranCatalogRecordContext,
) -> Result<(PackageName, RPackageVersion, CranCatalogRecordScope), CranRecordError> {
    reject_identity_duplicates(fields)?;
    let package = PackageName::new(required_field(fields, "Package")?.trim())
        .map_err(CranRecordError::InvalidPackageName)?;
    let version = RPackageVersion::parse(required_field(fields, "Version")?.trim())
        .map_err(CranRecordError::InvalidVersion)?;
    let scope = match context {
        CranCatalogRecordContext::PackagesIndex => field(fields, "Path")
            .map(classify_path)
            .transpose()?
            .unwrap_or(CranCatalogRecordScope::Root),
        CranCatalogRecordContext::Description => CranCatalogRecordScope::Root,
    };
    Ok((package, version, scope))
}

fn reject_identity_duplicates(fields: &[(&str, &str)]) -> Result<(), CranRecordError> {
    let mut names = BTreeSet::new();
    for (name, _) in fields {
        let normalized = name.to_ascii_lowercase();
        if !matches!(normalized.as_str(), "package" | "version" | "path") {
            continue;
        }
        if !names.insert(normalized) {
            return Err(CranRecordError::DuplicateField((*name).to_owned()));
        }
    }
    Ok(())
}

type ProviderIdentityKey = (PackageName, RPackageVersion, CranCatalogRecordScope);

fn provider_identity_key(
    package: &PackageName,
    version: &RPackageVersion,
    scope: &CranCatalogRecordScope,
) -> ProviderIdentityKey {
    (package.clone(), version.clone(), scope.clone())
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

pub(super) fn catalog_from_observations<I>(
    observations: I,
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
    catalog_from_observations_with_context(observations, CranCatalogRecordContext::PackagesIndex)
}

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

fn metadata_field<'a>(observation: &'a ReleaseObservation, name: &str) -> Option<&'a str> {
    observation
        .metadata
        .fields()
        .iter()
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn observation_scope(
    observation: &ReleaseObservation,
    context: CranCatalogRecordContext,
) -> CranCatalogRecordScope {
    let Some(path) = metadata_field(observation, "Path") else {
        return CranCatalogRecordScope::Root;
    };
    match context {
        CranCatalogRecordContext::PackagesIndex => {
            classify_path(path).expect("validated CRAN observation must have a valid Path")
        }
        CranCatalogRecordContext::Description => CranCatalogRecordScope::Root,
    }
}

pub(super) fn observation_from_fields(
    fields: &[(&str, &str)],
) -> Result<ReleaseObservation, CranRecordError> {
    observation_from_fields_with_context(fields, CranCatalogRecordContext::PackagesIndex)
}

pub(super) fn observation_from_fields_with_context(
    fields: &[(&str, &str)],
    context: CranCatalogRecordContext,
) -> Result<ReleaseObservation, CranRecordError> {
    reject_duplicate_fields(fields)?;
    let package_value = required_field(fields, "Package")?;
    let version_value = required_field(fields, "Version")?;
    let package =
        PackageName::new(package_value.trim()).map_err(CranRecordError::InvalidPackageName)?;
    let version =
        RPackageVersion::parse(version_value.trim()).map_err(CranRecordError::InvalidVersion)?;
    let publication = field(fields, "Published")
        .map(parse_publication_date)
        .transpose()?;

    let mut dependencies = Vec::new();
    for (field_name, kind) in [
        ("Depends", DependencyKind::Depends),
        ("Imports", DependencyKind::Imports),
        ("LinkingTo", DependencyKind::LinkingTo),
        ("Suggests", DependencyKind::Suggests),
        ("Enhances", DependencyKind::Enhances),
    ] {
        if let Some(value) = field(fields, field_name) {
            // `split_terminator` drops only the terminal empty segment from
            // a literal trailing comma, while preserving internal empties
            // and whitespace-only entries for semantic validation, matching
            // R's dependency splitter without allocating an intermediate
            // collection.
            for entry in value.split_terminator(',') {
                let dependency = parse_dependency_entry(entry).map_err(|source| {
                    CranRecordError::Dependency {
                        field: field_name,
                        entry: entry.trim().to_owned(),
                        source,
                    }
                })?;
                dependencies.push(DependencyRequirement::new(
                    kind,
                    dependency.name,
                    DependencySourceConstraint::Any,
                    dependency.constraint,
                ));
            }
        }
    }

    let metadata_fields = fields
        .iter()
        .filter(|(name, _)| !is_reserved_field(name))
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    let metadata =
        ReleaseMetadata::new(metadata_fields).map_err(CranRecordError::InvalidMetadata)?;
    if matches!(context, CranCatalogRecordContext::PackagesIndex)
        && let Some(path) = field(fields, "Path")
    {
        classify_path(path)?;
    }
    let identity = ReleaseIdentity::new(
        package.clone(),
        Provenance::RegistryRelease {
            namespace: rsolve_core::PackageNamespace::new(CRAN_NAMESPACE)
                .expect("the fixed CRAN namespace is valid"),
            version: version.clone(),
        },
    );

    Ok(ReleaseObservation {
        identity,
        observed_package: package,
        observed_version: version,
        metadata,
        publication,
        dependencies,
        distributions: vec![Distribution {
            registry: RegistryId::new(CRAN_NAMESPACE).expect("the fixed CRAN registry is valid"),
            channel: DistributionChannel::new(SOURCE_CHANNEL)
                .expect("the fixed source channel is valid"),
            snapshot: None,
            artifacts: Vec::new(),
            observed_metadata: DistributionMetadata::default(),
        }],
    })
}

fn classify_path(value: &str) -> Result<CranCatalogRecordScope, CranRecordError> {
    let mut segments = value.split('/');
    let version = segments.next().unwrap_or_default();
    let suffix = segments.next().unwrap_or_default();
    if segments.next().is_some() || suffix != "Recommended" || version.is_empty() {
        return Err(CranRecordError::InvalidPath {
            value: value.to_owned(),
            diagnostic: "expected <R version>/Recommended".into(),
        });
    }
    let runtime =
        RPackageVersion::parse_bare(version).map_err(|error| CranRecordError::InvalidPath {
            value: value.to_owned(),
            diagnostic: format!("invalid Recommended runtime version: {error}"),
        })?;
    Ok(CranCatalogRecordScope::RecommendedOverlay { runtime })
}

fn required_field<'a>(
    fields: &'a [(&str, &str)],
    name: &'static str,
) -> Result<&'a str, CranRecordError> {
    field(fields, name).ok_or(CranRecordError::MissingField(name))
}

fn field<'a>(fields: &'a [(&str, &str)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field_name, _)| field_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| *value)
}

fn reject_duplicate_fields(fields: &[(&str, &str)]) -> Result<(), CranRecordError> {
    let mut names = BTreeSet::new();
    for (name, _) in fields {
        let normalized = name.to_ascii_lowercase();
        if !names.insert(normalized) {
            return Err(CranRecordError::DuplicateField((*name).to_owned()));
        }
    }
    Ok(())
}

fn is_reserved_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "package"
            | "version"
            | "depends"
            | "imports"
            | "linkingto"
            | "suggests"
            | "enhances"
            | "published"
    )
}

fn parse_publication_date(value: &str) -> Result<rsolve_core::ReleasePublication, CranRecordError> {
    let value = value.trim();
    let date = if value.len() == 10 {
        PublicationDate::parse(value).map_err(|error| error.to_string())
    } else {
        parse_publication_datetime(value)
    };
    date.map(rsolve_core::ReleasePublication::new)
        .map_err(|diagnostic| CranRecordError::InvalidPublicationDate {
            value: value.to_owned(),
            diagnostic,
        })
}

fn parse_publication_datetime(value: &str) -> Result<PublicationDate, String> {
    let (format, has_utc_suffix) = match value.len() {
        19 => ("%Y-%m-%d %H:%M:%S", false),
        23 => ("%Y-%m-%d %H:%M:%S UTC", true),
        _ => return Err("Published datetime must use an accepted full-string spelling".into()),
    };
    if has_utc_suffix && !value.ends_with(" UTC") {
        return Err("Published datetime must end with uppercase UTC".into());
    }
    let datetime =
        jiff::civil::DateTime::strptime(format, value).map_err(|error| error.to_string())?;
    let canonical = datetime.strftime(format).to_string();
    if canonical != value {
        return Err(
            "Published datetime is not canonical (leap seconds and normalized values are rejected)"
                .into(),
        );
    }
    let date = datetime.date().strftime("%Y-%m-%d").to_string();
    PublicationDate::parse(date).map_err(|error| error.to_string())
}

struct ParsedDependency {
    name: PackageName,
    constraint: VersionConstraint,
}

fn parse_dependency_entry(input: &str) -> Result<ParsedDependency, DependencyParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(DependencyParseError::EmptyEntry);
    }

    let (name_text, constraint) = match input.find('(') {
        Some(open) => {
            if !input.ends_with(')') {
                return Err(DependencyParseError::InvalidConstraintSyntax);
            }
            let expression = &input[open + 1..input.len() - 1];
            if expression.contains('(') || expression.contains(')') {
                return Err(DependencyParseError::InvalidConstraintSyntax);
            }
            let name_text = input[..open].trim();
            let expression = expression.trim();
            (name_text, Some(parse_constraint(expression)?))
        }
        None => {
            if input.contains(')') {
                return Err(DependencyParseError::InvalidConstraintSyntax);
            }
            (input, None)
        }
    };

    let name = PackageName::new(name_text).map_err(DependencyParseError::InvalidPackageName)?;
    Ok(ParsedDependency {
        name,
        constraint: constraint.unwrap_or_else(VersionConstraint::unconstrained),
    })
}

fn parse_constraint(input: &str) -> Result<VersionConstraint, DependencyParseError> {
    let operators = [
        (">=", RelationOp::Ge),
        ("<=", RelationOp::Le),
        ("==", RelationOp::Eq),
        ("!=", RelationOp::Ne),
        (">", RelationOp::Gt),
        ("<", RelationOp::Lt),
    ];
    let (operator, op) = operators
        .iter()
        .find(|(operator, _)| input.starts_with(operator))
        .ok_or(DependencyParseError::InvalidConstraintSyntax)?;
    let version_text = input[operator.len()..].trim();
    if version_text.is_empty() {
        return Err(DependencyParseError::MissingConstraintVersion);
    }
    let version =
        RPackageVersion::parse(version_text).map_err(DependencyParseError::InvalidVersion)?;
    Ok(VersionConstraint::from_clause(*op, version))
}

#[cfg(test)]
mod tests {
    use super::{CranCatalog, CranCatalogRecordContext, CranRecordError};
    use rsolve_core::PackageName;

    const MATCHING_ARCHIVE: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-overlay-PACKAGES.rds"
    );

    const MATCHING_PLAIN: &[u8] = b"Package: Matrix\nVersion: 1.7-6\nLicense: RSOLVE Fictional Terms Matrix\nMD5sum: 00000000000000000000000000000031\n\nPackage: Matrix\nVersion: 1.7-6\nLicense: RSOLVE Fictional Terms Matrix\nMD5sum: 00000000000000000000000000000031\nPath: 4.7.0/Recommended\n";

    fn assert_overlay_is_retained_losslessly(observations: &[super::CranCatalogObservation]) {
        assert_eq!(observations.len(), 2);
        assert!(matches!(
            observations[0].scope(),
            super::CranCatalogRecordScope::Root
        ));
        assert!(matches!(
            observations[1].scope(),
            super::CranCatalogRecordScope::RecommendedOverlay { .. }
        ));
        assert!(
            observations[1]
                .fields()
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("Path")
                    && value == "4.7.0/Recommended")
        );
    }

    #[test]
    fn plain_lossless_observations_share_matching_overlay_selection() {
        let catalog = CranCatalog::from_packages(MATCHING_PLAIN).unwrap();
        assert_eq!(catalog.candidate_count(), 1);
        let observations = CranCatalog::observations_from_packages(MATCHING_PLAIN).unwrap();
        assert_overlay_is_retained_losslessly(&observations);
    }

    #[test]
    fn archive_lossless_observations_share_matching_overlay_selection() {
        let catalog = CranCatalog::from_archive_index_rds(MATCHING_ARCHIVE).unwrap();
        assert_eq!(catalog.candidate_count(), 1);
        let observations =
            CranCatalog::observations_from_archive_index_rds(MATCHING_ARCHIVE).unwrap();
        assert_overlay_is_retained_losslessly(&observations);
    }

    #[test]
    fn mismatched_overlay_is_root_candidate_regardless_of_input_order() {
        let root = b"Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.1.0)\nMD5sum: root\n\n";
        let overlay = b"Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.7)\nMD5sum: overlay\nPath: 4.7.0/Recommended\n\n";
        for input in [
            [root.as_slice(), overlay.as_slice()].concat(),
            [overlay.as_slice(), root.as_slice()].concat(),
        ] {
            let catalog = CranCatalog::from_packages(&input).unwrap();
            assert_eq!(catalog.candidate_count(), 1);
            assert_eq!(
                catalog.candidates_named("survival").unwrap()[0]
                    .version()
                    .to_string(),
                "3.8-11"
            );
            let observations = CranCatalog::observations_from_packages(&input).unwrap();
            assert_eq!(observations.len(), 2);
        }
    }

    #[test]
    fn overlay_only_never_becomes_a_root_candidate() {
        let input =
            b"Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.7)\nPath: 4.7.0/Recommended\n";
        let catalog = CranCatalog::from_packages(input).unwrap();
        assert_eq!(catalog.candidate_count(), 0);
        let observations = CranCatalog::observations_from_packages(input).unwrap();
        assert_eq!(observations.len(), 1);
    }

    #[test]
    fn invalid_recommended_path_fails_closed() {
        for path in [
            "Recommended",
            "4.7.0/Recommended/extra",
            "latest/Recommended",
        ] {
            let input = format!("Package: survival\nVersion: 3.8-11\nPath: {path}\n");
            let error = CranCatalog::from_packages(input.as_bytes()).unwrap_err();
            assert!(matches!(
                error.diagnostics()[0].error(),
                super::CranRecordError::InvalidPath { .. }
            ));
        }
    }

    #[test]
    fn description_path_is_preserved_as_root_metadata() {
        let input = b"Package: survival\nVersion: 3.8-11\nPath: source/archive\n";
        let catalog = CranCatalog::from_description(input).unwrap();
        let release = &catalog.candidates_named("survival").unwrap()[0];
        assert_eq!(
            release.metadata().fields().get("Path").map(String::as_str),
            Some("source/archive")
        );

        let observations = CranCatalog::observations_from_description(input).unwrap();
        assert_eq!(observations.len(), 1);
        assert!(matches!(
            observations[0].scope(),
            super::CranCatalogRecordScope::Root
        ));
        assert!(
            observations[0]
                .fields()
                .iter()
                .any(|(name, value)| name == "Path" && value == "source/archive")
        );
    }

    #[test]
    fn conflicting_pathless_roots_fail_closed() {
        let input = b"Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.1.0)\n\nPackage: survival\nVersion: 3.8-11\nDepends: R (>= 4.7)\n";
        let error = CranCatalog::from_packages(input).unwrap_err();
        assert!(matches!(
            error.diagnostics()[0].error(),
            super::CranRecordError::Domain(_)
        ));
    }

    #[test]
    fn mixed_parse_and_domain_diagnostics_remain_in_source_order() {
        let input = b"Package: Matrix\nVersion: 1.0\nLicense: root\n\n\
Package: malformed\n\n\
Package: Matrix\nVersion: 1.0\nLicense: conflicting\n";
        let error = CranCatalog::from_packages(input).unwrap_err();
        let diagnostics = error.diagnostics();
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].record_index(), 1);
        assert!(matches!(
            diagnostics[0].error(),
            super::CranRecordError::MissingField("Version")
        ));
        assert_eq!(diagnostics[1].record_index(), 2);
        assert!(matches!(
            diagnostics[1].error(),
            super::CranRecordError::Domain(_)
        ));
    }

    #[test]
    fn provider_archive_projection_quarantines_release_local_dependency_errors() {
        let records = vec![
            (
                0,
                Some("rsolvefixture.history".to_owned()),
                vec![
                    ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                    ("Version".to_owned(), "1.0".to_owned()),
                    ("License".to_owned(), "fixture".to_owned()),
                ],
            ),
            (
                1,
                Some("rsolvefixture.history".to_owned()),
                vec![
                    ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                    ("Version".to_owned(), "1.1".to_owned()),
                    ("License".to_owned(), "fixture".to_owned()),
                ],
            ),
            (
                2,
                Some("rsolvefixture.history".to_owned()),
                vec![
                    ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                    ("Version".to_owned(), "1.2".to_owned()),
                    ("Depends".to_owned(), "libxml (>= )".to_owned()),
                ],
            ),
        ];
        let projection = super::provider_observations_from_fields(
            records,
            CranCatalogRecordContext::PackagesIndex,
            Some(&PackageName::new("rsolvefixture.history").unwrap()),
        );
        assert_eq!(projection.observations.len(), 2);
        assert_eq!(projection.rejections.len(), 1);
        assert_eq!(projection.rejections[0].record_index(), 2);
        assert_eq!(
            projection.rejections[0].package().unwrap().as_str(),
            "rsolvefixture.history"
        );
        assert_eq!(projection.rejections[0].version().unwrap().as_str(), "1.2");
        assert!(matches!(
            projection.rejections[0].error(),
            CranRecordError::Dependency { .. }
        ));
        let catalog = CranCatalog::from_provider_observations(&projection.observations);
        assert_eq!(catalog.candidate_count(), 2);
        assert!(
            catalog
                .candidates_named("rsolvefixture.history")
                .unwrap()
                .iter()
                .all(|release| release.version().as_str() != "1.2")
        );
    }

    #[test]
    fn provider_projection_checks_path_before_release_semantics() {
        let records = vec![(
            0,
            Some("rsolvefixture.history".to_owned()),
            vec![
                ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                ("Version".to_owned(), "1.0".to_owned()),
                ("Path".to_owned(), "broken-path".to_owned()),
                ("Depends".to_owned(), "libxml (>= )".to_owned()),
            ],
        )];
        let projection = super::provider_observations_from_fields(
            records,
            CranCatalogRecordContext::PackagesIndex,
            Some(&PackageName::new("rsolvefixture.history").unwrap()),
        );
        assert!(projection.observations.is_empty());
        assert!(matches!(
            projection.rejections[0].error(),
            CranRecordError::InvalidPath { .. }
        ));
        assert_eq!(projection.rejections[0].version().unwrap().as_str(), "1.0");
    }

    #[test]
    fn provider_projection_rejects_unexpected_package_and_preserves_raw_fields() {
        let records = vec![(
            0,
            Some("other".to_owned()),
            vec![
                ("Package".to_owned(), "other".to_owned()),
                ("Version".to_owned(), "1.0".to_owned()),
                ("Depends".to_owned(), "R".to_owned()),
            ],
        )];
        let projection = super::provider_observations_from_fields(
            records,
            CranCatalogRecordContext::PackagesIndex,
            Some(&PackageName::new("rsolvefixture.history").unwrap()),
        );
        assert!(projection.observations.is_empty());
        let rejection = &projection.rejections[0];
        assert!(matches!(
            rejection.error(),
            CranRecordError::UnexpectedPackage { .. }
        ));
        assert_eq!(rejection.fields().len(), 3);
    }

    #[test]
    fn provider_projection_aggregates_equivalent_valid_duplicates() {
        let fields = |version: &str| {
            vec![
                ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                ("Version".to_owned(), version.to_owned()),
                ("License".to_owned(), "fixture".to_owned()),
            ]
        };
        let projection = super::provider_observations_from_fields(
            vec![(0, None, fields("1.0")), (1, None, fields("1.0.0"))],
            CranCatalogRecordContext::PackagesIndex,
            Some(&PackageName::new("rsolvefixture.history").unwrap()),
        );
        assert_eq!(projection.observations.len(), 2);
        assert!(projection.rejections.is_empty());
        let catalog = CranCatalog::from_provider_observations(&projection.observations);
        assert_eq!(catalog.candidate_count(), 1);
    }

    #[test]
    fn provider_projection_makes_valid_and_rejected_duplicate_identity_hard() {
        let records = vec![
            (
                0,
                None,
                vec![
                    ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                    ("Version".to_owned(), "1.0".to_owned()),
                    ("Depends".to_owned(), "libxml (>= )".to_owned()),
                ],
            ),
            (
                1,
                None,
                vec![
                    ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                    ("Version".to_owned(), "1.0.0".to_owned()),
                ],
            ),
        ];
        let projection = super::provider_observations_from_fields(
            records,
            CranCatalogRecordContext::PackagesIndex,
            Some(&PackageName::new("rsolvefixture.history").unwrap()),
        );
        assert!(projection.observations.len() <= 1);
        assert!(projection.rejections.iter().any(|rejection| matches!(
            rejection.error(),
            CranRecordError::Domain(rsolve_core::PackageReleaseError::ConflictingMetadata {
                field: "duplicate identity"
            })
        )));
    }
}
