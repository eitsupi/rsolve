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
}

type CatalogRecord = (usize, Option<String>, Vec<(String, String)>);

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
}

impl CranCatalog {
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
                (record_index, package, observation_from_fields(&fields))
            });
        catalog_from_observations(observations).map_err(CranCatalogError::Semantic)
    }

    pub(crate) fn observations_from_packages(
        input: &[u8],
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
        validated_observations_from_fields(records)
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
                observation_from_fields(&field_refs),
            )
        })
        .collect::<Vec<_>>();
    let (selected, _) = select_and_aggregate(parsed).map_err(CranCatalogError::Semantic)?;

    Ok(selected
        .into_iter()
        .map(|(record_index, _, observation)| {
            let package = observation.identity.name().clone();
            let release = PackageRelease::try_from(observation)
                .expect("catalog validation already accepted the observation");
            CranCatalogObservation {
                record_index,
                package,
                fields: fields_by_index
                    .get(&record_index)
                    .cloned()
                    .expect("selected catalog record must have source fields"),
                release,
            }
        })
        .collect::<Vec<_>>())
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
    let observations = observations.into_iter().collect::<Vec<_>>();
    let (_, aggregation) = select_and_aggregate(observations)?;

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
) -> Result<(Vec<SelectedCatalogObservation>, ReleaseAggregation), Box<[CranDiagnostic]>> {
    let mut root_md5_by_identity = HashMap::<ReleaseIdentity, Vec<Option<String>>>::new();
    for (_, _, observation) in &observations {
        let Ok(observation) = observation else {
            continue;
        };
        if metadata_field(observation, "Path").is_none() {
            root_md5_by_identity
                .entry(observation.identity.clone())
                .or_default()
                .push(metadata_field(observation, "MD5sum").map(str::to_owned));
        }
    }

    let mut diagnostics = Vec::new();
    let mut selected = Vec::new();
    let mut aggregation = ReleaseAggregation::new();

    for (record_index, package, observation) in observations {
        match observation {
            Ok(observation) => {
                if should_suppress_overlay(&observation, &root_md5_by_identity) {
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

fn is_recommended_overlay(observation: &ReleaseObservation) -> bool {
    let Some(path) = metadata_field(observation, "Path") else {
        return false;
    };
    let Some((version, suffix)) = path.rsplit_once('/') else {
        return false;
    };
    suffix == "Recommended"
        && !version.is_empty()
        && RPackageVersion::parse_bare(version).is_ok()
        && path.matches('/').count() == 1
}

fn should_suppress_overlay(
    observation: &ReleaseObservation,
    root_md5_by_identity: &HashMap<ReleaseIdentity, Vec<Option<String>>>,
) -> bool {
    if !is_recommended_overlay(observation) {
        return false;
    }
    let Some(root_md5s) = root_md5_by_identity.get(&observation.identity) else {
        return false;
    };

    // A missing MD5 on either row is common in alternate CRAN indexes and
    // does not prevent selecting the root metadata. If both sides provide a
    // value, retain the overlay on any mismatch so normal aggregation fails
    // closed instead of silently discarding conflicting artifact facts.
    let overlay_md5 = metadata_field(observation, "MD5sum")
        .filter(|value| !value.trim().is_empty())
        .map(str::trim);
    let has_mismatch = root_md5s
        .iter()
        .flatten()
        .filter_map(|value| {
            let value = value.trim();
            (!value.is_empty()).then_some(value)
        })
        .any(|root_md5| Some(root_md5) != overlay_md5 && overlay_md5.is_some());
    !has_mismatch
}

pub(super) fn observation_from_fields(
    fields: &[(&str, &str)],
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
    use super::CranCatalog;

    const MATCHING_ARCHIVE: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-overlay-PACKAGES.rds"
    );

    const MATCHING_PLAIN: &[u8] = b"Package: Matrix\nVersion: 1.7-6\nLicense: RSOLVE Fictional Terms Matrix\nMD5sum: 00000000000000000000000000000031\n\nPackage: Matrix\nVersion: 1.7-6\nLicense: RSOLVE Fictional Terms Matrix\nMD5sum: 00000000000000000000000000000031\nPath: 4.7.0/Recommended\n";

    fn assert_matching_overlay_is_suppressed(observations: &[super::CranCatalogObservation]) {
        assert_eq!(observations.len(), 1);
        assert!(
            observations[0]
                .fields()
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("Path"))
        );
    }

    #[test]
    fn plain_lossless_observations_share_matching_overlay_selection() {
        let catalog = CranCatalog::from_packages(MATCHING_PLAIN).unwrap();
        assert_eq!(catalog.candidate_count(), 1);
        let observations = CranCatalog::observations_from_packages(MATCHING_PLAIN).unwrap();
        assert_matching_overlay_is_suppressed(&observations);
    }

    #[test]
    fn archive_lossless_observations_share_matching_overlay_selection() {
        let catalog = CranCatalog::from_archive_index_rds(MATCHING_ARCHIVE).unwrap();
        assert_eq!(catalog.candidate_count(), 1);
        let observations =
            CranCatalog::observations_from_archive_index_rds(MATCHING_ARCHIVE).unwrap();
        assert_matching_overlay_is_suppressed(&observations);
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
}
