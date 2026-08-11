//! Conversion of a current CRAN `PACKAGES` DCF index into domain candidates.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use nrr_core::{
    DependencyKind, DependencyRequirement, DependencySourceConstraint, Distribution,
    DistributionChannel, DistributionMetadata, PackageName, PackageNameError, PackageRelease,
    PackageReleaseError, Provenance, RPackageVersion, RPackageVersionError, RegistryId, RelationOp,
    ReleaseAggregation, ReleaseIdentity, ReleaseMetadata, ReleaseMetadataError, ReleaseObservation,
    VersionConstraint,
};

use super::{DcfDocument, DcfError};

const CRAN_NAMESPACE: &str = "cran";
const SOURCE_CHANNEL: &str = "source";

/// A candidate catalog produced from one pinned current CRAN index.
#[derive(Clone, Debug, Default)]
pub struct CranCatalog {
    candidates: BTreeMap<PackageName, Vec<PackageRelease>>,
    diagnostics: Vec<CranDiagnostic>,
}

impl CranCatalog {
    /// Parses and converts a plain `src/contrib/PACKAGES` snapshot.
    ///
    /// DCF syntax errors fail the operation because record boundaries cannot
    /// be trusted.  A semantically malformed record is instead skipped and
    /// recorded in [`Self::diagnostics`], allowing the rest of a large index
    /// to remain useful.
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
        Ok(catalog_from_observations(observations))
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

    /// Records skipped semantic records, in source record order.
    pub fn diagnostics(&self) -> &[CranDiagnostic] {
        &self.diagnostics
    }
}

/// A failure while parsing the index as DCF syntax.
#[derive(Debug)]
pub enum CranCatalogError {
    Dcf(DcfError),
}

impl fmt::Display for CranCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dcf(error) => write!(f, "invalid CRAN PACKAGES DCF: {error}"),
        }
    }
}

impl Error for CranCatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Dcf(error) => Some(error),
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

pub(super) fn catalog_from_observations<I>(observations: I) -> CranCatalog
where
    I: IntoIterator<
        Item = (
            usize,
            Option<String>,
            Result<ReleaseObservation, CranRecordError>,
        ),
    >,
{
    let mut aggregation = ReleaseAggregation::new();
    let mut diagnostics = Vec::new();

    for (record_index, package, observation) in observations {
        match observation {
            Ok(observation) => {
                if let Err(error) = aggregation.observe(observation) {
                    diagnostics.push(CranDiagnostic {
                        record_index,
                        package,
                        error: CranRecordError::Domain(error),
                    });
                }
            }
            Err(error) => diagnostics.push(CranDiagnostic {
                record_index,
                package,
                error,
            }),
        }
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
    CranCatalog {
        candidates,
        diagnostics,
    }
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

    let mut dependencies = Vec::new();
    for (field_name, kind) in [
        ("Depends", DependencyKind::Depends),
        ("Imports", DependencyKind::Imports),
        ("LinkingTo", DependencyKind::LinkingTo),
        ("Suggests", DependencyKind::Suggests),
        ("Enhances", DependencyKind::Enhances),
    ] {
        if let Some(value) = field(fields, field_name) {
            for entry in value.split(',') {
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
            namespace: nrr_core::PackageNamespace::new(CRAN_NAMESPACE)
                .expect("the fixed CRAN namespace is valid"),
            version: version.clone(),
        },
    );

    Ok(ReleaseObservation {
        identity,
        observed_package: package,
        observed_version: version,
        metadata,
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
        "package" | "version" | "depends" | "imports" | "linkingto" | "suggests" | "enhances"
    )
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
