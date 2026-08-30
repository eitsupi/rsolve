//! Validation and domain projection for the rsolve R-universe API profile.
//!
//! This module deliberately accepts a versioned, transport-neutral response
//! shape. It does not classify endpoints by hostname or server software.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use rsolve_core::{
    DeclaredDependency, DependencyKind, DependencySourceConstraint, Distribution,
    DistributionChannel, DistributionMetadata, GitCommitId, NormalizedGitUrl, PackageName,
    PackageRelease, PackageReleaseError, PackageRequirement, Provenance, PublicationDate,
    RPackageVersion, RegistryId, RelationOp, ReleaseAggregation, ReleaseMetadata,
    ReleaseObservation, ReleasePublication, RepositorySubdir, VersionClause, VersionConstraint,
};
use serde_json::{Map, Value};

mod provider;
pub use provider::*;

/// Human-readable name for the R-universe response profile.
pub const RUNIVERSE_API_PROFILE: &str = "r-universe.v1";

/// Local compatibility revision for the R-universe response profile.
pub const RUNIVERSE_COMPATIBILITY_PROFILE: u32 = 1;

/// Local parser revision for the R-universe catalog projection.
pub const RUNIVERSE_PARSER_SCHEMA: u32 = 1;

/// A validated catalog projected from one R-universe response.
#[derive(Clone, Debug)]
pub struct RUniverseCatalog {
    releases: Vec<PackageRelease>,
}

impl RUniverseCatalog {
    /// Parse a catalog array or single package object and project every entry
    /// into a validated Git-backed release.
    pub fn from_json(input: &str, registry: RegistryId) -> Result<Self, RUniverseCatalogError> {
        let value: Value = serde_json::from_str(input)
            .map_err(|error| RUniverseCatalogError::Json(error.to_string()))?;
        let packages = match &value {
            Value::Object(_) => std::slice::from_ref(&value),
            Value::Array(packages) => packages.as_slice(),
            _ => {
                return Err(invalid_field(
                    "response",
                    "expected a package object or array",
                ));
            }
        };
        let mut aggregation = ReleaseAggregation::new();
        for (index, package) in packages.iter().enumerate() {
            let release = parse_package(package, index, &registry)?;
            aggregation.observe_release(release).map_err(|error| {
                RUniverseCatalogError::MetadataConflict {
                    package: package_name_for_error(package, index),
                    reason: error.to_string(),
                }
            })?;
        }
        let mut releases = aggregation.releases().cloned().collect::<Vec<_>>();
        releases.sort_by(compare_releases);
        Ok(Self { releases })
    }

    pub fn releases(&self) -> &[PackageRelease] {
        &self.releases
    }

    pub fn candidates_named(&self, name: &PackageName) -> Vec<&PackageRelease> {
        self.releases
            .iter()
            .filter(|release| release.identity().name() == name)
            .collect()
    }
}

/// Parse a validated catalog response.
pub fn parse_catalog(
    input: &str,
    registry: RegistryId,
) -> Result<RUniverseCatalog, RUniverseCatalogError> {
    RUniverseCatalog::from_json(input, registry)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RUniverseCatalogError {
    Json(String),
    MissingField { field: String },
    InvalidField { field: String, reason: String },
    InvalidDependency { index: usize, reason: String },
    MetadataConflict { package: String, reason: String },
}

impl fmt::Display for RUniverseCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(reason) => write!(f, "invalid R-universe JSON: {reason}"),
            Self::MissingField { field } => write!(f, "missing R-universe field {field:?}"),
            Self::InvalidField { field, reason } => {
                write!(f, "invalid R-universe field {field:?}: {reason}")
            }
            Self::InvalidDependency { index, reason } => {
                write!(f, "invalid R-universe dependency {index}: {reason}")
            }
            Self::MetadataConflict { package, reason } => {
                write!(
                    f,
                    "conflicting metadata for R-universe package {package}: {reason}"
                )
            }
        }
    }
}

impl Error for RUniverseCatalogError {}

fn parse_package(
    value: &Value,
    index: usize,
    registry: &RegistryId,
) -> Result<PackageRelease, RUniverseCatalogError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_field(format!("response[{index}]"), "expected an object"))?;
    let package_text = required_string(object, "Package")?;
    let package = PackageName::new(&package_text)
        .map_err(|error| invalid_field("Package", error.to_string()))?;
    let version_text = required_string(object, "Version")?;
    let version = RPackageVersion::parse(&version_text)
        .map_err(|error| invalid_field("Version", error.to_string()))?;
    let remote_url = required_string(object, "RemoteUrl")?;
    let remote_url = NormalizedGitUrl::new(remote_url)
        .map_err(|error| invalid_field("RemoteUrl", error.to_string()))?;
    let remote_sha = required_string(object, "RemoteSha")?;
    let commit = GitCommitId::new(remote_sha)
        .map_err(|error| invalid_field("RemoteSha", error.to_string()))?;
    let subdirectory = object
        .get("RemoteSubdir")
        .map(|value| {
            if value.is_null() {
                return Ok(None);
            }
            value
                .as_str()
                .ok_or_else(|| invalid_field("RemoteSubdir", "expected a string"))
                .and_then(|value| {
                    RepositorySubdir::new(value)
                        .map_err(|error| invalid_field("RemoteSubdir", error.to_string()))
                        .map(Some)
                })
        })
        .transpose()?
        .flatten();
    let dependencies = object
        .get("_dependencies")
        .ok_or_else(|| missing_field("_dependencies"))?;
    let dependencies = parse_dependencies(dependencies)?;
    let publication = parse_publication(object, &package)?;

    let mut metadata = BTreeMap::new();
    for (field, value) in object {
        if matches!(
            field.as_str(),
            "Package"
                | "Version"
                | "RemoteUrl"
                | "RemoteRef"
                | "RemoteSha"
                | "RemoteSubdir"
                | "_dependencies"
                | "Packaged"
                | "Date/Publication"
                | "Published"
        ) {
            continue;
        }
        if matches!(
            field.as_str(),
            "Depends" | "Imports" | "LinkingTo" | "Suggests" | "Enhances"
        ) {
            continue;
        }
        if field.starts_with('_') {
            continue;
        }
        let scalar = match value {
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Null | Value::Array(_) | Value::Object(_) => continue,
        };
        metadata.insert(field.clone(), scalar);
    }
    let metadata = ReleaseMetadata::from_pairs(metadata)
        .map_err(|error| invalid_field("metadata", error.to_string()))?;
    let identity = rsolve_core::ReleaseIdentity::new(
        package.clone(),
        Provenance::GitCommit {
            repository: remote_url,
            commit,
            subdirectory,
        },
    );
    let distribution = Distribution {
        registry: registry.clone(),
        channel: DistributionChannel::new("source").expect("source is a valid channel"),
        snapshot: None,
        artifacts: Vec::new(),
        observed_metadata: DistributionMetadata::default(),
    };
    PackageRelease::try_from(ReleaseObservation {
        identity,
        observed_package: package,
        observed_version: version,
        metadata,
        publication,
        declared_dependencies: dependencies,
        distributions: vec![distribution],
    })
    .map_err(|error| map_release_error(index, error))
}

fn parse_dependencies(value: &Value) -> Result<Vec<DeclaredDependency>, RUniverseCatalogError> {
    let entries = value
        .as_array()
        .ok_or_else(|| invalid_field("_dependencies", "expected an array"))?;
    let mut dependencies = Vec::with_capacity(entries.len());
    let mut seen = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or_else(|| RUniverseCatalogError::InvalidDependency {
                index,
                reason: "expected an object".into(),
            })?;
        for field in object.keys() {
            if !matches!(field.as_str(), "package" | "version" | "role") {
                return Err(RUniverseCatalogError::InvalidDependency {
                    index,
                    reason: format!("unknown field {field:?}"),
                });
            }
        }
        let name_text = required_string(object, "package")?;
        let name = PackageName::new(&name_text).map_err(|error| {
            RUniverseCatalogError::InvalidDependency {
                index,
                reason: error.to_string(),
            }
        })?;
        let kind = match required_string(object, "role")?.as_str() {
            "Depends" => DependencyKind::Depends,
            "Imports" => DependencyKind::Imports,
            "LinkingTo" => DependencyKind::LinkingTo,
            "Suggests" => DependencyKind::Suggests,
            "Enhances" => DependencyKind::Enhances,
            role => {
                return Err(RUniverseCatalogError::InvalidDependency {
                    index,
                    reason: format!("unsupported role {role:?}"),
                });
            }
        };
        let constraint = object
            .get("version")
            .map(|value| {
                if value.is_null() {
                    return Ok(VersionConstraint::unconstrained());
                }
                let value =
                    value
                        .as_str()
                        .ok_or_else(|| RUniverseCatalogError::InvalidDependency {
                            index,
                            reason: "version must be a string".into(),
                        })?;
                parse_constraint(value)
                    .map_err(|reason| RUniverseCatalogError::InvalidDependency { index, reason })
            })
            .transpose()?
            .unwrap_or_else(VersionConstraint::unconstrained);
        let package_key = (dependency_kind_rank(kind), name.clone());
        if let Some(previous) = seen.get(&package_key) {
            if previous != &constraint {
                return Err(RUniverseCatalogError::MetadataConflict {
                    package: name.to_string(),
                    reason: "dependency entries disagree on their version constraint".into(),
                });
            }
            continue;
        }
        seen.insert(package_key, constraint.clone());
        dependencies.push(DeclaredDependency {
            kind,
            package: PackageRequirement::new(name, DependencySourceConstraint::Any, constraint)
                .map_err(|error| RUniverseCatalogError::InvalidDependency {
                    index,
                    reason: error.to_string(),
                })?,
        });
    }
    dependencies.sort_by(compare_dependencies);
    Ok(dependencies)
}

fn parse_publication(
    object: &Map<String, Value>,
    package: &PackageName,
) -> Result<Option<ReleasePublication>, RUniverseCatalogError> {
    let date_publication = object
        .get("Date/Publication")
        .map(|value| parse_optional_publication_value("Date/Publication", value))
        .transpose()?
        .flatten();
    let published = object
        .get("Published")
        .map(|value| parse_optional_publication_value("Published", value))
        .transpose()?
        .flatten();
    if let (Some(date_publication), Some(published)) = (date_publication, published)
        && date_publication != published
    {
        return Err(RUniverseCatalogError::MetadataConflict {
            package: package.to_string(),
            reason: "Date/Publication and Published disagree".into(),
        });
    }
    Ok(date_publication.or(published).map(ReleasePublication::new))
}

fn parse_optional_publication_value(
    field: &str,
    value: &Value,
) -> Result<Option<PublicationDate>, RUniverseCatalogError> {
    if value.is_null() {
        return Ok(None);
    }
    parse_publication_value(field, value).map(Some)
}

fn parse_publication_value(
    field: &str,
    value: &Value,
) -> Result<PublicationDate, RUniverseCatalogError> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid_field(field, "expected a canonical date or UTC timestamp"))?;
    if value.len() == 10 {
        return PublicationDate::parse(value)
            .map_err(|error| invalid_field(field, error.to_string()));
    }
    if value.len() != 23 || !value.ends_with(" UTC") {
        return Err(invalid_field(
            field,
            "expected YYYY-MM-DD or YYYY-MM-DD HH:MM:SS UTC",
        ));
    }
    let datetime = jiff::civil::DateTime::strptime("%Y-%m-%d %H:%M:%S UTC", value)
        .map_err(|error| invalid_field(field, error.to_string()))?;
    if datetime.strftime("%Y-%m-%d %H:%M:%S UTC").to_string() != value {
        return Err(invalid_field(field, "timestamp is not canonical"));
    }
    PublicationDate::parse(datetime.date().strftime("%Y-%m-%d").to_string())
        .map_err(|error| invalid_field(field, error.to_string()))
}

fn parse_constraint(input: &str) -> Result<VersionConstraint, String> {
    if input.trim().is_empty() {
        return Err("version constraint must not be empty".into());
    }
    let mut clauses = Vec::new();
    for term in input.split(',') {
        let term = term.trim();
        let (op, version) = if let Some(value) = term.strip_prefix(">=") {
            (RelationOp::Ge, value)
        } else if let Some(value) = term.strip_prefix("<=") {
            (RelationOp::Le, value)
        } else if let Some(value) = term.strip_prefix("!=") {
            (RelationOp::Ne, value)
        } else if let Some(value) = term.strip_prefix('>') {
            (RelationOp::Gt, value)
        } else if let Some(value) = term.strip_prefix('<') {
            (RelationOp::Lt, value)
        } else if let Some(value) = term.strip_prefix("==") {
            (RelationOp::Eq, value)
        } else if let Some(value) = term.strip_prefix('=') {
            (RelationOp::Eq, value)
        } else {
            (RelationOp::Eq, term)
        };
        let version = RPackageVersion::parse(version.trim()).map_err(|error| error.to_string())?;
        clauses.push(VersionClause::new(op, version));
    }
    clauses.sort_by(|left, right| {
        relation_op_rank(left.op)
            .cmp(&relation_op_rank(right.op))
            .then_with(|| left.version.cmp(&right.version))
    });
    clauses.dedup_by(|left, right| left.op == right.op && left.version == right.version);
    Ok(VersionConstraint::new(clauses))
}

fn required_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<String, RUniverseCatalogError> {
    object
        .get(field)
        .ok_or_else(|| missing_field(field))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_field(field, "expected a string"))
}

fn missing_field(field: impl Into<String>) -> RUniverseCatalogError {
    RUniverseCatalogError::MissingField {
        field: field.into(),
    }
}

fn invalid_field(field: impl Into<String>, reason: impl Into<String>) -> RUniverseCatalogError {
    RUniverseCatalogError::InvalidField {
        field: field.into(),
        reason: reason.into(),
    }
}

fn package_name_for_error(value: &Value, index: usize) -> String {
    value
        .get("Package")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>")
        .to_owned()
        + &format!("[{index}]")
}

fn map_release_error(index: usize, error: PackageReleaseError) -> RUniverseCatalogError {
    match error {
        PackageReleaseError::ConflictingMetadata { field } => {
            RUniverseCatalogError::MetadataConflict {
                package: format!("<record {index}>"),
                reason: format!("conflicting {field}"),
            }
        }
        PackageReleaseError::InvalidMetadata(error) => invalid_field("metadata", error.to_string()),
        PackageReleaseError::InvalidDependency { index } => {
            RUniverseCatalogError::InvalidDependency {
                index,
                reason: "core rejected the dependency".into(),
            }
        }
    }
}

fn compare_releases(left: &PackageRelease, right: &PackageRelease) -> Ordering {
    left.identity()
        .name()
        .cmp(right.identity().name())
        .then_with(|| left.version().cmp(right.version()))
        .then_with(|| compare_git_provenance(left, right))
}

fn compare_git_provenance(left: &PackageRelease, right: &PackageRelease) -> Ordering {
    let (left_repository, left_commit, left_subdirectory) = match left.identity().provenance() {
        Provenance::GitCommit {
            repository,
            commit,
            subdirectory,
        } => (repository, commit, subdirectory),
        _ => unreachable!("R-universe catalog releases always use Git provenance"),
    };
    let (right_repository, right_commit, right_subdirectory) = match right.identity().provenance() {
        Provenance::GitCommit {
            repository,
            commit,
            subdirectory,
        } => (repository, commit, subdirectory),
        _ => unreachable!("R-universe catalog releases always use Git provenance"),
    };
    left_repository
        .cmp(right_repository)
        .then_with(|| left_commit.cmp(right_commit))
        .then_with(|| left_subdirectory.cmp(right_subdirectory))
}

fn dependency_kind_rank(kind: DependencyKind) -> u8 {
    match kind {
        DependencyKind::Depends => 0,
        DependencyKind::Imports => 1,
        DependencyKind::LinkingTo => 2,
        DependencyKind::Suggests => 3,
        DependencyKind::Enhances => 4,
    }
}

fn relation_op_rank(op: RelationOp) -> u8 {
    match op {
        RelationOp::Lt => 0,
        RelationOp::Le => 1,
        RelationOp::Eq => 2,
        RelationOp::Ne => 3,
        RelationOp::Ge => 4,
        RelationOp::Gt => 5,
    }
}

fn compare_constraints(left: &VersionConstraint, right: &VersionConstraint) -> Ordering {
    left.clauses
        .iter()
        .zip(&right.clauses)
        .map(|(left, right)| {
            relation_op_rank(left.op)
                .cmp(&relation_op_rank(right.op))
                .then_with(|| left.version.cmp(&right.version))
        })
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or_else(|| left.clauses.len().cmp(&right.clauses.len()))
}

fn compare_dependencies(left: &DeclaredDependency, right: &DeclaredDependency) -> Ordering {
    dependency_kind_rank(left.kind)
        .cmp(&dependency_kind_rank(right.kind))
        .then_with(|| left.package.name().cmp(right.package.name()))
        .then_with(|| compare_constraints(left.package.constraint(), right.package.constraint()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY: &str = "r-universe-test";
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn response(entry: &str) -> String {
        format!(r#"[{entry}]"#)
    }

    fn entry(extra: &str) -> String {
        format!(
            r#"{{"Package":"demo","Version":"1.2.0","RemoteUrl":"https://github.com/example/demo.git","RemoteSha":"{COMMIT}","_dependencies":[{{"package":"R","version":">= 4.0","role":"Depends"}}]{extra}}}"#
        )
    }

    #[test]
    fn projects_git_provenance_and_dependencies() {
        let catalog = parse_catalog(
            &response(&entry(",\"Title\":\"Demo\",\"RemoteSubdir\":\"src/demo\"")),
            RegistryId::new(REGISTRY).unwrap(),
        )
        .unwrap();
        let release = &catalog.releases()[0];
        assert!(matches!(
            release.identity().provenance(),
            Provenance::GitCommit { repository, commit, .. }
                if repository.as_str() == "https://github.com/example/demo.git"
                    && commit.as_str() == COMMIT
        ));
        assert!(matches!(
            release.identity().provenance(),
            Provenance::GitCommit {
                subdirectory: Some(subdirectory),
                ..
            } if subdirectory.as_str() == "src/demo"
        ));
        assert_eq!(release.declared_dependencies().len(), 1);
        assert_eq!(
            release.metadata().fields().get("Title"),
            Some(&"Demo".to_owned())
        );
    }

    #[test]
    fn accepts_raw_description_dependencies_alongside_profile_dependencies() {
        let input = response(&entry(
            ",\"Depends\":\"R (>= 4.0)\",\"Imports\":\"cli\",\
             \"LinkingTo\":null,\"Suggests\":[],\"Enhances\":{\"optional\":true}",
        ));
        let catalog = parse_catalog(&input, RegistryId::new(REGISTRY).unwrap()).unwrap();
        let release = &catalog.releases()[0];
        assert_eq!(release.declared_dependencies().len(), 1);
        for field in ["Depends", "Imports", "LinkingTo", "Suggests", "Enhances"] {
            assert!(!release.metadata().fields().contains_key(field));
        }
    }

    #[test]
    fn missing_and_null_dependency_versions_are_unconstrained() {
        let null_version =
            response(&entry("").replace("\"version\":\">= 4.0\",", "\"version\":null,"));
        let missing_version = response(&entry("").replace("\"version\":\">= 4.0\",", ""));
        for input in [null_version, missing_version] {
            let catalog = parse_catalog(&input, RegistryId::new(REGISTRY).unwrap()).unwrap();
            let release = &catalog.releases()[0];
            assert!(
                release.declared_dependencies()[0]
                    .package
                    .constraint()
                    .is_unconstrained()
            );
        }
        let invalid = response(&entry("").replace("\"version\":\">= 4.0\"", "\"version\":true"));
        assert!(matches!(
            parse_catalog(&invalid, RegistryId::new(REGISTRY).unwrap()),
            Err(RUniverseCatalogError::InvalidDependency { .. })
        ));
    }

    #[test]
    fn projects_canonical_publication_date_and_excludes_raw_fields() {
        let input = response(&entry(
            ",\"Date/Publication\":\"2025-06-10 18:33:15 UTC\",\
             \"Published\":\"2025-06-10\"",
        ));
        let catalog = parse_catalog(&input, RegistryId::new(REGISTRY).unwrap()).unwrap();
        let release = &catalog.releases()[0];
        assert_eq!(
            release
                .publication()
                .map(|publication| publication.date().to_string()),
            Some("2025-06-10".to_owned())
        );
        assert!(!release.metadata().fields().contains_key("Date/Publication"));
        assert!(!release.metadata().fields().contains_key("Published"));
    }

    #[test]
    fn treats_missing_and_null_publication_as_unobserved() {
        let registry = RegistryId::new(REGISTRY).unwrap();
        let missing = parse_catalog(&response(&entry("")), registry.clone()).unwrap();
        assert_eq!(missing.releases()[0].publication(), None);

        let null_only =
            parse_catalog(&response(&entry(",\"Published\":null")), registry.clone()).unwrap();
        assert_eq!(null_only.releases()[0].publication(), None);

        for extra in [
            ",\"Date/Publication\":\"2025-06-10\",\"Published\":null",
            ",\"Date/Publication\":null,\"Published\":\"2025-06-10\"",
        ] {
            let catalog = parse_catalog(&response(&entry(extra)), registry.clone()).unwrap();
            assert_eq!(
                catalog.releases()[0]
                    .publication()
                    .map(|publication| publication.date().to_string()),
                Some("2025-06-10".to_owned())
            );
        }
    }

    #[test]
    fn rejects_invalid_or_conflicting_publication_values() {
        let registry = RegistryId::new(REGISTRY).unwrap();
        for input in [
            response(&entry(",\"Published\":true")),
            response(&entry(",\"Date/Publication\":\"2025-06-10 18:33:15\"")),
            response(&entry(",\"Published\":\"2025-6-11\"")),
        ] {
            assert!(
                parse_catalog(&input, registry.clone()).is_err(),
                "accepted invalid publication input"
            );
        }
        let conflicting = response(&entry(
            ",\"Date/Publication\":\"2025-06-10\",\"Published\":\"2025-06-11\"",
        ));
        assert!(matches!(
            parse_catalog(&conflicting, registry),
            Err(RUniverseCatalogError::MetadataConflict { .. })
        ));
    }

    #[test]
    fn profile_is_independent_of_endpoint_hosting() {
        let official = parse_catalog(
            &response(&entry("")),
            RegistryId::new("official-endpoint").unwrap(),
        )
        .unwrap();
        let custom = parse_catalog(
            &response(&entry("")),
            RegistryId::new("custom-endpoint").unwrap(),
        )
        .unwrap();
        assert_eq!(
            official.releases()[0].identity(),
            custom.releases()[0].identity()
        );
        assert_eq!(
            official.releases()[0].version(),
            custom.releases()[0].version()
        );
        assert_eq!(
            official.releases()[0].distributions()[0].registry.as_str(),
            "official-endpoint"
        );
        assert_eq!(
            custom.releases()[0].distributions()[0].registry.as_str(),
            "custom-endpoint"
        );

        let bare_array = format!("[{}]", entry(""));
        assert_eq!(
            parse_catalog(&bare_array, RegistryId::new("self-hosted").unwrap())
                .unwrap()
                .releases()
                .len(),
            1
        );
    }

    #[test]
    fn rejects_provenance_defects() {
        let registry = RegistryId::new(REGISTRY).unwrap();
        for (input, expected) in [
            (
                response(&entry("").replace(
                    ",\"RemoteSha\":\"0123456789abcdef0123456789abcdef01234567\"",
                    "",
                )),
                "RemoteSha",
            ),
            (
                response(&entry("").replace("https://github.com/example/demo.git", "not-a-url")),
                "RemoteUrl",
            ),
            (
                response(&entry("")).replace("0123456789abcdef0123456789abcdef01234567", "0123456"),
                "RemoteSha",
            ),
            (
                response(&entry(",\"RemoteSubdir\":\"../escape\"")),
                "RemoteSubdir",
            ),
            (
                response(&entry(",\"RemoteSubdir\":\"src/./pkg\"")),
                "RemoteSubdir",
            ),
        ] {
            let error = parse_catalog(&input, registry.clone()).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_cran_like_records() {
        let registry = RegistryId::new(REGISTRY).unwrap();
        let cran_like = r#"[{"Package":"demo","Version":"1.0.0","_dependencies":[]}]"#;
        assert!(matches!(
            parse_catalog(cran_like, registry),
            Err(RUniverseCatalogError::MissingField { field }) if field == "RemoteUrl"
        ));
    }

    #[test]
    fn accepts_official_shapes_and_ignores_nonsemantic_fields() {
        let registry = RegistryId::new(REGISTRY).unwrap();
        let package = entry(
            ",\"Packaged\":{\"Date\":\"2025-01-01\",\"User\":\"builder\"},\
             \"_derived_array\":[1,2],\"_derived_object\":{\"state\":\"ok\"},\
             \"UnmodeledNull\":null,\"UnmodeledArray\":[true],\
             \"UnmodeledObject\":{\"value\":1},\"Description\":\"A package\"",
        );
        let array = response(&package);
        let array_catalog = parse_catalog(&array, registry.clone()).unwrap();
        assert_eq!(array_catalog.releases().len(), 1);
        assert_eq!(
            array_catalog.releases()[0]
                .metadata()
                .fields()
                .get("Description"),
            Some(&"A package".to_owned())
        );

        let object_catalog = parse_catalog(&package, registry).unwrap();
        assert_eq!(object_catalog.releases().len(), 1);
        assert_eq!(
            object_catalog.releases()[0].metadata(),
            array_catalog.releases()[0].metadata()
        );
    }

    #[test]
    fn local_profile_revisions_are_numeric() {
        assert_eq!(RUNIVERSE_COMPATIBILITY_PROFILE, 1);
        assert_eq!(RUNIVERSE_PARSER_SCHEMA, 1);
    }

    #[test]
    fn rejects_conflicting_dependency_metadata() {
        let input = response(&format!(
            r#"{{"Package":"demo","Version":"1.2.0","RemoteUrl":"https://github.com/example/demo.git","RemoteSha":"{COMMIT}","_dependencies":[{{"package":"dep","version":">= 1.0","role":"Imports"}},{{"package":"dep","version":"< 1.0","role":"Imports"}}]}}"#
        ));
        assert!(matches!(
            parse_catalog(&input, RegistryId::new(REGISTRY).unwrap()),
            Err(RUniverseCatalogError::MetadataConflict { .. })
        ));
    }
}
