use super::repository::{
    digest_fields, hex_digest, normalize_requested_path, reject_raw_root_escape, validate_named_id,
    validate_relative_subdirectory, validate_repository_id, validate_selector,
};
use super::{Endpoint, ManifestError, RegistrySpec, RepositorySpec};
use rsolve_core::{
    NormalizedGitUrl, PackageName, PackageNamespace, PublicationDate, RepositoryId, Sha256Digest,
};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Parsed and validated manifest wire document.  This is deliberately
/// separate from [`Manifest`], the legacy in-memory first-slice request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestDocument {
    pub schema: u32,
    pub project_root: Option<PathBuf>,
    pub r_requirement: String,
    pub published_before: Option<PublicationDate>,
    pub repositories: Vec<RepositorySpec>,
    pub dependencies: BTreeMap<PackageName, ManifestDependencySpec>,
    pub groups: BTreeMap<String, BTreeMap<PackageName, ManifestDependencySpec>>,
    pub environments: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestSource {
    Registry {
        repository: Option<RepositoryId>,
    },
    Git {
        url: NormalizedGitUrl,
        selector: GitSelector,
        subdirectory: Option<String>,
    },
    Url {
        url: DirectUrl,
        sha256: Option<Sha256Digest>,
    },
    Path {
        path: String,
        sha256: Option<Sha256Digest>,
    },
}

/// A direct source URL. Unlike a repository base endpoint, its query is part
/// of the requested immutable locator and is therefore retained.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectUrl(Box<str>);

impl DirectUrl {
    pub fn parse(input: impl AsRef<str>) -> Result<Self, ManifestError> {
        let original = input.as_ref();
        reject_raw_root_escape(original)?;
        let mut url =
            url::Url::parse(original).map_err(|error| ManifestError::InvalidEndpoint {
                value: original.into(),
                reason: error.to_string(),
            })?;
        if url.scheme() != "https" || url.host_str().is_none() {
            return Err(ManifestError::InvalidEndpoint {
                value: original.into(),
                reason: "direct source URL must be an absolute HTTPS URL".into(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(ManifestError::InvalidEndpoint {
                value: original.into(),
                reason: "direct source URL forbids credentials and fragments".into(),
            });
        }
        let path = super::repository::normalize_url_path(url.path())?;
        url.set_path(&path);
        if url.port() == Some(443) {
            url.set_port(None)
                .map_err(|_| ManifestError::InvalidEndpoint {
                    value: original.into(),
                    reason: "invalid default port".into(),
                })?;
        }
        Ok(Self(url.to_string().into_boxed_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DirectUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitSelector {
    DefaultBranch,
    Branch(String),
    Tag(String),
    Rev(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestDependencySpec {
    pub version: String,
    pub source: ManifestSource,
    pub include_suggests: bool,
}

impl ManifestDocument {
    pub fn repository_intent_digest(&self) -> Result<Sha256Digest, ManifestError> {
        let mut fields = Vec::new();
        for repository in &self.repositories {
            fields.push(repository.id().as_str().as_bytes());
            fields.push(repository.registry().tag().as_bytes());
            if let RegistrySpec::CranLike { namespace } = repository.registry() {
                fields.push(namespace.as_str().as_bytes());
            }
            fields.push(repository.manifest_endpoint().as_str().as_bytes());
        }
        Sha256Digest::new(hex_digest(&digest_fields(&fields))).map_err(|error| {
            ManifestError::InvalidRepository {
                reason: error.to_string(),
            }
        })
    }
}

pub fn parse_manifest(input: &str) -> Result<ManifestDocument, ManifestError> {
    let value: toml::Value =
        toml::from_str(input).map_err(|error| ManifestError::Toml(error.to_string()))?;
    parse_manifest_value(value, None)
}

pub fn read_manifest(path: impl AsRef<Path>) -> Result<ManifestDocument, ManifestError> {
    let path = path.as_ref();
    let input = fs::read_to_string(path).map_err(|error| ManifestError::Io {
        path: path.to_path_buf(),
        source: error.to_string(),
    })?;
    parse_manifest_value(
        toml::from_str(&input).map_err(|error| ManifestError::Toml(error.to_string()))?,
        Some(
            path.parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        ),
    )
}

pub fn discover_manifest(
    start: impl AsRef<Path>,
) -> Result<(PathBuf, ManifestDocument), ManifestError> {
    let mut directory = start.as_ref().to_path_buf();
    if !directory.is_dir() {
        directory = directory
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
    }
    loop {
        let candidate = directory.join("rsolve.toml");
        if candidate.is_file() {
            return Ok((candidate.clone(), read_manifest(candidate)?));
        }
        if !directory.pop() {
            break;
        }
    }
    Err(ManifestError::NotFound {
        start: start.as_ref().to_path_buf(),
    })
}

pub fn load_manifest(
    explicit_path: Option<&Path>,
    start: impl AsRef<Path>,
) -> Result<(PathBuf, ManifestDocument), ManifestError> {
    if let Some(path) = explicit_path {
        let path = path.to_path_buf();
        let document = read_manifest(&path)?;
        return Ok((path, document));
    }
    discover_manifest(start)
}

fn parse_manifest_value(
    value: toml::Value,
    project_root: Option<PathBuf>,
) -> Result<ManifestDocument, ManifestError> {
    let root = value.as_table().ok_or_else(|| ManifestError::WrongType {
        field: "root".into(),
        expected: "table".into(),
    })?;
    reject_unknown(
        root,
        &[
            "rsolve",
            "r",
            "resolution",
            "repositories",
            "dependencies",
            "groups",
            "environments",
        ],
        "root",
    )?;
    let rsolve = table(root, "rsolve")?;
    reject_unknown(rsolve, &["schema"], "rsolve")?;
    let schema = integer(rsolve, "schema")?.ok_or(ManifestError::MissingField {
        field: "rsolve.schema".into(),
    })?;
    if schema != 1 {
        return Err(ManifestError::UnknownSchema { schema });
    }
    let r_requirement = parse_required_section_string(root, "r", "version")?;
    let published_before = parse_optional_date(root, "resolution", "published-before")?;
    let repositories = parse_repositories(root.get("repositories"))?;
    let dependencies = parse_dependencies(root.get("dependencies"), "dependencies")?;
    let groups = parse_groups(root.get("groups"))?;
    let environments = parse_environments(root.get("environments"))?;
    let repository_ids: HashSet<_> = repositories
        .iter()
        .map(|repository| repository.id().clone())
        .collect();
    validate_repository_references(&dependencies, &groups, &repository_ids)?;
    validate_environment_references(&environments, &groups)?;
    Ok(ManifestDocument {
        schema: schema as u32,
        project_root,
        r_requirement,
        published_before,
        repositories,
        dependencies,
        groups,
        environments,
    })
}

fn parse_optional_string(
    root: &toml::map::Map<String, toml::Value>,
    section: &str,
    key: &str,
) -> Result<Option<String>, ManifestError> {
    let Some(value) = root.get(section) else {
        return Ok(None);
    };
    let table = value.as_table().ok_or_else(|| ManifestError::WrongType {
        field: section.into(),
        expected: "table".into(),
    })?;
    reject_unknown(table, &[key], section)?;
    string(table, key)
}

fn parse_required_section_string(
    root: &toml::map::Map<String, toml::Value>,
    section: &str,
    key: &str,
) -> Result<String, ManifestError> {
    let value = root
        .get(section)
        .ok_or_else(|| ManifestError::MissingField {
            field: section.into(),
        })?;
    let table = value.as_table().ok_or_else(|| ManifestError::WrongType {
        field: section.into(),
        expected: "table".into(),
    })?;
    reject_unknown(table, &[key], section)?;
    let value = string(table, key)?.ok_or_else(|| ManifestError::MissingField {
        field: format!("{section}.{key}"),
    })?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ManifestError::InvalidField {
            field: format!("{section}.{key}"),
            reason: "constraint must be non-empty and contain no control characters".into(),
        });
    }
    Ok(value)
}

fn parse_optional_date(
    root: &toml::map::Map<String, toml::Value>,
    section: &str,
    key: &str,
) -> Result<Option<PublicationDate>, ManifestError> {
    let Some(value) = parse_optional_string(root, section, key)? else {
        return Ok(None);
    };
    PublicationDate::parse(&value)
        .map(Some)
        .map_err(|error| ManifestError::InvalidField {
            field: format!("{section}.{key}"),
            reason: error.to_string(),
        })
}

fn table<'a>(
    root: &'a toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<&'a toml::map::Map<String, toml::Value>, ManifestError> {
    match root.get(key) {
        Some(toml::Value::Table(value)) => Ok(value),
        Some(_) => Err(ManifestError::WrongType {
            field: key.into(),
            expected: "table".into(),
        }),
        None => Err(ManifestError::MissingField { field: key.into() }),
    }
}

fn reject_unknown(
    table: &toml::map::Map<String, toml::Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), ManifestError> {
    if let Some(field) = table
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(ManifestError::UnknownField {
            field: format!("{context}.{field}"),
        });
    }
    Ok(())
}

fn string(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Option<String>, ManifestError> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(ManifestError::WrongType {
            field: key.into(),
            expected: "string".into(),
        }),
    }
}

fn required_string(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<String, ManifestError> {
    string(table, key)?.ok_or_else(|| ManifestError::MissingField { field: key.into() })
}

fn integer(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Option<i64>, ManifestError> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::Integer(value)) => Ok(Some(*value)),
        Some(_) => Err(ManifestError::WrongType {
            field: key.into(),
            expected: "integer".into(),
        }),
    }
}

fn parse_repositories(value: Option<&toml::Value>) -> Result<Vec<RepositorySpec>, ManifestError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = value.as_array().ok_or_else(|| ManifestError::WrongType {
        field: "repositories".into(),
        expected: "array of tables".into(),
    })?;
    let mut result = Vec::with_capacity(entries.len());
    let mut ids = HashSet::new();
    for entry in entries {
        let table = entry.as_table().ok_or_else(|| ManifestError::WrongType {
            field: "repositories[]".into(),
            expected: "table".into(),
        })?;
        reject_unknown(table, &["id", "url", "registry"], "repositories[]")?;
        let id = RepositoryId::new(required_string(table, "id")?).map_err(|error| {
            ManifestError::InvalidRepository {
                reason: error.to_string(),
            }
        })?;
        validate_repository_id(&id)?;
        if !ids.insert(id.clone()) {
            return Err(ManifestError::DuplicateRepository { id });
        }
        let endpoint = Endpoint::parse(required_string(table, "url")?)?;
        let registry = parse_registry(table.get("registry"))?;
        result.push(RepositorySpec::new(id, registry, endpoint)?);
    }
    Ok(result)
}

fn parse_registry(value: Option<&toml::Value>) -> Result<RegistrySpec, ManifestError> {
    let value = value.ok_or_else(|| ManifestError::MissingField {
        field: "repositories[].registry".into(),
    })?;
    let (kind, namespace) = match value {
        toml::Value::String(kind) => (kind.clone(), None),
        toml::Value::Table(table) => {
            reject_unknown(table, &["kind", "namespace"], "repositories[].registry")?;
            (required_string(table, "kind")?, string(table, "namespace")?)
        }
        _ => {
            return Err(ManifestError::WrongType {
                field: "repositories[].registry".into(),
                expected: "string or table".into(),
            });
        }
    };
    match kind.as_str() {
        "cran" => {
            if namespace.is_some() {
                return Err(ManifestError::InvalidRegistry {
                    reason: "cran does not accept namespace".into(),
                });
            }
            Ok(RegistrySpec::Cran)
        }
        "cran-like" => {
            let namespace = namespace.ok_or_else(|| ManifestError::InvalidRegistry {
                reason: "cran-like requires namespace".into(),
            })?;
            if namespace == "cran" {
                return Err(ManifestError::InvalidRegistry {
                    reason: "cran-like cannot use reserved namespace `cran`".into(),
                });
            }
            let namespace = PackageNamespace::new(&namespace).map_err(|error| {
                ManifestError::InvalidRegistry {
                    reason: error.to_string(),
                }
            })?;
            RegistrySpec::cran_like(namespace)
        }
        "r-universe" => {
            if namespace.is_some() {
                return Err(ManifestError::InvalidRegistry {
                    reason: "r-universe is parameterless".into(),
                });
            }
            Ok(RegistrySpec::RUniverse)
        }
        other => Err(ManifestError::UnknownRegistryKind { kind: other.into() }),
    }
}

fn parse_dependencies(
    value: Option<&toml::Value>,
    context: &str,
) -> Result<BTreeMap<PackageName, ManifestDependencySpec>, ManifestError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let table = value.as_table().ok_or_else(|| ManifestError::WrongType {
        field: context.into(),
        expected: "table".into(),
    })?;
    table
        .iter()
        .map(|(name, value)| {
            let package =
                PackageName::new(name).map_err(|error| ManifestError::InvalidDependencyField {
                    name: name.clone(),
                    reason: error.to_string(),
                })?;
            if package.as_str() == "R" {
                return Err(ManifestError::RIsNotAPackageRequirement);
            }
            Ok((
                package,
                parse_dependency(value, &format!("{context}.{name}"))?,
            ))
        })
        .collect()
}

fn validate_repository_references(
    dependencies: &BTreeMap<PackageName, ManifestDependencySpec>,
    groups: &BTreeMap<String, BTreeMap<PackageName, ManifestDependencySpec>>,
    repository_ids: &HashSet<RepositoryId>,
) -> Result<(), ManifestError> {
    let check = |field: String, source: &ManifestSource| {
        if let ManifestSource::Registry {
            repository: Some(id),
        } = source
            && !repository_ids.contains(id)
        {
            return Err(ManifestError::UnknownRepositoryReference {
                id: id.clone(),
                field,
            });
        }
        Ok(())
    };
    for (name, dependency) in dependencies {
        check(name.to_string(), &dependency.source)?;
    }
    for (group, dependencies) in groups {
        for (name, dependency) in dependencies {
            check(format!("groups.{group}.{name}"), &dependency.source)?;
        }
    }
    Ok(())
}

fn parse_dependency(
    value: &toml::Value,
    context: &str,
) -> Result<ManifestDependencySpec, ManifestError> {
    let (version, source, include_suggests) = match value {
        toml::Value::String(version) => {
            validate_version(version, context)?;
            (
                version.clone(),
                ManifestSource::Registry { repository: None },
                false,
            )
        }
        toml::Value::Table(table) => {
            reject_unknown(
                table,
                &[
                    "version",
                    "repository",
                    "git",
                    "branch",
                    "tag",
                    "rev",
                    "subdirectory",
                    "url",
                    "sha256",
                    "path",
                    "include-suggests",
                ],
                context,
            )?;
            let version = string(table, "version")?.unwrap_or_else(|| "*".into());
            validate_version(&version, context)?;
            let include = match table.get("include-suggests") {
                None => false,
                Some(toml::Value::Boolean(value)) => *value,
                Some(_) => {
                    return Err(ManifestError::WrongType {
                        field: format!("{context}.include-suggests"),
                        expected: "boolean".into(),
                    });
                }
            };
            let subdirectory = string(table, "subdirectory")?;
            let repository = string(table, "repository")?;
            let git = string(table, "git")?;
            let direct_url = string(table, "url")?;
            let path = string(table, "path")?;
            let sources = usize::from(repository.is_some())
                + usize::from(git.is_some())
                + usize::from(direct_url.is_some())
                + usize::from(path.is_some());
            if sources > 1 {
                return Err(ManifestError::SourceConflict {
                    field: context.into(),
                });
            }
            let source = if let Some(repository) = repository {
                let id = RepositoryId::new(repository).map_err(|error| {
                    ManifestError::InvalidRepository {
                        reason: error.to_string(),
                    }
                })?;
                validate_repository_id(&id)?;
                if table.keys().any(|key| {
                    matches!(
                        key.as_str(),
                        "branch" | "tag" | "rev" | "sha256" | "subdirectory"
                    )
                }) {
                    return Err(ManifestError::SourceConflict {
                        field: context.into(),
                    });
                }
                ManifestSource::Registry {
                    repository: Some(id),
                }
            } else if let Some(git) = git {
                let url = NormalizedGitUrl::new(git).map_err(|error| {
                    ManifestError::InvalidDependencyField {
                        name: context.into(),
                        reason: error.to_string(),
                    }
                })?;
                let selectors = [
                    string(table, "branch")?,
                    string(table, "tag")?,
                    string(table, "rev")?,
                ];
                if selectors
                    .iter()
                    .filter(|selector| selector.is_some())
                    .count()
                    > 1
                {
                    return Err(ManifestError::SourceConflict {
                        field: context.into(),
                    });
                }
                let selector = if let Some(value) = selectors[0].clone() {
                    validate_selector(&value, context)?;
                    GitSelector::Branch(value)
                } else if let Some(value) = selectors[1].clone() {
                    validate_selector(&value, context)?;
                    GitSelector::Tag(value)
                } else if let Some(value) = selectors[2].clone() {
                    validate_selector(&value, context)?;
                    GitSelector::Rev(value)
                } else {
                    GitSelector::DefaultBranch
                };
                if table.contains_key("sha256") {
                    return Err(ManifestError::SourceConflict {
                        field: context.into(),
                    });
                }
                if let Some(subdirectory) = &subdirectory {
                    validate_relative_subdirectory(subdirectory).map_err(|reason| {
                        ManifestError::InvalidDependencyField {
                            name: context.into(),
                            reason,
                        }
                    })?;
                }
                ManifestSource::Git {
                    url,
                    selector,
                    subdirectory,
                }
            } else if let Some(url) = direct_url {
                if subdirectory.is_some() {
                    return Err(ManifestError::SourceConflict {
                        field: context.into(),
                    });
                }
                let url = DirectUrl::parse(url)?;
                let sha256 = string(table, "sha256")?
                    .map(|digest| {
                        Sha256Digest::new(digest).map_err(|error| {
                            ManifestError::InvalidDependencyField {
                                name: context.into(),
                                reason: error.to_string(),
                            }
                        })
                    })
                    .transpose()?;
                if table
                    .keys()
                    .any(|key| matches!(key.as_str(), "branch" | "tag" | "rev"))
                {
                    return Err(ManifestError::SourceConflict {
                        field: context.into(),
                    });
                }
                ManifestSource::Url { url, sha256 }
            } else if let Some(path) = path {
                if Path::new(&path).is_absolute() || path.is_empty() {
                    return Err(ManifestError::InvalidDependencyField {
                        name: context.into(),
                        reason: "path must be a non-empty relative path".into(),
                    });
                }
                if table
                    .keys()
                    .any(|key| matches!(key.as_str(), "branch" | "tag" | "rev"))
                {
                    return Err(ManifestError::SourceConflict {
                        field: context.into(),
                    });
                }
                let sha256 = string(table, "sha256")?
                    .map(|digest| {
                        Sha256Digest::new(digest).map_err(|error| {
                            ManifestError::InvalidDependencyField {
                                name: context.into(),
                                reason: error.to_string(),
                            }
                        })
                    })
                    .transpose()?;
                if subdirectory.is_some() {
                    return Err(ManifestError::SourceConflict {
                        field: context.into(),
                    });
                }
                ManifestSource::Path {
                    path: normalize_requested_path(&path).map_err(|reason| {
                        ManifestError::InvalidDependencyField {
                            name: context.into(),
                            reason,
                        }
                    })?,
                    sha256,
                }
            } else {
                if table.keys().any(|key| {
                    matches!(
                        key.as_str(),
                        "branch" | "tag" | "rev" | "sha256" | "subdirectory"
                    )
                }) {
                    return Err(ManifestError::SourceConflict {
                        field: context.into(),
                    });
                }
                ManifestSource::Registry { repository: None }
            };
            (version, source, include)
        }
        _ => {
            return Err(ManifestError::WrongType {
                field: context.into(),
                expected: "string or table".into(),
            });
        }
    };
    Ok(ManifestDependencySpec {
        version,
        source,
        include_suggests,
    })
}

fn validate_version(value: &str, context: &str) -> Result<(), ManifestError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ManifestError::InvalidDependencyField {
            name: context.into(),
            reason: "version must be non-empty and contain no control characters".into(),
        });
    }
    Ok(())
}

fn parse_groups(
    value: Option<&toml::Value>,
) -> Result<BTreeMap<String, BTreeMap<PackageName, ManifestDependencySpec>>, ManifestError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let groups = value.as_table().ok_or_else(|| ManifestError::WrongType {
        field: "groups".into(),
        expected: "table".into(),
    })?;
    groups
        .iter()
        .map(|(id, value)| {
            validate_named_id(id, "group")?;
            let table = value.as_table().ok_or_else(|| ManifestError::WrongType {
                field: format!("groups.{id}"),
                expected: "table".into(),
            })?;
            reject_unknown(table, &["dependencies"], &format!("groups.{id}"))?;
            Ok((
                id.clone(),
                parse_dependencies(
                    table.get("dependencies"),
                    &format!("groups.{id}.dependencies"),
                )?,
            ))
        })
        .collect()
}

fn parse_environments(
    value: Option<&toml::Value>,
) -> Result<BTreeMap<String, Vec<String>>, ManifestError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let environments = value.as_table().ok_or_else(|| ManifestError::WrongType {
        field: "environments".into(),
        expected: "table".into(),
    })?;
    environments
        .iter()
        .map(|(id, value)| {
            validate_named_id(id, "environment")?;
            let groups = value.as_array().ok_or_else(|| ManifestError::WrongType {
                field: format!("environments.{id}"),
                expected: "array of strings".into(),
            })?;
            let groups = groups
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(String::from)
                        .ok_or_else(|| ManifestError::WrongType {
                            field: format!("environments.{id}[]"),
                            expected: "string".into(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((id.clone(), groups))
        })
        .collect()
}

fn validate_environment_references(
    environments: &BTreeMap<String, Vec<String>>,
    groups: &BTreeMap<String, BTreeMap<PackageName, ManifestDependencySpec>>,
) -> Result<(), ManifestError> {
    for (environment, references) in environments {
        let mut seen = HashSet::with_capacity(references.len());
        for group in references {
            if !groups.contains_key(group) {
                return Err(ManifestError::UnknownEnvironmentGroup {
                    environment: environment.clone(),
                    group: group.clone(),
                });
            }
            if !seen.insert(group) {
                return Err(ManifestError::DuplicateEnvironmentGroup {
                    environment: environment.clone(),
                    group: group.clone(),
                });
            }
        }
    }
    Ok(())
}
