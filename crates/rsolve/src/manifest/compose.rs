use super::repository::{
    hex_digest, normalize_relative_subdirectory, normalize_requested_path, validate_named_id,
    validate_relative_subdirectory, validate_repository_id, validate_selector,
};
use super::{
    GitSelector, ManifestDependencySpec, ManifestDocument, ManifestError, ManifestSource,
    RegistrySpec, RepositorySpec,
};
use rsolve_core::{
    DependencySourceConstraint, EnvironmentId, LockedIdentities, PackageName, PublicationCutoff,
    RelationOp, RepositoryId, ResolutionRequest, ResolutionTarget, RootExpansionPolicy,
    RootRequirement, Sha256Digest, VersionClause, VersionConstraint,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

/// A normalized root intent selected for one manifest environment.
///
/// Direct sources remain manifest-layer values until acquisition has produced
/// a verified release identity. They are never represented as an exact core
/// requirement merely because a requested locator was supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposedRootIntent {
    pub name: PackageName,
    pub constraint: VersionConstraint,
    pub source: ManifestSource,
    pub expansion: RootExpansionPolicy,
}

/// The owned result of selecting and composing one environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposedEnvironment {
    pub environment: EnvironmentId,
    pub r_requirement: VersionConstraint,
    pub published_before: Option<rsolve_core::PublicationDate>,
    pub target: ResolutionTarget,
    pub repositories: Vec<RepositorySpec>,
    pub roots: Vec<ComposedRootIntent>,
    pub locked: LockedIdentities,
}

impl ComposedEnvironment {
    /// Project registry-only roots into the resolver's transport-free request.
    /// Direct URL, Git, and local roots require acquisition and therefore fail
    /// closed until their immutable release facts are available.
    pub fn into_resolution_request(self) -> Result<ResolutionRequest, ManifestError> {
        let mut roots = Vec::with_capacity(self.roots.len());
        for root in self.roots {
            let source = match &root.source {
                ManifestSource::Registry { repository: None } => DependencySourceConstraint::Any,
                ManifestSource::Registry {
                    repository: Some(repository),
                } => DependencySourceConstraint::Repository {
                    repository: repository.clone(),
                },
                ManifestSource::Git { .. }
                | ManifestSource::Url { .. }
                | ManifestSource::Path { .. } => {
                    return Err(ManifestError::DirectSourceRequiresAcquisition { name: root.name });
                }
            };
            roots.push(RootRequirement {
                package: rsolve_core::PackageRequirement::new(root.name, source, root.constraint)
                    .map_err(|error| ManifestError::InvalidDependency(error.to_string()))?,
                expansion: root.expansion,
            });
        }
        let publication_cutoff = self.published_before.map(PublicationCutoff::new);
        Ok(
            ResolutionRequest::new(roots, self.target, self.r_requirement, self.locked)
                .with_optional_publication_cutoff(publication_cutoff),
        )
    }

    /// Compute the selected environment's manifest intent digest. The target
    /// R version and locked identities are deliberately excluded: they are
    /// applicability and preference inputs validated separately from the
    /// manifest-selected intent.
    pub fn resolution_intent_digest(&self) -> Result<Sha256Digest, ManifestError> {
        let mut payload = Vec::new();
        append_field(&mut payload, b"schema");
        append_field(&mut payload, b"1");
        append_field(&mut payload, b"environment");
        append_field(&mut payload, self.environment.as_str().as_bytes());
        append_field(&mut payload, b"r");
        append_constraint(&mut payload, &self.r_requirement);
        append_field(&mut payload, b"published-before");
        append_field(
            &mut payload,
            self.published_before
                .map(|date| date.to_string())
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        for repository in &self.repositories {
            append_field(&mut payload, b"repository");
            append_field(&mut payload, repository.id().as_str().as_bytes());
            append_registry(&mut payload, repository.registry());
            append_field(
                &mut payload,
                repository.manifest_endpoint().as_str().as_bytes(),
            );
        }
        for root in &self.roots {
            append_field(&mut payload, b"root");
            append_field(&mut payload, root.name.as_str().as_bytes());
            append_constraint(&mut payload, &root.constraint);
            append_source(&mut payload, &root.source);
            append_field(
                &mut payload,
                match root.expansion {
                    RootExpansionPolicy::HardOnly => b"hard-only",
                    RootExpansionPolicy::DirectSuggests => b"direct-suggests",
                },
            );
        }
        let mut hasher = Sha256::new();
        hasher.update(b"rsolve.resolution-intent.v1\0");
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
        Sha256Digest::new(hex_digest(&hasher.finalize())).map_err(|error| {
            ManifestError::InvalidField {
                field: "resolution intent".into(),
                reason: error.to_string(),
            }
        })
    }
}

impl ManifestDocument {
    pub fn compose_environment(
        &self,
        environment: impl AsRef<str>,
        target: ResolutionTarget,
    ) -> Result<ComposedEnvironment, ManifestError> {
        compose_environment(self, environment, target)
    }

    pub fn compose_environment_with_locked(
        &self,
        environment: impl AsRef<str>,
        target: ResolutionTarget,
        locked: LockedIdentities,
    ) -> Result<ComposedEnvironment, ManifestError> {
        compose_environment_with_locked(self, environment, target, locked)
    }
}

/// Compose base dependencies and the selected environment's groups.
fn compose_environment(
    document: &ManifestDocument,
    environment: impl AsRef<str>,
    target: ResolutionTarget,
) -> Result<ComposedEnvironment, ManifestError> {
    compose_environment_with_locked(document, environment, target, LockedIdentities::new())
}

fn compose_environment_with_locked(
    document: &ManifestDocument,
    environment: impl AsRef<str>,
    target: ResolutionTarget,
    locked: LockedIdentities,
) -> Result<ComposedEnvironment, ManifestError> {
    validate_document(document)?;
    let environment_input = environment.as_ref();
    let environment = EnvironmentId::new(environment_input).map_err(|_error| {
        ManifestError::InvalidIdentifier {
            kind: "environment".into(),
            value: environment_input.into(),
        }
    })?;
    let group_ids: &[String] = match document.environments.get(environment.as_str()) {
        Some(group_ids) => group_ids,
        None if environment.as_str() == "default" => &[],
        None => {
            return Err(ManifestError::UnknownEnvironment {
                id: environment.to_string(),
            });
        }
    };
    let r_requirement = parse_version_constraint(&document.r_requirement, "r.version")?;
    if !r_requirement.satisfies(&target.r_version) {
        return Err(ManifestError::TargetOutsideRConstraint {
            target: target.r_version.to_string(),
            constraint: document.r_requirement.clone(),
        });
    }

    let mut roots = BTreeMap::<PackageName, ComposedRootIntent>::new();
    append_dependencies(&mut roots, &document.dependencies)?;
    for group_id in group_ids {
        let dependencies = document.groups.get(group_id).ok_or_else(|| {
            ManifestError::UnknownEnvironmentGroup {
                environment: environment.to_string(),
                group: group_id.clone(),
            }
        })?;
        append_dependencies(&mut roots, dependencies)?;
    }
    Ok(ComposedEnvironment {
        environment,
        r_requirement,
        published_before: document.published_before,
        target,
        repositories: document.repositories.clone(),
        roots: roots.into_values().collect(),
        locked,
    })
}

pub(crate) fn parse_version_constraint(
    input: &str,
    field: impl Into<String>,
) -> Result<VersionConstraint, ManifestError> {
    let field = field.into();
    if input.is_empty() || input.chars().any(char::is_control) {
        return Err(ManifestError::InvalidVersionConstraint {
            field,
            reason: "constraint must be non-empty and contain no control characters".into(),
        });
    }
    if input.trim() == "*" {
        return Ok(VersionConstraint::unconstrained());
    }
    let mut clauses = Vec::new();
    for term in input.split(',') {
        let term = term.trim();
        if term.is_empty() {
            return Err(ManifestError::InvalidVersionConstraint {
                field: field.clone(),
                reason: "constraint contains an empty conjunction term".into(),
            });
        }
        let (op, version) = if let Some(version) = term.strip_prefix(">=") {
            (RelationOp::Ge, version)
        } else if let Some(version) = term.strip_prefix("<=") {
            (RelationOp::Le, version)
        } else if let Some(version) = term.strip_prefix("!=") {
            (RelationOp::Ne, version)
        } else if let Some(version) = term.strip_prefix("==") {
            (RelationOp::Eq, version)
        } else if let Some(version) = term.strip_prefix('>') {
            (RelationOp::Gt, version)
        } else if let Some(version) = term.strip_prefix('<') {
            (RelationOp::Lt, version)
        } else if let Some(version) = term.strip_prefix('=') {
            (RelationOp::Eq, version)
        } else {
            (RelationOp::Eq, term)
        };
        let version = version.trim();
        if version.is_empty() || version == "*" {
            return Err(ManifestError::InvalidVersionConstraint {
                field: field.clone(),
                reason: "relation must have a numeric R version".into(),
            });
        }
        let version = rsolve_core::RPackageVersion::parse_bare(version).map_err(|error| {
            ManifestError::InvalidVersionConstraint {
                field: field.clone(),
                reason: error.to_string(),
            }
        })?;
        clauses.push(VersionClause::new(op, version));
    }
    Ok(canonicalize_constraint(&VersionConstraint::new(clauses)))
}

fn canonicalize_constraint(constraint: &VersionConstraint) -> VersionConstraint {
    let mut clauses = constraint.clauses.clone();
    clauses.sort_by(|left, right| {
        relation_rank(left.op)
            .cmp(&relation_rank(right.op))
            .then_with(|| left.version.cmp(&right.version))
            .then_with(|| left.version.as_str().cmp(right.version.as_str()))
    });
    clauses.dedup_by(|left, right| left.op == right.op && left.version == right.version);
    VersionConstraint::new(clauses)
}

fn append_dependencies(
    roots: &mut BTreeMap<PackageName, ComposedRootIntent>,
    dependencies: &BTreeMap<PackageName, ManifestDependencySpec>,
) -> Result<(), ManifestError> {
    for (name, dependency) in dependencies {
        if name.as_str() == "R" {
            return Err(ManifestError::RIsNotAPackageRequirement);
        }
        let candidate = ComposedRootIntent {
            name: name.clone(),
            constraint: parse_version_constraint(&dependency.version, name.as_str())?,
            source: normalize_source(name, &dependency.source)?,
            expansion: if dependency.include_suggests {
                RootExpansionPolicy::DirectSuggests
            } else {
                RootExpansionPolicy::HardOnly
            },
        };
        if let Some(existing) = roots.remove(name) {
            roots.insert(name.clone(), merge_roots(existing, candidate)?);
        } else {
            roots.insert(name.clone(), candidate);
        }
    }
    Ok(())
}

fn merge_roots(
    left: ComposedRootIntent,
    right: ComposedRootIntent,
) -> Result<ComposedRootIntent, ManifestError> {
    let source = merge_sources(&left.name, left.source, right.source)?;
    Ok(ComposedRootIntent {
        name: left.name,
        constraint: canonicalize_constraint(&left.constraint.conjunction(&right.constraint)),
        source,
        expansion: if left.expansion == RootExpansionPolicy::DirectSuggests
            || right.expansion == RootExpansionPolicy::DirectSuggests
        {
            RootExpansionPolicy::DirectSuggests
        } else {
            RootExpansionPolicy::HardOnly
        },
    })
}

fn merge_sources(
    name: &PackageName,
    left: ManifestSource,
    right: ManifestSource,
) -> Result<ManifestSource, ManifestError> {
    if left == right {
        return Ok(left);
    }
    match (left, right) {
        (
            ManifestSource::Registry { repository: None },
            ManifestSource::Registry {
                repository: Some(repository),
            },
        )
        | (
            ManifestSource::Registry {
                repository: Some(repository),
            },
            ManifestSource::Registry { repository: None },
        ) => Ok(ManifestSource::Registry {
            repository: Some(repository),
        }),
        _ => Err(ManifestError::SourceConflict {
            field: name.to_string(),
        }),
    }
}

fn normalize_source(
    name: &PackageName,
    source: &ManifestSource,
) -> Result<ManifestSource, ManifestError> {
    match source {
        ManifestSource::Git {
            url,
            selector,
            subdirectory,
        } => Ok(ManifestSource::Git {
            url: url.clone(),
            selector: selector.clone(),
            subdirectory: subdirectory
                .as_deref()
                .map(normalize_relative_subdirectory)
                .transpose()
                .map_err(|reason| ManifestError::InvalidDependencyField {
                    name: name.to_string(),
                    reason,
                })?,
        }),
        ManifestSource::Path { path, sha256 } => Ok(ManifestSource::Path {
            path: normalize_requested_path(path).map_err(|reason| {
                ManifestError::InvalidDependencyField {
                    name: name.to_string(),
                    reason,
                }
            })?,
            sha256: sha256.clone(),
        }),
        _ => Ok(source.clone()),
    }
}

fn validate_document(document: &ManifestDocument) -> Result<(), ManifestError> {
    if document.schema != 1 {
        return Err(ManifestError::UnknownSchema {
            schema: i64::from(document.schema),
        });
    }
    parse_version_constraint(&document.r_requirement, "r.version")?;
    let mut repositories = HashSet::with_capacity(document.repositories.len());
    for repository in &document.repositories {
        validate_repository_id(repository.id())?;
        if !repositories.insert(repository.id().clone()) {
            return Err(ManifestError::DuplicateRepository {
                id: repository.id().clone(),
            });
        }
        if let RegistrySpec::CranLike { namespace } = repository.registry()
            && namespace.as_str() == "cran"
        {
            return Err(ManifestError::InvalidRegistry {
                reason: "cran-like cannot use reserved namespace `cran`".into(),
            });
        }
    }
    for (id, group_ids) in &document.environments {
        EnvironmentId::new(id).map_err(|_error| ManifestError::InvalidIdentifier {
            kind: "environment".into(),
            value: id.clone(),
        })?;
        let mut seen = HashSet::with_capacity(group_ids.len());
        for group_id in group_ids {
            if !document.groups.contains_key(group_id) {
                return Err(ManifestError::UnknownEnvironmentGroup {
                    environment: id.clone(),
                    group: group_id.clone(),
                });
            }
            if !seen.insert(group_id) {
                return Err(ManifestError::DuplicateEnvironmentGroup {
                    environment: id.clone(),
                    group: group_id.clone(),
                });
            }
        }
    }
    for id in document.groups.keys() {
        validate_named_id(id, "group")?;
    }
    validate_dependency_maps(&document.dependencies, &repositories)?;
    for dependencies in document.groups.values() {
        validate_dependency_maps(dependencies, &repositories)?;
    }
    Ok(())
}

fn validate_dependency_maps(
    dependencies: &BTreeMap<PackageName, ManifestDependencySpec>,
    repositories: &HashSet<RepositoryId>,
) -> Result<(), ManifestError> {
    for (name, dependency) in dependencies {
        parse_version_constraint(&dependency.version, name.as_str())?;
        if name.as_str() == "R" {
            return Err(ManifestError::RIsNotAPackageRequirement);
        }
        if let ManifestSource::Registry {
            repository: Some(repository),
        } = &dependency.source
        {
            validate_repository_id(repository)?;
            if !repositories.contains(repository) {
                return Err(ManifestError::UnknownRepositoryReference {
                    id: repository.clone(),
                    field: name.to_string(),
                });
            }
        }
        match &dependency.source {
            ManifestSource::Registry { .. } => {}
            ManifestSource::Git {
                selector,
                subdirectory,
                ..
            } => {
                let selector_value = match selector {
                    GitSelector::DefaultBranch => None,
                    GitSelector::Branch(value)
                    | GitSelector::Tag(value)
                    | GitSelector::Rev(value) => Some(value),
                };
                if let Some(value) = selector_value {
                    validate_selector(value, name.as_str())?;
                }
                if let Some(value) = subdirectory {
                    validate_relative_subdirectory(value).map_err(|reason| {
                        ManifestError::InvalidDependencyField {
                            name: name.to_string(),
                            reason,
                        }
                    })?;
                }
            }
            ManifestSource::Url { .. } => {}
            ManifestSource::Path { path, .. } => {
                normalize_requested_path(path).map_err(|reason| {
                    ManifestError::InvalidDependencyField {
                        name: name.to_string(),
                        reason,
                    }
                })?;
            }
        }
    }
    Ok(())
}

fn append_field(payload: &mut Vec<u8>, value: &[u8]) {
    payload.extend_from_slice(&(value.len() as u64).to_be_bytes());
    payload.extend_from_slice(value);
}

fn append_constraint(payload: &mut Vec<u8>, constraint: &VersionConstraint) {
    let mut clauses = constraint.clauses.iter().collect::<Vec<_>>();
    clauses.sort_by(|left, right| {
        relation_rank(left.op)
            .cmp(&relation_rank(right.op))
            .then_with(|| left.version.cmp(&right.version))
            .then_with(|| left.version.as_str().cmp(right.version.as_str()))
    });
    clauses.dedup_by(|left, right| left.op == right.op && left.version == right.version);
    append_field(payload, b"constraint");
    for clause in clauses {
        append_field(payload, relation_tag(clause.op));
        let version = clause
            .version
            .components()
            .take(clause.version.canonical_component_count())
            .map(|component| component.to_string())
            .collect::<Vec<_>>()
            .join(".");
        append_field(
            payload,
            if version.is_empty() {
                b"0"
            } else {
                version.as_bytes()
            },
        );
    }
}

fn append_registry(payload: &mut Vec<u8>, registry: &RegistrySpec) {
    append_field(payload, b"registry");
    append_field(payload, registry.tag().as_bytes());
    if let RegistrySpec::CranLike { namespace } = registry {
        append_field(payload, namespace.as_str().as_bytes());
    }
}

fn append_source(payload: &mut Vec<u8>, source: &ManifestSource) {
    match source {
        ManifestSource::Registry { repository } => {
            append_field(payload, b"registry-source");
            append_field(
                payload,
                repository
                    .as_ref()
                    .map(RepositoryId::as_str)
                    .unwrap_or("")
                    .as_bytes(),
            );
        }
        ManifestSource::Git {
            url,
            selector,
            subdirectory,
        } => {
            append_field(payload, b"git");
            append_field(payload, url.as_str().as_bytes());
            match selector {
                GitSelector::DefaultBranch => append_field(payload, b"default-branch"),
                GitSelector::Branch(value) => {
                    append_field(payload, b"branch");
                    append_field(payload, value.as_bytes());
                }
                GitSelector::Tag(value) => {
                    append_field(payload, b"tag");
                    append_field(payload, value.as_bytes());
                }
                GitSelector::Rev(value) => {
                    append_field(payload, b"rev");
                    append_field(payload, value.as_bytes());
                }
            }
            append_field(payload, subdirectory.as_deref().unwrap_or("").as_bytes());
        }
        ManifestSource::Url { url, sha256 } => {
            append_field(payload, b"url");
            append_field(payload, url.as_str().as_bytes());
            append_field(
                payload,
                sha256
                    .as_ref()
                    .map(Sha256Digest::as_str)
                    .unwrap_or("")
                    .as_bytes(),
            );
        }
        ManifestSource::Path { path, sha256 } => {
            append_field(payload, b"path");
            append_field(payload, path.as_bytes());
            append_field(
                payload,
                sha256
                    .as_ref()
                    .map(Sha256Digest::as_str)
                    .unwrap_or("")
                    .as_bytes(),
            );
        }
    }
}

fn relation_rank(op: RelationOp) -> u8 {
    match op {
        RelationOp::Lt => 0,
        RelationOp::Le => 1,
        RelationOp::Eq => 2,
        RelationOp::Ne => 3,
        RelationOp::Ge => 4,
        RelationOp::Gt => 5,
    }
}

fn relation_tag(op: RelationOp) -> &'static [u8] {
    match op {
        RelationOp::Lt => b"<",
        RelationOp::Le => b"<=",
        RelationOp::Eq => b"=",
        RelationOp::Ne => b"!=",
        RelationOp::Ge => b">=",
        RelationOp::Gt => b">",
    }
}
