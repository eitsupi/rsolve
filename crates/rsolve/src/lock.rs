//! Shared logical lock domain and projections.
//!
//! This module intentionally contains no artifact or filesystem state. The
//! strict TOML codec lives in [`crate::wire`].

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use rsolve_core::{
    DependencySourceConstraint, EffectiveDependencyKind, LockedIdentities, PackageName, Provenance,
    PublicationCutoff, PublicationDate, RPackageVersion, ReleaseIdentity, RepositoryId, Resolution,
    ResolutionRequest, ResolutionTarget, ResolvedPackage, Sha256Digest, SolverKey,
};

#[cfg(test)]
use rsolve_core::{DependencyKind, PackageRelease};

pub use rsolve_core::{EnvironmentId, EnvironmentIdError};

use crate::manifest::{
    ComposedEnvironment, ComposedRootIntent, Endpoint, Manifest, ManifestError, ManifestSource,
    RegistrySpec, RepositorySpec, canonicalize_constraint,
};

/// An immutable, validated projection of a lockfile for direct consumption.
///
/// This graph preserves the locked identities, versions, metadata digests, and
/// selected dependency edges. It deliberately does not re-check transitive
/// version constraints, upstream metadata, release eligibility, or publication
/// policy: those facts cannot be proven from a lockfile alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedLockedGraph {
    target: ResolutionTarget,
    environment: EnvironmentId,
    publication_cutoff: Option<PublicationDate>,
    packages: Vec<LockedPackage>,
}

impl ConsumedLockedGraph {
    pub fn target(&self) -> &ResolutionTarget {
        &self.target
    }

    pub fn environment(&self) -> &EnvironmentId {
        &self.environment
    }

    pub fn publication_cutoff(&self) -> Option<&PublicationDate> {
        self.publication_cutoff.as_ref()
    }

    pub fn packages(&self) -> &[LockedPackage] {
        &self.packages
    }
}

/// One validated logical release in a lockfile.
///
/// This type has complete-record equality but deliberately no `Hash`: an
/// identity-only hash would discard conflicting metadata before validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedPackage {
    pub identity: ReleaseIdentity,
    pub version: RPackageVersion,
    pub published_version_spelling: Option<Box<str>>,
    /// Effective graph edges, retaining the reason for each selected target.
    pub dependencies: Vec<LockedDependencyEdge>,
    /// Repositories whose available occurrences made this package visible for
    /// the selected solver subject(s). This is provenance visibility, not an
    /// artifact endpoint restriction.
    pub visible_repository_ids: Vec<rsolve_core::RepositoryId>,
    pub metadata_sha256: Sha256Digest,
}

/// One effective dependency edge in the selected lock graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedDependencyEdge {
    /// The dependency reason projected from the resolved graph.
    pub kind: EffectiveDependencyKind,
    /// The selected package target.
    pub package: PackageName,
}

impl LockedPackage {
    fn from_resolved(selected: &ResolvedPackage) -> Result<Self, LockError> {
        let canonical = canonical_version(selected.release().version());
        let published = match selected.release().identity().provenance() {
            Provenance::RegistryRelease { version, .. }
            | Provenance::BioconductorRelease { version, .. } => version.as_str(),
            _ => selected.release().version().as_str(),
        };
        let published_version_spelling = (published != canonical).then(|| published.into());
        let mut dependencies = Vec::new();
        for dependency in selected.effective_dependencies() {
            match dependency.kind {
                EffectiveDependencyKind::Depends
                | EffectiveDependencyKind::Imports
                | EffectiveDependencyKind::LinkingTo => {
                    if dependency.package.name().as_str() != "R" {
                        dependencies.push(LockedDependencyEdge {
                            kind: dependency.kind,
                            package: dependency.package.name().clone(),
                        });
                    }
                }
                EffectiveDependencyKind::PromotedSuggests => {
                    if dependency.package.name().as_str() != "R" {
                        dependencies.push(LockedDependencyEdge {
                            kind: dependency.kind,
                            package: dependency.package.name().clone(),
                        });
                    }
                }
            }
        }
        canonicalize_dependency_edges(&mut dependencies);
        Ok(Self {
            identity: selected.release().identity().clone(),
            version: selected.release().version().clone(),
            published_version_spelling,
            dependencies,
            visible_repository_ids: selected.visible_repository_ids().to_vec(),
            metadata_sha256: selected.release().metadata_digest().clone(),
        })
    }

    #[cfg(test)]
    fn from_release(release: &PackageRelease) -> Self {
        let canonical = canonical_version(release.version());
        let published = match release.identity().provenance() {
            Provenance::RegistryRelease { version, .. }
            | Provenance::BioconductorRelease { version, .. } => version.as_str(),
            _ => release.version().as_str(),
        };
        let published_version_spelling = (published != canonical).then(|| published.into());
        let mut dependencies = release
            .declared_dependencies()
            .iter()
            .filter(|dependency| {
                matches!(
                    dependency.kind,
                    DependencyKind::Depends | DependencyKind::Imports | DependencyKind::LinkingTo
                ) && dependency.package.name().as_str() != "R"
            })
            .map(|dependency| LockedDependencyEdge {
                kind: dependency
                    .kind
                    .effective()
                    .expect("filtered hard dependency"),
                package: dependency.package.name().clone(),
            })
            .collect::<Vec<_>>();
        canonicalize_dependency_edges(&mut dependencies);
        Self {
            identity: release.identity().clone(),
            version: release.version().clone(),
            published_version_spelling,
            dependencies,
            visible_repository_ids: Vec::new(),
            metadata_sha256: release.metadata_digest().clone(),
        }
    }

    fn validate(&self) -> Result<(), LockError> {
        if self.identity.provenance().is_r_base_package() {
            return Err(LockError::RBasePackage {
                identity: identity_key(&self.identity),
            });
        }
        match self.identity.provenance() {
            Provenance::RegistryRelease { version, .. }
            | Provenance::BioconductorRelease { version, .. }
                if version != &self.version =>
            {
                return Err(LockError::ConflictingMetadata {
                    identity: identity_key(&self.identity),
                });
            }
            Provenance::GitCommit { .. }
            | Provenance::ImmutableSource { .. }
            | Provenance::RBasePackage { .. }
            | Provenance::RegistryRelease { .. }
            | Provenance::BioconductorRelease { .. } => {}
        }
        if let Some(spelling) = &self.published_version_spelling {
            let parsed = RPackageVersion::parse(spelling).map_err(|_| {
                LockError::InvalidPublishedVersionSpelling {
                    identity: identity_key(&self.identity),
                }
            })?;
            if parsed != self.version || spelling.as_ref() == canonical_version(&self.version) {
                return Err(LockError::InvalidPublishedVersionSpelling {
                    identity: identity_key(&self.identity),
                });
            }
        }
        Ok(())
    }
}

/// The direct single-resolution container used by the command boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedResolution {
    pub target: ResolutionTarget,
    pub environment: EnvironmentId,
    pub publication_cutoff: Option<PublicationDate>,
    pub packages: Vec<LockedPackage>,
}

/// Shared lock state. The TOML projection flattens this single resolution at
/// the wire root and records the applicability facts needed for safe reuse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lockfile {
    pub resolution_intent_sha256: Sha256Digest,
    pub r_requirement: rsolve_core::VersionConstraint,
    pub resolution: LockedResolution,
}

/// Return the canonical primary lock basename for one selected environment.
/// The default environment intentionally has no environment suffix.
pub(crate) fn canonical_lock_basename(environment: &EnvironmentId) -> String {
    if environment.as_str() == "default" {
        "rsolve.lock".into()
    } else {
        format!("rsolve.{}.lock", environment.as_str())
    }
}

impl Lockfile {
    pub fn from_resolution_with_composed_environment(
        resolution: &Resolution,
        composed: &ComposedEnvironment,
    ) -> Result<Self, LockError> {
        if resolution.target() != &composed.target {
            return Err(LockError::TargetMismatch);
        }
        let resolution_intent_sha256 = composed
            .resolution_intent_digest()
            .map_err(LockError::Manifest)?;
        Self::from_resolution_with_applicability(
            resolution,
            composed.environment.clone(),
            composed.published_before,
            resolution_intent_sha256,
            composed.r_requirement.clone(),
        )
    }

    pub fn from_resolution_with_applicability(
        resolution: &Resolution,
        environment: EnvironmentId,
        publication_cutoff: Option<PublicationDate>,
        resolution_intent_sha256: Sha256Digest,
        r_requirement: rsolve_core::VersionConstraint,
    ) -> Result<Self, LockError> {
        let selected_names = resolution
            .packages()
            .iter()
            .map(|selected| selected.name().clone())
            .collect::<BTreeSet<_>>();
        let mut packages = resolution
            .packages()
            .iter()
            .map(|selected| {
                LockedPackage::from_resolved(selected).map(|mut package| {
                    package
                        .dependencies
                        .retain(|dependency| selected_names.contains(&dependency.package));
                    package
                })
            })
            .collect::<Result<Vec<_>, LockError>>()?;
        for package in &packages {
            package.validate()?;
        }
        packages.sort_by(|left, right| cmp_identity(&left.identity, &right.identity));
        let mut unique: Vec<LockedPackage> = Vec::with_capacity(packages.len());
        for package in packages {
            if let Some(previous) = unique.last()
                && previous.identity == package.identity
            {
                if previous != &package {
                    return Err(LockError::ConflictingMetadata {
                        identity: identity_key(&package.identity),
                    });
                }
                continue;
            }
            unique.push(package);
        }
        Self::new(
            resolution_intent_sha256,
            canonicalize_constraint(&r_requirement),
            LockedResolution {
                target: resolution.target().clone(),
                environment,
                publication_cutoff,
                packages: unique,
            },
        )
    }

    /// Validate a lock container at the reader/command boundary.
    pub fn new(
        resolution_intent_sha256: Sha256Digest,
        r_requirement: rsolve_core::VersionConstraint,
        resolution: LockedResolution,
    ) -> Result<Self, LockError> {
        let mut lock = Self {
            resolution_intent_sha256,
            r_requirement: canonicalize_constraint(&r_requirement),
            resolution,
        };
        lock.normalize_contents()?;
        lock.validate_contents()?;
        Ok(lock)
    }

    /// Produce the identity map consumed by the resolver. Lock policy is
    /// intentionally selected by orchestration, not by the lock reader.
    pub fn locked_identities(&self) -> Result<LockedIdentities, LockError> {
        self.validate()?;
        let resolution = &self.resolution;
        let mut identities = LockedIdentities::new();
        for package in &resolution.packages {
            for key in identity_solver_keys(&package.identity, &package.visible_repository_ids) {
                if let Some(previous) = identities.insert(key, package.identity.clone())
                    && previous != package.identity
                {
                    return Err(LockError::ConflictingMetadata {
                        identity: identity_key(&package.identity),
                    });
                }
            }
        }
        Ok(identities)
    }

    /// Compose a manifest with this lock without embedding lock policy
    /// semantics in the reader.
    pub fn resolution_request(
        &self,
        manifest: Manifest,
        environment: &EnvironmentId,
    ) -> Result<ResolutionRequest, LockError> {
        self.validate()?;
        let resolution = &self.resolution;
        let target = resolution.target.clone();
        if &resolution.environment != environment {
            return Err(LockError::EnvironmentMismatch {
                expected: resolution.environment.to_string(),
                found: environment.to_string(),
            });
        }
        let request = manifest
            .into_resolution_request()
            .map_err(LockError::Manifest)?;
        if request.target != target {
            return Err(LockError::TargetMismatch);
        }
        if !request.r_requirement.satisfies(&target.r_version) {
            return Err(LockError::RRequirementMismatch);
        }
        if request.r_requirement != self.r_requirement {
            return Err(LockError::RRequirementIntentMismatch);
        }
        Ok(ResolutionRequest::new(
            request.roots,
            request.target,
            request.r_requirement,
            self.locked_identities()?,
        )
        .with_optional_publication_cutoff(
            resolution.publication_cutoff.map(PublicationCutoff::new),
        ))
    }

    /// Consume this lock as a directly usable, immutable graph.
    ///
    /// This operation takes no candidate loader, cache, store, or network
    /// capability. It returns only the validated graph projection.
    ///
    /// Validation covers lock self-consistency, environment and target
    /// agreement, the manifest R requirement, direct roots, installed-name
    /// uniqueness, dangling edges, and graph reachability. It does not verify
    /// transitive version constraints, upstream metadata, release eligibility,
    /// or publication policy because those facts are not represented by the
    /// lockfile.
    pub fn consume_locked_graph(
        &self,
        manifest: Manifest,
        environment: &EnvironmentId,
    ) -> Result<ConsumedLockedGraph, LockError> {
        let request = self.resolution_request(manifest.clone(), environment)?;
        let roots = request
            .roots
            .iter()
            .map(|root| RootCheck {
                name: root.package.name().clone(),
                constraint: root.package.constraint().clone(),
                repository: match root.package.source() {
                    DependencySourceConstraint::Repository { repository } => {
                        Some(repository.clone())
                    }
                    DependencySourceConstraint::Any
                    | DependencySourceConstraint::Registry { .. }
                    | DependencySourceConstraint::Bioconductor { .. }
                    | DependencySourceConstraint::Git { .. }
                    | DependencySourceConstraint::Exact(_) => None,
                },
                runtime_provided: matches!(root.package.source(), DependencySourceConstraint::Any),
            })
            .collect::<Vec<_>>();
        self.consume_roots(
            &request.target,
            environment,
            &manifest.r_requirement,
            &roots,
            None,
        )
    }

    /// Consume a lock against a composed environment without candidate
    /// generation. Direct source roots are checked for graph applicability
    /// only; their acquisition-specific source facts remain out of scope.
    pub fn consume_composed_environment(
        &self,
        composed: &ComposedEnvironment,
    ) -> Result<ConsumedLockedGraph, LockError> {
        self.validate()?;
        let resolution = &self.resolution;
        if resolution.target != composed.target {
            return Err(LockError::TargetMismatch);
        }
        if resolution.environment != composed.environment {
            return Err(LockError::EnvironmentMismatch {
                expected: resolution.environment.to_string(),
                found: composed.environment.to_string(),
            });
        }
        if !self.r_requirement.satisfies(&composed.target.r_version) {
            return Err(LockError::RRequirementMismatch);
        }
        if self.r_requirement != composed.r_requirement {
            return Err(LockError::RRequirementIntentMismatch);
        }
        if resolution.publication_cutoff.as_ref() != composed.published_before.as_ref() {
            return Err(LockError::PublicationCutoffMismatch {
                lock: resolution
                    .publication_cutoff
                    .as_ref()
                    .map(ToString::to_string),
                composed: composed.published_before.as_ref().map(ToString::to_string),
            });
        }
        let resolution_intent_sha256 = composed
            .resolution_intent_digest()
            .map_err(LockError::Manifest)?;
        if self.resolution_intent_sha256 != resolution_intent_sha256 {
            return Err(LockError::ResolutionIntentMismatch {
                lock: self.resolution_intent_sha256.to_string(),
                composed: resolution_intent_sha256.to_string(),
            });
        }
        let roots = composed
            .roots
            .iter()
            .map(|root| RootCheck {
                name: root.name.clone(),
                constraint: root.constraint.clone(),
                repository: match &root.source {
                    ManifestSource::Registry { repository } => repository.clone(),
                    ManifestSource::Git { .. }
                    | ManifestSource::Url { .. }
                    | ManifestSource::Path { .. } => None,
                },
                runtime_provided: matches!(
                    &root.source,
                    ManifestSource::Registry { repository: None }
                ),
            })
            .collect::<Vec<_>>();
        self.consume_roots(
            &composed.target,
            &composed.environment,
            &composed.r_requirement,
            &roots,
            Some(&composed.repositories),
        )
    }

    fn consume_roots(
        &self,
        target: &ResolutionTarget,
        environment: &EnvironmentId,
        r_requirement: &rsolve_core::VersionConstraint,
        roots: &[RootCheck],
        configured_repositories: Option<&[crate::manifest::RepositorySpec]>,
    ) -> Result<ConsumedLockedGraph, LockError> {
        self.validate()?;
        let resolution = &self.resolution;
        validate_canonical_resolution(resolution)?;
        if &resolution.target != target {
            return Err(LockError::TargetMismatch);
        }
        if &resolution.environment != environment {
            return Err(LockError::EnvironmentMismatch {
                expected: resolution.environment.to_string(),
                found: environment.to_string(),
            });
        }
        if !r_requirement.satisfies(&resolution.target.r_version) {
            return Err(LockError::RRequirementMismatch);
        }
        let configured_ids = configured_repositories.map(|repositories| {
            repositories
                .iter()
                .map(|repository| repository.id())
                .collect::<BTreeSet<_>>()
        });
        let configured_ranks = configured_repositories.map(|repositories| {
            repositories
                .iter()
                .enumerate()
                .map(|(rank, repository)| (repository.id(), rank))
                .collect::<BTreeMap<_, _>>()
        });
        for package in &resolution.packages {
            if let Some(configured_ids) = &configured_ids {
                for repository in &package.visible_repository_ids {
                    if !configured_ids.contains(repository) {
                        return Err(LockError::UnknownVisibleRepository {
                            package: package.identity.name().to_string(),
                            repository: repository.to_string(),
                        });
                    }
                }
                for repository in &package.visible_repository_ids {
                    let spec = configured_repositories
                        .expect("configured repository IDs were provided")
                        .iter()
                        .find(|candidate| candidate.id() == repository)
                        .expect("visible repository IDs were validated above");
                    if !spec.package_allowed(package.identity.name()) {
                        return Err(LockError::VisibleRepositoryPackageNotAllowed {
                            package: package.identity.name().to_string(),
                            repository: repository.to_string(),
                        });
                    }
                }
            }
            if let Some(configured_ranks) = &configured_ranks {
                let mut previous_rank = None;
                for repository in &package.visible_repository_ids {
                    let rank = configured_ranks[repository];
                    if previous_rank.is_some_and(|previous| previous >= rank) {
                        return Err(LockError::VisibleRepositoryOrderMismatch {
                            package: package.identity.name().to_string(),
                        });
                    }
                    previous_rank = Some(rank);
                }
            }
        }

        let by_name = resolution
            .packages
            .iter()
            .map(|package| (package.identity.name().clone(), package))
            .collect::<BTreeMap<_, _>>();
        let mut reachable = BTreeSet::new();
        for root in roots {
            let name = &root.name;
            if root.runtime_provided && is_r_base_name(name) {
                if !root.constraint.satisfies(&resolution.target.r_version) {
                    return Err(LockError::DirectRootVersionMismatch {
                        name: name.to_string(),
                    });
                }
                continue;
            }
            let package = by_name
                .get(name)
                .ok_or_else(|| LockError::DirectRootMissing {
                    name: name.to_string(),
                })?;
            if !root.constraint.satisfies(&package.version) {
                return Err(LockError::DirectRootVersionMismatch {
                    name: name.to_string(),
                });
            }
            if let Some(repository) = &root.repository
                && !package.visible_repository_ids.contains(repository)
            {
                return Err(LockError::RootRepositoryNotVisible {
                    name: name.to_string(),
                    repository: repository.to_string(),
                });
            }
            mark_reachable(package, &by_name, &mut reachable)?;
        }
        for package in &resolution.packages {
            if !reachable.contains(package.identity.name()) {
                return Err(LockError::UnreachablePackage {
                    package: package.identity.name().to_string(),
                });
            }
        }
        Ok(ConsumedLockedGraph {
            target: resolution.target.clone(),
            environment: resolution.environment.clone(),
            publication_cutoff: resolution.publication_cutoff,
            packages: resolution.packages.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), LockError> {
        self.validate_contents()
    }

    fn normalize_contents(&mut self) -> Result<(), LockError> {
        let resolution = &mut self.resolution;
        for package in &mut resolution.packages {
            package.validate()?;
            canonicalize_dependency_edges(&mut package.dependencies);
            validate_visible_repository_ids(package)?;
        }
        resolution
            .packages
            .sort_by(|left, right| cmp_identity(&left.identity, &right.identity));
        let mut unique: Vec<LockedPackage> = Vec::with_capacity(resolution.packages.len());
        for package in resolution.packages.drain(..) {
            if let Some(previous) = unique.last()
                && previous.identity == package.identity
            {
                if previous != &package {
                    return Err(LockError::ConflictingMetadata {
                        identity: identity_key(&package.identity),
                    });
                }
                continue;
            }
            unique.push(package);
        }
        resolution.packages = unique;
        ensure_installed_names(&resolution.packages)?;
        ensure_dependencies_exist(&resolution.packages)?;
        Ok(())
    }

    fn validate_contents(&self) -> Result<(), LockError> {
        let resolution = &self.resolution;
        if !self.r_requirement.satisfies(&resolution.target.r_version) {
            return Err(LockError::RRequirementMismatch);
        }
        let mut packages = resolution.packages.clone();
        packages.sort_by(|left, right| cmp_identity(&left.identity, &right.identity));
        for package in &packages {
            package.validate()?;
            validate_visible_repository_ids(package)?;
        }
        for pair in packages.windows(2) {
            if pair[0].identity == pair[1].identity && pair[0] != pair[1] {
                return Err(LockError::ConflictingMetadata {
                    identity: identity_key(&pair[0].identity),
                });
            }
        }
        ensure_installed_names(&packages)?;
        ensure_dependencies_exist(&packages)?;
        Ok(())
    }
}

/// Build the applicability facts for the legacy package command. The legacy
/// surface has no manifest file, so its canonical input is represented as a
/// default environment with unconstrained roots and the normalized CRAN
/// endpoint selected by the command.
pub(crate) fn legacy_composed_environment(
    manifest: &Manifest,
    mirror: &str,
    publication_cutoff: Option<PublicationDate>,
) -> Result<ComposedEnvironment, LockError> {
    let endpoint = Endpoint::parse(mirror).map_err(LockError::Manifest)?;
    let repository = RepositorySpec::new(
        RepositoryId::new("cran").expect("cran is a valid repository ID"),
        RegistrySpec::Cran,
        endpoint,
    )
    .map_err(LockError::Manifest)?;
    let roots = manifest
        .requirements
        .iter()
        .map(|requirement| ComposedRootIntent {
            name: requirement.name.clone(),
            constraint: requirement.constraint.clone(),
            source: ManifestSource::Registry { repository: None },
            expansion: rsolve_core::RootExpansionPolicy::HardOnly,
        })
        .collect();
    Ok(ComposedEnvironment {
        environment: EnvironmentId::new("default")
            .expect("default is a valid environment identifier"),
        r_requirement: manifest.r_requirement.clone(),
        published_before: publication_cutoff,
        target: ResolutionTarget::new(manifest.target.r_version.clone()),
        repositories: vec![repository],
        roots,
        locked: rsolve_core::LockedIdentities::new(),
    })
}

struct RootCheck {
    name: PackageName,
    constraint: rsolve_core::VersionConstraint,
    repository: Option<rsolve_core::RepositoryId>,
    runtime_provided: bool,
}

/// Consume a lockfile as an immutable graph without exposing any resolver or
/// candidate-loading capability.
pub fn consume_locked_graph(
    manifest: Manifest,
    lockfile: &Lockfile,
    environment: &EnvironmentId,
) -> Result<ConsumedLockedGraph, LockError> {
    lockfile.consume_locked_graph(manifest, environment)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockError {
    ConflictingMetadata {
        identity: String,
    },
    InvalidPublishedVersionSpelling {
        identity: String,
    },
    RBasePackage {
        identity: String,
    },
    DanglingDependency {
        package: String,
        dependency: String,
    },
    InstalledNameConflict {
        name: String,
        first_identity: String,
        second_identity: String,
    },
    TargetMismatch,
    EnvironmentMismatch {
        expected: String,
        found: String,
    },
    Manifest(ManifestError),
    NonCanonical,
    RRequirementMismatch,
    DirectRootMissing {
        name: String,
    },
    DirectRootVersionMismatch {
        name: String,
    },
    UnreachablePackage {
        package: String,
    },
    DuplicateVisibleRepository {
        package: String,
        repository: String,
    },
    UnknownVisibleRepository {
        package: String,
        repository: String,
    },
    RootRepositoryNotVisible {
        name: String,
        repository: String,
    },
    VisibleRepositoryPackageNotAllowed {
        package: String,
        repository: String,
    },
    VisibleRepositoryOrderMismatch {
        package: String,
    },
    PublicationCutoffMismatch {
        lock: Option<String>,
        composed: Option<String>,
    },
    ResolutionIntentMismatch {
        lock: String,
        composed: String,
    },
    RRequirementIntentMismatch,
    ExactIdentitySetMismatch {
        missing: Vec<String>,
        extra: Vec<String>,
    },
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingMetadata { identity } => {
                write!(f, "conflicting metadata for locked identity {identity}")
            }
            Self::InvalidPublishedVersionSpelling { identity } => {
                write!(f, "invalid published version spelling for {identity}")
            }
            Self::RBasePackage { identity } => {
                write!(f, "R base package is not lockable: {identity}")
            }
            Self::DanglingDependency {
                package,
                dependency,
            } => write!(
                f,
                "locked package {package} refers to unselected dependency {dependency}"
            ),
            Self::InstalledNameConflict {
                name,
                first_identity,
                second_identity,
            } => write!(
                f,
                "installed package name {name} maps to distinct identities {first_identity} and {second_identity}"
            ),
            Self::TargetMismatch => f.write_str("lock target does not match manifest target"),
            Self::EnvironmentMismatch { expected, found } => write!(
                f,
                "lock environment {expected} does not match requested environment {found}"
            ),
            Self::Manifest(error) => write!(f, "manifest composition failed: {error}"),
            Self::NonCanonical => f.write_str("lock contents are not in canonical order"),
            Self::RRequirementMismatch => {
                f.write_str("stored R requirement is not satisfied by the lock target")
            }
            Self::DirectRootMissing { name } => {
                write!(f, "direct manifest root {name} is absent from the lock")
            }
            Self::DirectRootVersionMismatch { name } => {
                write!(
                    f,
                    "locked version for direct manifest root {name} does not satisfy manifest constraint"
                )
            }
            Self::UnreachablePackage { package } => {
                write!(
                    f,
                    "locked package {package} is unreachable from manifest roots"
                )
            }
            Self::DuplicateVisibleRepository {
                package,
                repository,
            } => write!(
                f,
                "locked package {package} lists duplicate visible repository {repository}"
            ),
            Self::UnknownVisibleRepository {
                package,
                repository,
            } => write!(
                f,
                "locked package {package} references unknown configured repository {repository}"
            ),
            Self::RootRepositoryNotVisible { name, repository } => write!(
                f,
                "locked root {name} is not visible from repository {repository}"
            ),
            Self::VisibleRepositoryPackageNotAllowed {
                package,
                repository,
            } => write!(
                f,
                "locked package {package} is excluded by repository {repository}"
            ),
            Self::VisibleRepositoryOrderMismatch { package } => write!(
                f,
                "locked package {package} visible repositories are not in manifest order"
            ),
            Self::PublicationCutoffMismatch { lock, composed } => write!(
                f,
                "lock publication cutoff {lock:?} does not match composed environment cutoff {composed:?}"
            ),
            Self::ResolutionIntentMismatch { lock, composed } => write!(
                f,
                "lock resolution intent {lock} does not match composed environment intent {composed}"
            ),
            Self::RRequirementIntentMismatch => {
                f.write_str("lock R requirement does not match the composed environment")
            }
            Self::ExactIdentitySetMismatch { missing, extra } => write!(
                f,
                "exact lock identity set mismatch (missing: {missing:?}, extra: {extra:?})"
            ),
        }
    }
}

fn is_r_base_name(name: &PackageName) -> bool {
    name.as_str() == "R" || rsolve_resolver::is_r_base_package_name(name)
}

fn mark_reachable(
    package: &LockedPackage,
    by_name: &BTreeMap<PackageName, &LockedPackage>,
    reachable: &mut BTreeSet<PackageName>,
) -> Result<(), LockError> {
    if !reachable.insert(package.identity.name().clone()) {
        return Ok(());
    }
    for dependency in &package.dependencies {
        let dependency_package =
            by_name
                .get(&dependency.package)
                .ok_or_else(|| LockError::DanglingDependency {
                    package: package.identity.name().to_string(),
                    dependency: dependency.package.to_string(),
                })?;
        mark_reachable(dependency_package, by_name, reachable)?;
    }
    Ok(())
}

pub(crate) fn validate_canonical_resolution(
    resolution: &LockedResolution,
) -> Result<(), LockError> {
    let mut packages = resolution.packages.clone();
    packages.sort_by(|left, right| cmp_identity(&left.identity, &right.identity));
    if packages != resolution.packages {
        return Err(LockError::NonCanonical);
    }
    if resolution
        .packages
        .windows(2)
        .any(|pair| pair[0].identity == pair[1].identity)
    {
        return Err(LockError::NonCanonical);
    }
    if resolution.packages.iter().any(|package| {
        package
            .dependencies
            .windows(2)
            .any(|pair| dependency_edge_cmp(&pair[0], &pair[1]) != Ordering::Less)
    }) {
        return Err(LockError::NonCanonical);
    }
    Ok(())
}

fn ensure_installed_names(packages: &[LockedPackage]) -> Result<(), LockError> {
    let mut identities = BTreeMap::<PackageName, &ReleaseIdentity>::new();
    for package in packages {
        let name = package.identity.name().clone();
        if let Some(previous) = identities.insert(name.clone(), &package.identity)
            && previous != &package.identity
        {
            return Err(LockError::InstalledNameConflict {
                name: name.to_string(),
                first_identity: identity_key(previous),
                second_identity: identity_key(&package.identity),
            });
        }
    }
    Ok(())
}

fn ensure_dependencies_exist(packages: &[LockedPackage]) -> Result<(), LockError> {
    let selected = packages
        .iter()
        .map(|package| package.identity.name())
        .collect::<BTreeSet<_>>();
    for package in packages {
        for dependency in &package.dependencies {
            if !selected.contains(&dependency.package) {
                return Err(LockError::DanglingDependency {
                    package: package.identity.name().to_string(),
                    dependency: dependency.package.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn validate_visible_repository_ids(package: &LockedPackage) -> Result<(), LockError> {
    let mut seen = BTreeSet::new();
    for repository in &package.visible_repository_ids {
        if !seen.insert(repository) {
            return Err(LockError::DuplicateVisibleRepository {
                package: package.identity.name().to_string(),
                repository: repository.to_string(),
            });
        }
    }
    Ok(())
}

fn dependency_edge_cmp(left: &LockedDependencyEdge, right: &LockedDependencyEdge) -> Ordering {
    left.package
        .cmp(&right.package)
        .then_with(|| dependency_kind_rank(left.kind).cmp(&dependency_kind_rank(right.kind)))
}

fn dependency_kind_rank(kind: EffectiveDependencyKind) -> u8 {
    match kind {
        EffectiveDependencyKind::Depends => 0,
        EffectiveDependencyKind::Imports => 1,
        EffectiveDependencyKind::LinkingTo => 2,
        EffectiveDependencyKind::PromotedSuggests => 3,
    }
}

fn canonicalize_dependency_edges(edges: &mut Vec<LockedDependencyEdge>) {
    edges.sort_by(dependency_edge_cmp);
    edges.dedup();
}

impl Error for LockError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            _ => None,
        }
    }
}

fn canonical_version(version: &RPackageVersion) -> String {
    let mut components = version.components().collect::<Vec<_>>();
    while components.len() > 2 && components.last() == Some(&0) {
        components.pop();
    }
    components
        .iter()
        .map(|component| component.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn identity_solver_keys(
    identity: &ReleaseIdentity,
    visible_repository_ids: &[rsolve_core::RepositoryId],
) -> Vec<SolverKey> {
    let mut keys = vec![SolverKey::InstalledName(identity.name().clone())];
    keys.extend(
        visible_repository_ids
            .iter()
            .cloned()
            .map(|repository| SolverKey::Repository {
                repository,
                name: identity.name().clone(),
            }),
    );
    match identity.provenance() {
        Provenance::RegistryRelease { namespace, .. } => {
            keys.push(SolverKey::Registry {
                namespace: namespace.clone(),
                name: identity.name().clone(),
            });
            keys.push(SolverKey::Exact(identity.clone()));
        }
        Provenance::BioconductorRelease {
            namespace, release, ..
        } => {
            keys.push(SolverKey::Bioconductor {
                namespace: namespace.clone(),
                release: release.clone(),
                name: identity.name().clone(),
            });
            keys.push(SolverKey::Exact(identity.clone()));
        }
        Provenance::GitCommit { .. } | Provenance::ImmutableSource { .. } => {
            keys.push(SolverKey::Exact(identity.clone()))
        }
        Provenance::RBasePackage { .. } => {}
    }
    keys
}

fn cmp_optional_subdirectory(
    left: &Option<rsolve_core::RepositorySubdir>,
    right: &Option<rsolve_core::RepositorySubdir>,
) -> Ordering {
    left.as_ref()
        .map(rsolve_core::RepositorySubdir::as_str)
        .cmp(&right.as_ref().map(rsolve_core::RepositorySubdir::as_str))
}

fn cmp_identity(left: &ReleaseIdentity, right: &ReleaseIdentity) -> Ordering {
    left.name()
        .cmp(right.name())
        .then_with(|| cmp_provenance(left.provenance(), right.provenance()))
}

fn cmp_provenance(left: &Provenance, right: &Provenance) -> Ordering {
    provenance_rank(left)
        .cmp(&provenance_rank(right))
        .then_with(|| match (left, right) {
            (
                Provenance::RBasePackage { r_version: left },
                Provenance::RBasePackage { r_version: right },
            ) => left.cmp(right),
            (
                Provenance::RegistryRelease {
                    namespace: left_namespace,
                    version: left_version,
                },
                Provenance::RegistryRelease {
                    namespace: right_namespace,
                    version: right_version,
                },
            ) => left_namespace
                .cmp(right_namespace)
                .then_with(|| left_version.cmp(right_version)),
            (
                Provenance::GitCommit {
                    repository: left_repository,
                    commit: left_commit,
                    subdirectory: left_subdirectory,
                },
                Provenance::GitCommit {
                    repository: right_repository,
                    commit: right_commit,
                    subdirectory: right_subdirectory,
                },
            ) => left_repository
                .cmp(right_repository)
                .then_with(|| left_commit.cmp(right_commit))
                .then_with(|| cmp_optional_subdirectory(left_subdirectory, right_subdirectory)),
            (
                Provenance::BioconductorRelease {
                    namespace: left_namespace,
                    release: left_release,
                    version: left_version,
                },
                Provenance::BioconductorRelease {
                    namespace: right_namespace,
                    release: right_release,
                    version: right_version,
                },
            ) => left_namespace
                .cmp(right_namespace)
                .then_with(|| left_release.cmp(right_release))
                .then_with(|| left_version.cmp(right_version)),
            (
                Provenance::ImmutableSource {
                    scheme: left_scheme,
                    digest: left_digest,
                },
                Provenance::ImmutableSource {
                    scheme: right_scheme,
                    digest: right_digest,
                },
            ) => left_scheme
                .cmp(right_scheme)
                .then_with(|| left_digest.cmp(right_digest)),
            _ => Ordering::Equal,
        })
}

fn provenance_rank(provenance: &Provenance) -> u8 {
    match provenance {
        Provenance::RBasePackage { .. } => 0,
        Provenance::RegistryRelease { .. } => 1,
        Provenance::GitCommit { .. } => 2,
        Provenance::BioconductorRelease { .. } => 3,
        Provenance::ImmutableSource { .. } => 4,
    }
}

/// Stable human-readable diagnostic identity. This is not the future wire
/// encoding; it exists only for typed error messages and comparisons.
pub(crate) fn identity_key(identity: &ReleaseIdentity) -> String {
    match identity.provenance() {
        Provenance::RBasePackage { r_version } => {
            format!("{}:r-base:{}", identity.name(), r_version.as_str())
        }
        Provenance::RegistryRelease { namespace, version } => format!(
            "{}:registry:{}@{}",
            identity.name(),
            namespace,
            version.as_str()
        ),
        Provenance::GitCommit {
            repository,
            commit,
            subdirectory,
        } => format!(
            "{}:git:{}@{}:{}",
            identity.name(),
            repository,
            commit,
            subdirectory.as_ref().map_or("", |value| value.as_str())
        ),
        Provenance::BioconductorRelease {
            namespace,
            release,
            version,
        } => format!(
            "{}:bioconductor:{}:{}@{}",
            identity.name(),
            namespace,
            release,
            version.as_str()
        ),
        Provenance::ImmutableSource { scheme, digest } => {
            format!("{}:immutable:{}@{}", identity.name(), scheme, digest)
        }
    }
}

#[cfg(test)]
mod tests;
