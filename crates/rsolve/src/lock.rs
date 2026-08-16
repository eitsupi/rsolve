//! Shared logical lock domain and projections.
//!
//! This module intentionally contains no artifact or filesystem state. The
//! strict TOML codec lives in [`crate::wire`].

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use rsolve_core::{
    DependencyKind, DependencyRequirement, DependencySourceConstraint, Distribution,
    DistributionChannel, LockedIdentities, PackageName, PackageRelease, Provenance,
    RPackageVersion, RegistryId, ReleaseIdentity, Resolution, ResolutionRequest, ResolutionTarget,
    Sha256Digest, SnapshotId, SolverKey, VersionClause, VersionConstraint,
};

pub use rsolve_core::{EnvironmentId, EnvironmentIdError};

use crate::manifest::{Manifest, ManifestError};

/// A distribution coordinate that is meaningful across machines.
///
/// In particular, this type has no artifact list. Artifact locators,
/// checksums, sizes, and selected source/binary forms belong to local state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedDistributionRef {
    pub registry: RegistryId,
    pub channel: DistributionChannel,
    pub snapshot: Option<SnapshotId>,
}

impl LockedDistributionRef {
    fn from_distribution(distribution: &Distribution) -> Self {
        Self {
            registry: distribution.registry.clone(),
            channel: distribution.channel.clone(),
            snapshot: distribution.snapshot.clone(),
        }
    }
}

/// A dependency edge retained in the shared logical result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedDependencyEdge {
    pub kind: DependencyKind,
    pub name: PackageName,
    pub source: DependencySourceConstraint,
    pub constraint: VersionConstraint,
}

impl From<&DependencyRequirement> for LockedDependencyEdge {
    fn from(dependency: &DependencyRequirement) -> Self {
        Self {
            kind: dependency.kind,
            name: dependency.name.clone(),
            source: dependency.source.clone(),
            constraint: dependency.constraint.clone(),
        }
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
    pub distributions: Vec<LockedDistributionRef>,
    pub dependencies: Vec<LockedDependencyEdge>,
    pub metadata_sha256: Option<Sha256Digest>,
}

impl LockedPackage {
    fn from_release(release: &PackageRelease) -> Self {
        let canonical = canonical_version(release.version());
        let published = match release.identity().provenance() {
            Provenance::RegistryRelease { version, .. }
            | Provenance::BioconductorRelease { version, .. } => version.as_str(),
            _ => release.version().as_str(),
        };
        let published_version_spelling = (published != canonical).then(|| published.into());
        let mut distributions = release
            .distributions()
            .iter()
            .map(LockedDistributionRef::from_distribution)
            .collect::<Vec<_>>();
        distributions.sort_by(distribution_sort_cmp);
        distributions.dedup();
        let mut dependencies = release
            .dependencies()
            .iter()
            .map(LockedDependencyEdge::from)
            .collect::<Vec<_>>();
        for dependency in &mut dependencies {
            dependency
                .constraint
                .clauses
                .sort_by(compare_version_clauses);
        }
        dependencies.sort_by(dependency_sort_cmp);
        dependencies.dedup();
        Self {
            identity: release.identity().clone(),
            version: release.version().clone(),
            published_version_spelling,
            distributions,
            dependencies,
            metadata_sha256: release.metadata_digest().cloned(),
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
        for (index, dependency) in self.dependencies.iter().enumerate() {
            if let DependencySourceConstraint::Exact(identity) = &dependency.source
                && identity.name() != &dependency.name
            {
                return Err(LockError::InvalidDependency {
                    package: identity_key(&self.identity),
                    index,
                });
            }
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

/// The one resolution container currently supported by the command boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedResolution {
    pub target: ResolutionTarget,
    pub environment: EnvironmentId,
    pub packages: Vec<LockedPackage>,
}

/// Shared lock state. v1 accepts exactly one element in `resolutions`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lockfile {
    pub resolutions: Vec<LockedResolution>,
}

impl Lockfile {
    /// Project one successful logical resolution into a deterministic lock.
    pub fn from_resolution(
        resolution: &Resolution,
        environment: EnvironmentId,
    ) -> Result<Self, LockError> {
        let mut packages = resolution
            .packages()
            .iter()
            .map(|selected| LockedPackage::from_release(selected.release()))
            .collect::<Vec<_>>();
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
        Self::new(vec![LockedResolution {
            target: resolution.target().clone(),
            environment,
            packages: unique,
        }])
    }

    /// Validate a lock container at the reader/command boundary.
    pub fn new(resolutions: Vec<LockedResolution>) -> Result<Self, LockError> {
        validate_resolution_count(resolutions.len())?;
        let mut lock = Self { resolutions };
        lock.normalize_contents()?;
        Ok(lock)
    }

    pub fn single_resolution(&self) -> Result<&LockedResolution, LockError> {
        self.validate()?;
        self.resolutions
            .first()
            .ok_or(LockError::UnsupportedResolutionCount { found: 0 })
    }

    /// Produce the identity map consumed by the resolver. Lock policy is
    /// intentionally selected by orchestration, not by the lock reader.
    pub fn locked_identities(&self) -> Result<LockedIdentities, LockError> {
        let resolution = self.single_resolution()?;
        let mut identities = LockedIdentities::new();
        for package in &resolution.packages {
            for key in identity_solver_keys(&package.identity) {
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
        let resolution = self
            .resolutions
            .first()
            .ok_or(LockError::UnsupportedResolutionCount { found: 0 })?;
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
        Ok(ResolutionRequest::new(
            request.requirements,
            request.target,
            request.r_requirement,
            self.locked_identities()?,
        ))
    }

    pub fn validate(&self) -> Result<(), LockError> {
        validate_resolution_count(self.resolutions.len())?;
        self.validate_contents()
    }

    fn normalize_contents(&mut self) -> Result<(), LockError> {
        for resolution in &mut self.resolutions {
            for package in &mut resolution.packages {
                package.validate()?;
                package.distributions.sort_by(distribution_sort_cmp);
                package.distributions.dedup();
                for dependency in &mut package.dependencies {
                    dependency
                        .constraint
                        .clauses
                        .sort_by(compare_version_clauses);
                }
                package.dependencies.sort_by(dependency_sort_cmp);
                package.dependencies.dedup();
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
        }
        Ok(())
    }

    fn validate_contents(&self) -> Result<(), LockError> {
        for resolution in &self.resolutions {
            let mut packages = resolution.packages.clone();
            packages.sort_by(|left, right| cmp_identity(&left.identity, &right.identity));
            for package in &packages {
                package.validate()?;
            }
            for pair in packages.windows(2) {
                if pair[0].identity == pair[1].identity && pair[0] != pair[1] {
                    return Err(LockError::ConflictingMetadata {
                        identity: identity_key(&pair[0].identity),
                    });
                }
            }
            ensure_installed_names(&packages)?;
        }
        Ok(())
    }
}

fn validate_resolution_count(found: usize) -> Result<(), LockError> {
    if found == 1 {
        Ok(())
    } else {
        Err(LockError::UnsupportedResolutionCount { found })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockError {
    UnsupportedResolutionCount {
        found: usize,
    },
    ConflictingMetadata {
        identity: String,
    },
    InvalidPublishedVersionSpelling {
        identity: String,
    },
    RBasePackage {
        identity: String,
    },
    InvalidDependency {
        package: String,
        index: usize,
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
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedResolutionCount { found } => {
                write!(f, "v1 lock requires exactly one resolution, found {found}")
            }
            Self::ConflictingMetadata { identity } => {
                write!(f, "conflicting metadata for locked identity {identity}")
            }
            Self::InvalidPublishedVersionSpelling { identity } => {
                write!(f, "invalid published version spelling for {identity}")
            }
            Self::RBasePackage { identity } => {
                write!(f, "R base package is not lockable: {identity}")
            }
            Self::InvalidDependency { package, index } => {
                write!(f, "invalid dependency {index} in locked package {package}")
            }
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
        }
    }
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

fn identity_solver_keys(identity: &ReleaseIdentity) -> Vec<SolverKey> {
    let mut keys = vec![SolverKey::InstalledName(identity.name().clone())];
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

fn distribution_sort_cmp(left: &LockedDistributionRef, right: &LockedDistributionRef) -> Ordering {
    left.registry
        .cmp(&right.registry)
        .then_with(|| left.channel.cmp(&right.channel))
        .then_with(|| cmp_optional_snapshot(&left.snapshot, &right.snapshot))
}

fn dependency_sort_cmp(left: &LockedDependencyEdge, right: &LockedDependencyEdge) -> Ordering {
    dependency_kind_rank(left.kind)
        .cmp(&dependency_kind_rank(right.kind))
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| cmp_source(&left.source, &right.source))
        .then_with(|| cmp_constraint(&left.constraint, &right.constraint))
}

fn compare_version_clauses(left: &VersionClause, right: &VersionClause) -> Ordering {
    relation_rank(left.op)
        .cmp(&relation_rank(right.op))
        .then_with(|| left.version.cmp(&right.version))
}

fn cmp_optional_snapshot(left: &Option<SnapshotId>, right: &Option<SnapshotId>) -> Ordering {
    left.as_ref()
        .map(SnapshotId::as_str)
        .cmp(&right.as_ref().map(SnapshotId::as_str))
}

fn cmp_optional_subdirectory(
    left: &Option<rsolve_core::RepositorySubdir>,
    right: &Option<rsolve_core::RepositorySubdir>,
) -> Ordering {
    left.as_ref()
        .map(rsolve_core::RepositorySubdir::as_str)
        .cmp(&right.as_ref().map(rsolve_core::RepositorySubdir::as_str))
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

fn relation_rank(op: rsolve_core::RelationOp) -> u8 {
    match op {
        rsolve_core::RelationOp::Lt => 0,
        rsolve_core::RelationOp::Le => 1,
        rsolve_core::RelationOp::Eq => 2,
        rsolve_core::RelationOp::Ne => 3,
        rsolve_core::RelationOp::Ge => 4,
        rsolve_core::RelationOp::Gt => 5,
    }
}

fn cmp_constraint(left: &VersionConstraint, right: &VersionConstraint) -> Ordering {
    left.clauses
        .iter()
        .zip(&right.clauses)
        .map(|(left, right)| {
            relation_rank(left.op)
                .cmp(&relation_rank(right.op))
                .then_with(|| left.version.cmp(&right.version))
        })
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or_else(|| left.clauses.len().cmp(&right.clauses.len()))
}

fn cmp_source(left: &DependencySourceConstraint, right: &DependencySourceConstraint) -> Ordering {
    source_rank(left)
        .cmp(&source_rank(right))
        .then_with(|| match (left, right) {
            (DependencySourceConstraint::Any, DependencySourceConstraint::Any) => Ordering::Equal,
            (
                DependencySourceConstraint::Registry { namespace: left },
                DependencySourceConstraint::Registry { namespace: right },
            ) => left.cmp(right),
            (
                DependencySourceConstraint::Bioconductor {
                    namespace: left_namespace,
                    release: left_release,
                },
                DependencySourceConstraint::Bioconductor {
                    namespace: right_namespace,
                    release: right_release,
                },
            ) => left_namespace
                .cmp(right_namespace)
                .then_with(|| left_release.cmp(right_release)),
            (
                DependencySourceConstraint::Git { repository: left },
                DependencySourceConstraint::Git { repository: right },
            ) => left.cmp(right),
            (DependencySourceConstraint::Exact(left), DependencySourceConstraint::Exact(right)) => {
                cmp_identity(left, right)
            }
            _ => Ordering::Equal,
        })
}

fn source_rank(source: &DependencySourceConstraint) -> u8 {
    match source {
        DependencySourceConstraint::Any => 0,
        DependencySourceConstraint::Registry { .. } => 1,
        DependencySourceConstraint::Bioconductor { .. } => 2,
        DependencySourceConstraint::Git { .. } => 3,
        DependencySourceConstraint::Exact(_) => 4,
    }
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
fn identity_key(identity: &ReleaseIdentity) -> String {
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
