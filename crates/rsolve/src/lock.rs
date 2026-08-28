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
    EffectiveDependencyKind, LockedIdentities, PackageName, Provenance, PublicationCutoff,
    PublicationDate, RPackageVersion, ReleaseIdentity, Resolution, ResolutionRequest,
    ResolutionTarget, ResolvedPackage, Sha256Digest, SolverKey,
};

#[cfg(test)]
use rsolve_core::{DependencyKind, PackageRelease};

pub use rsolve_core::{EnvironmentId, EnvironmentIdError};

use crate::manifest::{Manifest, ManifestError};

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
    pub dependencies: Vec<PackageName>,
    pub metadata_sha256: Sha256Digest,
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
                        dependencies.push(dependency.package.name().clone());
                    }
                }
                EffectiveDependencyKind::PromotedSuggests => {
                    return Err(LockError::UnsupportedDependencyKind {
                        package: selected.name().to_string(),
                        dependency: dependency.package.name().to_string(),
                    });
                }
            }
        }
        dependencies.sort();
        dependencies.dedup();
        Ok(Self {
            identity: selected.release().identity().clone(),
            version: selected.release().version().clone(),
            published_version_spelling,
            dependencies,
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
            .map(|dependency| dependency.package.name().clone())
            .collect::<Vec<_>>();
        dependencies.sort();
        dependencies.dedup();
        Self {
            identity: release.identity().clone(),
            version: release.version().clone(),
            published_version_spelling,
            dependencies,
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

/// The one resolution container currently supported by the command boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedResolution {
    pub target: ResolutionTarget,
    pub environment: EnvironmentId,
    pub publication_cutoff: Option<PublicationDate>,
    pub packages: Vec<LockedPackage>,
}

/// Shared lock state. The current command boundary accepts exactly one
/// logical resolution; the TOML projection flattens that resolution at the
/// wire root.
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
        Self::from_resolution_with_publication_cutoff(resolution, environment, None)
    }

    pub fn from_resolution_with_publication_cutoff(
        resolution: &Resolution,
        environment: EnvironmentId,
        publication_cutoff: Option<PublicationDate>,
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
                        .retain(|dependency| selected_names.contains(dependency));
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
        Self::new(vec![LockedResolution {
            target: resolution.target().clone(),
            environment,
            publication_cutoff,
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
        let resolution = self.single_resolution()?;
        validate_canonical_resolution(resolution)?;
        let request = self.resolution_request(manifest.clone(), environment)?;
        if !manifest
            .r_requirement
            .satisfies(&resolution.target.r_version)
        {
            return Err(LockError::RRequirementMismatch);
        }

        let by_name = resolution
            .packages
            .iter()
            .map(|package| (package.identity.name().clone(), package))
            .collect::<BTreeMap<_, _>>();
        let mut reachable = BTreeSet::new();
        for requirement in &request.roots {
            let name = &requirement.package.name();
            if is_r_base_name(name) {
                if !requirement
                    .package
                    .constraint()
                    .satisfies(&resolution.target.r_version)
                {
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
            if !requirement.package.constraint().satisfies(&package.version) {
                return Err(LockError::DirectRootVersionMismatch {
                    name: name.to_string(),
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
        validate_resolution_count(self.resolutions.len())?;
        self.validate_contents()
    }

    fn normalize_contents(&mut self) -> Result<(), LockError> {
        for resolution in &mut self.resolutions {
            for package in &mut resolution.packages {
                package.validate()?;
                package.dependencies.sort();
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
            ensure_dependencies_exist(&resolution.packages)?;
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
            ensure_dependencies_exist(&packages)?;
        }
        Ok(())
    }
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
    UnsupportedDependencyKind {
        package: String,
        dependency: String,
    },
    ExactIdentitySetMismatch {
        missing: Vec<String>,
        extra: Vec<String>,
    },
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
                f.write_str("manifest R requirement is not satisfied by the lock target")
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
            Self::UnsupportedDependencyKind {
                package,
                dependency,
            } => write!(
                f,
                "locked package {package} has unsupported effective dependency {dependency}"
            ),
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
                .get(dependency)
                .ok_or_else(|| LockError::DanglingDependency {
                    package: package.identity.name().to_string(),
                    dependency: dependency.to_string(),
                })?;
        mark_reachable(dependency_package, by_name, reachable)?;
    }
    Ok(())
}

fn validate_canonical_resolution(resolution: &LockedResolution) -> Result<(), LockError> {
    let mut packages = resolution.packages.clone();
    packages.sort_by(|left, right| cmp_identity(&left.identity, &right.identity));
    if packages != resolution.packages {
        return Err(LockError::NonCanonical);
    }
    if resolution.packages.iter().any(|package| {
        package
            .dependencies
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
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
            if !selected.contains(dependency) {
                return Err(LockError::DanglingDependency {
                    package: package.identity.name().to_string(),
                    dependency: dependency.to_string(),
                });
            }
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
