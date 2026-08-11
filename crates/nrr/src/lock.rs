//! Shared logical lock domain and projections.
//!
//! This module intentionally contains no artifact or filesystem state. TOML
//! encoding is deferred until the canonical identity grammar is fixed.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

use nrr_core::{
    DependencyKind, DependencyRequirement, DependencySourceConstraint, Distribution,
    DistributionChannel, LockedIdentities, PackageName, PackageRelease, Provenance,
    RPackageVersion, RegistryId, ReleaseIdentity, Resolution, ResolutionRequest, ResolutionTarget,
    Sha256Digest, SnapshotId, SolverKey, VersionConstraint,
};

pub use nrr_core::{EnvironmentId, EnvironmentIdError};

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
    UnsupportedResolutionCount { found: usize },
    ConflictingMetadata { identity: String },
    InvalidPublishedVersionSpelling { identity: String },
    RBasePackage { identity: String },
    TargetMismatch,
    EnvironmentMismatch { expected: String, found: String },
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
            Self::TargetMismatch => f.write_str("lock target does not match manifest target"),
            Self::EnvironmentMismatch { expected, found } => write!(
                f,
                "lock environment {expected} does not match requested environment {found}"
            ),
            Self::Manifest(error) => write!(f, "manifest composition failed: {error}"),
        }
    }
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
        Provenance::RegistryRelease { namespace, .. } => keys.push(SolverKey::Registry {
            namespace: namespace.clone(),
            name: identity.name().clone(),
        }),
        Provenance::BioconductorRelease {
            namespace, release, ..
        } => keys.push(SolverKey::Bioconductor {
            namespace: namespace.clone(),
            release: release.clone(),
            name: identity.name().clone(),
        }),
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

fn cmp_optional_snapshot(left: &Option<SnapshotId>, right: &Option<SnapshotId>) -> Ordering {
    left.as_ref()
        .map(SnapshotId::as_str)
        .cmp(&right.as_ref().map(SnapshotId::as_str))
}

fn cmp_optional_subdirectory(
    left: &Option<nrr_core::RepositorySubdir>,
    right: &Option<nrr_core::RepositorySubdir>,
) -> Ordering {
    left.as_ref()
        .map(nrr_core::RepositorySubdir::as_str)
        .cmp(&right.as_ref().map(nrr_core::RepositorySubdir::as_str))
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

fn relation_rank(op: nrr_core::RelationOp) -> u8 {
    match op {
        nrr_core::RelationOp::Lt => 0,
        nrr_core::RelationOp::Le => 1,
        nrr_core::RelationOp::Eq => 2,
        nrr_core::RelationOp::Ne => 3,
        nrr_core::RelationOp::Ge => 4,
        nrr_core::RelationOp::Gt => 5,
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
mod tests {
    use super::*;
    use nrr_core::{
        Artifact, ArtifactLocator, DistributionMetadata, PackageNamespace, RelationOp,
        ReleaseMetadata, ReleaseObservation, SourceArtifact, UpstreamChecksum,
    };
    use std::collections::BTreeMap;

    fn version(value: &str) -> RPackageVersion {
        RPackageVersion::parse(value).unwrap()
    }

    fn package(value: &str) -> PackageName {
        PackageName::new(value).unwrap()
    }

    fn release(name: &str, spelling: &str) -> PackageRelease {
        let name = package(name);
        let version = version(spelling);
        PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                name.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: name,
            observed_version: version,
            metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
            dependencies: Vec::new(),
            distributions: Vec::new(),
        })
        .unwrap()
    }

    fn target() -> ResolutionTarget {
        ResolutionTarget::new(version("4.4.0"), nrr_core::Target::new("linux", "x86_64"))
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::new("default").unwrap()
    }

    #[test]
    fn v1_requires_exactly_one_resolution() {
        assert_eq!(
            Lockfile::new(Vec::new()),
            Err(LockError::UnsupportedResolutionCount { found: 0 })
        );
        let empty = LockedResolution {
            target: target(),
            environment: environment(),
            packages: Vec::new(),
        };
        assert_eq!(
            Lockfile::new(vec![empty.clone(), empty]),
            Err(LockError::UnsupportedResolutionCount { found: 2 })
        );
    }

    #[test]
    fn reader_rejects_registry_record_version_mismatch() {
        let identity = ReleaseIdentity::new(
            package("mismatch"),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.0.0"),
            },
        );
        let package = LockedPackage {
            identity,
            version: version("2.0.0"),
            published_version_spelling: None,
            distributions: Vec::new(),
            dependencies: Vec::new(),
            metadata_sha256: None,
        };
        assert!(matches!(
            Lockfile::new(vec![LockedResolution {
                target: target(),
                environment: environment(),
                packages: vec![package],
            }]),
            Err(LockError::ConflictingMetadata { identity }) if identity.contains("mismatch")
        ));
    }

    #[test]
    fn normalization_is_independent_of_package_edge_and_distribution_input_order() {
        let alpha = package("alpha");
        let beta = package("beta");
        let dependency = |name: &PackageName, kind| LockedDependencyEdge {
            kind,
            name: name.clone(),
            source: DependencySourceConstraint::Any,
            constraint: VersionConstraint::unconstrained(),
        };
        let distribution = |channel: &str| LockedDistributionRef {
            registry: RegistryId::new("cran").unwrap(),
            channel: DistributionChannel::new(channel).unwrap(),
            snapshot: None,
        };
        let make = |name: PackageName| LockedPackage {
            identity: ReleaseIdentity::new(
                name,
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version("1.0.0"),
                },
            ),
            version: version("1.0.0"),
            published_version_spelling: None,
            distributions: vec![distribution("source"), distribution("archive")],
            dependencies: vec![
                dependency(&beta, DependencyKind::Suggests),
                dependency(&alpha, DependencyKind::Depends),
            ],
            metadata_sha256: None,
        };
        let mut reversed = make(alpha.clone());
        reversed.distributions.reverse();
        reversed.dependencies.reverse();
        let ordered = make(alpha.clone());
        let first = Lockfile::new(vec![LockedResolution {
            target: target(),
            environment: environment(),
            packages: vec![ordered, make(beta.clone())],
        }])
        .unwrap();
        let second = Lockfile::new(vec![LockedResolution {
            target: target(),
            environment: environment(),
            packages: vec![make(beta.clone()), reversed],
        }])
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn projection_is_sorted_and_keeps_logical_fields_only() {
        let mut first = release("zeta", "1.6-5");
        let second = release("alpha", "2.0.0");
        let dependency = DependencyRequirement::new(
            DependencyKind::Depends,
            package("alpha"),
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(RelationOp::Ge, version("1.0")),
        );
        first = PackageRelease::try_from(ReleaseObservation {
            identity: first.identity().clone(),
            observed_package: first.identity().name().clone(),
            observed_version: first.version().clone(),
            metadata: first.metadata().clone(),
            dependencies: vec![dependency],
            distributions: vec![Distribution {
                registry: RegistryId::new("cran").unwrap(),
                channel: DistributionChannel::new("source").unwrap(),
                snapshot: Some(SnapshotId::new("2026-01").unwrap()),
                artifacts: vec![Artifact::Source(SourceArtifact {
                    locator: ArtifactLocator::new("/machine/private.tar.gz").unwrap(),
                    upstream_checksums: vec![UpstreamChecksum::Md5("deadbeef".into())],
                    size: Some(123),
                })],
                observed_metadata: DistributionMetadata::default(),
            }],
        })
        .unwrap()
        .with_metadata_digest(Sha256Digest::new("a".repeat(64)).unwrap());
        let resolution = Resolution::new(
            target(),
            vec![
                nrr_core::ResolvedPackage::new(
                    SolverKey::InstalledName(second.identity().name().clone()),
                    second,
                ),
                nrr_core::ResolvedPackage::new(
                    SolverKey::InstalledName(first.identity().name().clone()),
                    first,
                ),
            ],
        );
        let lock = Lockfile::from_resolution(&resolution, environment()).unwrap();
        let packages = &lock.single_resolution().unwrap().packages;
        assert_eq!(packages[0].identity.name().as_str(), "alpha");
        assert_eq!(packages[1].identity.name().as_str(), "zeta");
        let zeta = &packages[1];
        assert_eq!(zeta.published_version_spelling.as_deref(), Some("1.6-5"));
        assert_eq!(zeta.dependencies.len(), 1);
        assert_eq!(zeta.distributions.len(), 1);
        assert_eq!(
            zeta.metadata_sha256.as_ref().unwrap().as_str(),
            &"a".repeat(64)
        );
        assert_eq!(zeta.distributions[0].registry.as_str(), "cran");
        // These fields exist only on `Distribution`, never on the lock ref.
        assert!(!format!("{:?}", zeta.distributions[0]).contains("machine/private"));
        assert!(!format!("{:?}", zeta.distributions[0]).contains("deadbeef"));
    }

    #[test]
    fn canonical_version_preserves_two_components_for_published_spelling() {
        let two = LockedPackage::from_release(&release("two", "1.0"));
        let three = LockedPackage::from_release(&release("three", "1.0.0"));
        let zero = LockedPackage::from_release(&release("zero", "0.0"));
        assert_eq!(two.published_version_spelling, None);
        assert_eq!(three.published_version_spelling.as_deref(), Some("1.0.0"));
        assert_eq!(zero.published_version_spelling, None);
    }

    #[test]
    fn downstream_projection_revalidates_mutated_public_lock_state() {
        let name = package("mutable");
        let resolution = Resolution::new(
            target(),
            vec![nrr_core::ResolvedPackage::new(
                SolverKey::InstalledName(name.clone()),
                release("mutable", "1.0.0"),
            )],
        );
        let mut lock = Lockfile::from_resolution(&resolution, environment()).unwrap();
        lock.resolutions[0].packages[0].version = version("2.0.0");
        assert!(matches!(
            lock.locked_identities(),
            Err(LockError::ConflictingMetadata { identity }) if identity.contains("mutable")
        ));
        assert!(matches!(
            lock.resolution_request(
                Manifest::new(
                    VersionConstraint::unconstrained(),
                    crate::manifest::ManifestTarget::new(version("4.4.0"), "linux", "x86_64",)
                        .unwrap(),
                    vec![crate::manifest::ManifestDependency::new(
                        name,
                        VersionConstraint::unconstrained(),
                    )],
                )
                .unwrap(),
                &environment(),
            ),
            Err(LockError::ConflictingMetadata { .. })
        ));
    }

    #[test]
    fn conflicting_repeated_identity_is_rejected_before_lock_state() {
        let identity_release = release("same", "1.0.0");
        let identity = identity_release.identity().clone();
        let other = identity_release
            .clone()
            .with_metadata_digest(Sha256Digest::new("b".repeat(64)).unwrap());
        let resolution = Resolution::new(
            target(),
            vec![
                nrr_core::ResolvedPackage::new(
                    SolverKey::InstalledName(package("same")),
                    identity_release,
                ),
                nrr_core::ResolvedPackage::new(SolverKey::InstalledName(package("same")), other),
            ],
        );
        assert!(matches!(
            Lockfile::from_resolution(&resolution, environment()),
            Err(LockError::ConflictingMetadata { identity: value }) if value.contains("same")
        ));
        assert_eq!(identity.name().as_str(), "same");
    }
}
