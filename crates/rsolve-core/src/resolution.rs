use std::error::Error;
use std::fmt;

use crate::{
    PackageName, PackageRelease, PreparedCandidate, RPackageVersion, ResolutionTarget,
    ResolvedDependencyEdge, SolverKey,
};

/// The stable categories a candidate source may report to the resolver.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CandidateLoadErrorCategory {
    NotFound,
    SnapshotInvalid,
    TransportFailure,
    MetadataInvalid,
    AuthenticationFailed,
    Cancelled,
}

/// A typed, transport-neutral candidate loading failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateLoadError {
    category: CandidateLoadErrorCategory,
    diagnostic: Box<str>,
}

impl CandidateLoadError {
    pub fn new(category: CandidateLoadErrorCategory, diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            category,
            diagnostic: diagnostic.into(),
        }
    }

    pub fn category(&self) -> CandidateLoadErrorCategory {
        self.category
    }

    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

impl fmt::Display for CandidateLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.category, self.diagnostic)
    }
}

impl Error for CandidateLoadError {}

/// A release coordinate that was observed but quarantined before it could be
/// projected into an installable candidate.
///
/// Quarantined coordinates are intentionally provider-neutral.  Providers may
/// retain richer raw evidence in their snapshots, while the resolver only
/// needs to know which versions must not be treated as an ordinary
/// no-solution result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedCandidate {
    version: RPackageVersion,
    diagnostic: Box<str>,
}

impl QuarantinedCandidate {
    pub fn new(version: RPackageVersion, diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            version,
            diagnostic: diagnostic.into(),
        }
    }

    pub fn version(&self) -> &RPackageVersion {
        &self.version
    }

    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

/// The provider-neutral result of loading one solver subject's candidates.
#[derive(Clone, Debug)]
pub struct CandidateLoadResult {
    candidates: Vec<PreparedCandidate>,
    quarantined: Vec<QuarantinedCandidate>,
}

impl CandidateLoadResult {
    pub fn new(candidates: Vec<PreparedCandidate>, quarantined: Vec<QuarantinedCandidate>) -> Self {
        Self {
            candidates,
            quarantined,
        }
    }

    pub fn candidates(&self) -> &[PreparedCandidate] {
        &self.candidates
    }

    pub fn quarantined(&self) -> &[QuarantinedCandidate] {
        &self.quarantined
    }

    pub fn into_parts(self) -> (Vec<PreparedCandidate>, Vec<QuarantinedCandidate>) {
        (self.candidates, self.quarantined)
    }
}

/// The resolver's candidate-loading port.
///
/// Implementations own provider conversion and must return immutable,
/// fully-prepared candidate views.  Repository occurrences, currentness,
/// publication facts, distributions, and logical release metadata are final
/// before the solver sees a candidate; the solver may validate identity
/// consistency but must not enrich or mutate these facts while solving.
pub trait CandidateLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PreparedCandidate>, CandidateLoadError>;

    /// Loads validated candidates together with coordinates that were
    /// deliberately quarantined by the provider.  Existing loaders that have
    /// no quarantine information get the ordinary candidate-only projection.
    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        self.releases(package)
            .map(|candidates| CandidateLoadResult::new(candidates, Vec::new()))
    }
}

/// One selected installable logical release.
#[derive(Clone, Debug)]
pub struct ResolvedPackage {
    subject: SolverKey,
    release: PackageRelease,
    effective_dependencies: Vec<ResolvedDependencyEdge>,
    visible_repository_ids: Vec<crate::RepositoryId>,
}

impl ResolvedPackage {
    pub fn subject(&self) -> &SolverKey {
        &self.subject
    }

    pub fn release(&self) -> &PackageRelease {
        &self.release
    }

    pub fn identity(&self) -> &crate::ReleaseIdentity {
        self.release.identity()
    }

    pub fn version(&self) -> &crate::RPackageVersion {
        self.release.version()
    }

    pub fn effective_dependencies(&self) -> &[ResolvedDependencyEdge] {
        &self.effective_dependencies
    }

    /// Repository identities that made the selected release visible in the
    /// selected subject. Artifact distributions are intentionally separate
    /// evidence and are exposed through `distributions()`.
    pub fn visible_repository_ids(&self) -> &[crate::RepositoryId] {
        &self.visible_repository_ids
    }

    pub fn distributions(&self) -> &[crate::Distribution] {
        self.release.distributions()
    }

    pub fn metadata_digest(&self) -> &crate::Sha256Digest {
        self.release.metadata_digest()
    }

    pub fn publication(&self) -> Option<&crate::ReleasePublication> {
        self.release.publication()
    }

    pub fn name(&self) -> &PackageName {
        self.release.identity().name()
    }

    #[doc(hidden)]
    pub fn new(
        subject: SolverKey,
        release: PackageRelease,
        effective_dependencies: Vec<ResolvedDependencyEdge>,
        visible_repository_ids: Vec<crate::RepositoryId>,
    ) -> Self {
        Self {
            subject,
            release,
            effective_dependencies,
            visible_repository_ids,
        }
    }
}

/// A successful logical solve.  R is represented by `target` and is not an
/// installable package entry.
#[derive(Clone, Debug)]
pub struct Resolution {
    target: ResolutionTarget,
    packages: Vec<ResolvedPackage>,
}

impl Resolution {
    #[doc(hidden)]
    pub fn new(target: ResolutionTarget, mut packages: Vec<ResolvedPackage>) -> Self {
        // R and the R base packages are runtime-provided subjects, not
        // installable entries in a logical resolution.  Keep this invariant at
        // the successful-result boundary as well as in the resolver adapter.
        packages.retain(|package| !package.release.is_r_base_package());
        packages.sort_by(|left, right| left.name().cmp(right.name()));
        Self { target, packages }
    }

    pub fn target(&self) -> &ResolutionTarget {
        &self.target
    }

    pub fn packages(&self) -> &[ResolvedPackage] {
        &self.packages
    }

    pub fn selected(&self, name: &PackageName) -> Option<&PackageRelease> {
        self.packages
            .iter()
            .find(|package| package.name() == name)
            .map(ResolvedPackage::release)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeclaredDependency, DependencyKind, DependencySourceConstraint, EffectiveDependencyKind,
        PackageRequirement, Provenance, ReleaseIdentity, ReleaseMetadata, ReleaseObservation,
        VersionConstraint,
    };

    #[test]
    fn default_projection_keeps_only_selected_hard_dependency_kinds() {
        let parent = PackageName::new("parent").unwrap();
        let child = PackageName::new("child").unwrap();
        let version = RPackageVersion::parse("1.0.0").unwrap();
        let requirement = PackageRequirement::new(
            child,
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )
        .unwrap();
        let release = PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                parent.clone(),
                Provenance::RegistryRelease {
                    namespace: crate::PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: parent.clone(),
            observed_version: version.clone(),
            metadata: ReleaseMetadata::default(),
            publication: None,
            declared_dependencies: vec![
                DeclaredDependency::from_package(DependencyKind::Depends, requirement.clone()),
                DeclaredDependency::from_package(DependencyKind::Suggests, requirement),
            ],
            distributions: Vec::new(),
        })
        .unwrap();
        let resolved = ResolvedPackage::new(
            SolverKey::InstalledName(parent),
            release,
            vec![ResolvedDependencyEdge {
                kind: EffectiveDependencyKind::Depends,
                package: PackageRequirement::new(
                    PackageName::new("child").unwrap(),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                )
                .unwrap(),
            }],
            Vec::new(),
        );
        assert_eq!(resolved.effective_dependencies().len(), 1);
        assert_eq!(
            resolved.effective_dependencies()[0].kind,
            EffectiveDependencyKind::Depends
        );
    }
}
