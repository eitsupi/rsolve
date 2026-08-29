//! Reusable logical resolution boundary for rsolve.
//!
//! PubGrub is deliberately confined to [`adapter`].  The public API contains
//! only rsolve domain values and resolver-owned policy/comparison values.

mod adapter;

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoadResult, CandidateLoader,
    DependencyKind, DependencySourceConstraint, NonRepositoryExposure, PackageName, PackageRelease,
    PreparedCandidate, Provenance, PublicationDate, RPackageVersion, ReleaseIdentity,
    ReleaseMetadata, ReleaseObservation, Resolution, ResolutionRequest, SolverKey,
    VersionConstraint,
};

pub use adapter::{
    PublicationPolicyDiagnostic, PublicationRejection, ResolutionDiagnostic, ResolutionFailure,
};

// These are R base packages only. Recommended packages such as Matrix are
// intentionally absent; without runtime inventory, the resolver must not
// infer that a recommended package is environment-provided.
/// The official R base package names projected by [`RBasePackageOverlay`].
pub const R_BASE_PACKAGE_NAMES: [&str; 14] = [
    "base",
    "compiler",
    "datasets",
    "graphics",
    "grDevices",
    "grid",
    "methods",
    "parallel",
    "splines",
    "stats",
    "stats4",
    "tcltk",
    "tools",
    "utils",
];

/// Reports whether a package is supplied by the selected R runtime.
///
/// This is a fixed R-base projection, not runtime discovery or selection. It
/// intentionally excludes recommended packages and any actual runtime
/// inventory.
pub fn is_r_base_package_name(name: &PackageName) -> bool {
    R_BASE_PACKAGE_NAMES
        .iter()
        .any(|candidate| *candidate == name.as_str())
}

/// Shadows candidate loading for the base packages supplied by one selected R
/// runtime.
///
/// The overlay projects the already-selected target R version into exactly one
/// canonical candidate for each of the fourteen official base packages. It is
/// not a runtime discovery or selection API, and it does not model recommended
/// packages or the runtime's actual installed inventory. Installed-name keys
/// for those packages are shadowed; source-qualified keys and all other names
/// delegate to the wrapped loader.
pub struct RBasePackageOverlay<L> {
    loader: L,
    base: BTreeMap<PackageName, PackageRelease>,
    r_version: RPackageVersion,
}

impl<L> RBasePackageOverlay<L> {
    /// Constructs a base-package projection for an already-selected R version.
    ///
    /// The projected releases pass through the same fallible canonical domain
    /// constructors as provider candidates. No unchecked or panic-based
    /// release construction is used.
    pub fn new(loader: L, r_version: RPackageVersion) -> Result<Self, CandidateLoadError> {
        let mut base = BTreeMap::new();
        for name in R_BASE_PACKAGE_NAMES {
            let package = PackageName::new(name).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("invalid R base package name {name}: {error}"),
                )
            })?;
            let release = PackageRelease::try_from(ReleaseObservation {
                identity: ReleaseIdentity::new(
                    package.clone(),
                    Provenance::RBasePackage {
                        r_version: r_version.clone(),
                    },
                ),
                observed_package: package.clone(),
                observed_version: r_version.clone(),
                metadata: ReleaseMetadata::new(BTreeMap::new()).map_err(|error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        format!("invalid R base package metadata: {error}"),
                    )
                })?,
                publication: None,
                declared_dependencies: Vec::new(),
                distributions: Vec::new(),
            })
            .map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("invalid R base package release {name}: {error}"),
                )
            })?;
            base.insert(package, release);
        }
        Ok(Self {
            loader,
            base,
            r_version,
        })
    }

    /// Returns the wrapped loader for consumer-owned refresh policy.
    pub fn inner(&self) -> &L {
        &self.loader
    }

    /// Returns the selected R version projected by this overlay.
    pub fn r_version(&self) -> &RPackageVersion {
        &self.r_version
    }
}

impl<L: CandidateLoader> CandidateLoader for RBasePackageOverlay<L> {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PreparedCandidate>, CandidateLoadError> {
        if let SolverKey::InstalledName(name) = package
            && let Some(release) = self.base.get(name)
        {
            return PreparedCandidate::new(
                release.clone(),
                NonRepositoryExposure::RuntimeInstalled,
                Vec::new(),
            )
            .map(|candidate| vec![candidate])
            .map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("invalid R base candidate: {error}"),
                )
            });
        }
        self.loader.releases(package)
    }

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        if let SolverKey::InstalledName(name) = package
            && let Some(release) = self.base.get(name)
        {
            let candidate = PreparedCandidate::new(
                release.clone(),
                NonRepositoryExposure::RuntimeInstalled,
                Vec::new(),
            )
            .map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("invalid R base candidate: {error}"),
                )
            })?;
            return Ok(CandidateLoadResult::new(vec![candidate], Vec::new()));
        }
        self.loader.load(package)
    }
}

/// Information available to a candidate ordering policy for one solve.
pub struct PreferenceContext<'a> {
    pub locked: Option<&'a ReleaseIdentity>,
}

/// Stable trial ordering.  It affects which compatible candidate PubGrub
/// tries first; it never changes the dependency constraints.
pub trait CandidatePreference {
    fn compare(
        &self,
        package: &SolverKey,
        left: &PreparedCandidate,
        right: &PreparedCandidate,
        context: &PreferenceContext<'_>,
    ) -> Ordering;
}

pub(crate) fn compare_prepared_candidates(
    preference: &dyn CandidatePreference,
    package: &SolverKey,
    left: &PreparedCandidate,
    right: &PreparedCandidate,
    context: &PreferenceContext<'_>,
) -> Ordering {
    preference
        .compare(package, left, right, context)
        .then_with(|| left.release().version().cmp(right.release().version()))
        .then_with(|| identity_sort_key(left.identity()).cmp(&identity_sort_key(right.identity())))
}

/// The default ordering is locked, then applicable current/history status,
/// then version, scoped repository rank, and canonical identity.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultCandidatePreference;

impl CandidatePreference for DefaultCandidatePreference {
    fn compare(
        &self,
        package: &SolverKey,
        left: &PreparedCandidate,
        right: &PreparedCandidate,
        context: &PreferenceContext<'_>,
    ) -> Ordering {
        preference_rank(left, package, context)
            .cmp(&preference_rank(right, package, context))
            .then_with(|| left.release().version().cmp(right.release().version()))
            .then_with(|| {
                right
                    .repository_rank_for(package)
                    .cmp(&left.repository_rank_for(package))
            })
            .then_with(|| {
                identity_sort_key(left.identity()).cmp(&identity_sort_key(right.identity()))
            })
    }
}

fn preference_rank(
    candidate: &PreparedCandidate,
    package: &SolverKey,
    context: &PreferenceContext<'_>,
) -> u8 {
    if context.locked == Some(candidate.identity()) {
        3
    } else if candidate
        .applicable_occurrences(package)
        .iter()
        .any(|occurrence| occurrence.currentness() == rsolve_core::CandidateCurrentness::Current)
    {
        2
    } else {
        1
    }
}

fn identity_sort_key(identity: &ReleaseIdentity) -> String {
    format!("{}:{:?}", identity.name(), identity.provenance())
}

/// The lock decision made by an injected update policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockDecision {
    Unlocked,
    Prefer(ReleaseIdentity),
    Require(ReleaseIdentity),
}

/// Controls whether a previous identity is a soft preference or a hard pin.
pub trait LockUpdatePolicy {
    fn decision(&self, package: &SolverKey, previous: Option<&ReleaseIdentity>) -> LockDecision;
}

/// The normal conservative lock policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreferLocked;

impl LockUpdatePolicy for PreferLocked {
    fn decision(&self, _package: &SolverKey, previous: Option<&ReleaseIdentity>) -> LockDecision {
        previous
            .cloned()
            .map(LockDecision::Prefer)
            .unwrap_or(LockDecision::Unlocked)
    }
}

/// A frozen-lock policy that rejects candidates other than the locked one.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequireLocked;

impl LockUpdatePolicy for RequireLocked {
    fn decision(&self, _package: &SolverKey, previous: Option<&ReleaseIdentity>) -> LockDecision {
        previous
            .cloned()
            .map(LockDecision::Require)
            .unwrap_or(LockDecision::Unlocked)
    }
}

/// A policy for an update that intentionally ignores previous identities.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unlocked;

impl LockUpdatePolicy for Unlocked {
    fn decision(&self, _package: &SolverKey, _previous: Option<&ReleaseIdentity>) -> LockDecision {
        LockDecision::Unlocked
    }
}

/// A candidate plus the reason it differs from the final assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionCandidate {
    Release {
        identity: ReleaseIdentity,
        version: RPackageVersion,
    },
    R(RPackageVersion),
    InstalledName {
        name: PackageName,
        occupied_by: ReleaseIdentity,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionSubject {
    Package(PackageName),
    R,
    InstalledName(PackageName),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssignmentBasis {
    LockedPreference { identity: ReleaseIdentity },
    RepositoryCurrent,
    HighestCompatible,
    OnlyStaticallyCompatible,
    ExactRootRequirement,
    FixedRTarget,
    InstalledNameReservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssignmentDifference {
    RootRequirementMismatch {
        requirement: VersionConstraint,
    },
    ConstraintViolatedByAssignment {
        against: DecisionSubject,
        requirement: VersionConstraint,
        assigned: DecisionCandidate,
    },
    RequiredLockMismatch {
        required: ReleaseIdentity,
    },
    InstalledNameConflict {
        name: PackageName,
        assigned_to: ReleaseIdentity,
    },
    LowerPreference {
        assigned: DecisionCandidate,
    },
    PublicationCooldown {
        cutoff: PublicationDate,
    },
    PublicationUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlternativeComparison {
    pub candidate: DecisionCandidate,
    pub differs_by: AssignmentDifference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAssignment {
    pub subject: DecisionSubject,
    pub assigned: DecisionCandidate,
    pub basis: AssignmentBasis,
    pub alternatives: Vec<AlternativeComparison>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentComparison {
    pub assignments: Vec<SubjectAssignment>,
}

#[derive(Clone, Debug)]
pub struct ComparedResolution {
    pub resolution: Resolution,
    pub comparison: AssignmentComparison,
}

pub struct Resolver<'a> {
    loader: &'a dyn CandidateLoader,
    preference: &'a dyn CandidatePreference,
    lock_policy: &'a dyn LockUpdatePolicy,
}

impl<'a> Resolver<'a> {
    pub fn new(
        loader: &'a dyn CandidateLoader,
        preference: &'a dyn CandidatePreference,
        lock_policy: &'a dyn LockUpdatePolicy,
    ) -> Self {
        Self {
            loader,
            preference,
            lock_policy,
        }
    }

    pub fn resolve(&self, request: ResolutionRequest) -> Result<Resolution, ResolutionFailure> {
        adapter::solve(self.loader, self.preference, self.lock_policy, &request)
    }

    pub fn resolve_with_assignment_comparison(
        &self,
        request: ResolutionRequest,
    ) -> Result<ComparedResolution, ResolutionFailure> {
        let resolution = self.resolve(request.clone())?;
        let comparison = self.reconstruct_comparison(&request, &resolution)?;
        Ok(ComparedResolution {
            resolution,
            comparison,
        })
    }

    fn reconstruct_comparison(
        &self,
        request: &ResolutionRequest,
        resolution: &Resolution,
    ) -> Result<AssignmentComparison, ResolutionFailure> {
        let mut assignments = Vec::new();
        assignments.push(SubjectAssignment {
            subject: DecisionSubject::R,
            assigned: DecisionCandidate::R(resolution.target().r_version.clone()),
            basis: AssignmentBasis::FixedRTarget,
            alternatives: Vec::new(),
        });

        let mut selected = resolution.packages().to_vec();
        selected.sort_by(|left, right| {
            left.name().cmp(right.name()).then_with(|| {
                identity_sort_key(left.release().identity())
                    .cmp(&identity_sort_key(right.release().identity()))
            })
        });

        for package in &selected {
            let subject = package.subject().clone();
            let candidates = self.load_candidates(&subject)?;
            let Some(selected_candidate) = candidates
                .iter()
                .find(|candidate| candidate.identity() == package.release().identity())
            else {
                return Err(ResolutionFailure::CandidateLoad {
                    package: subject,
                    source: Box::new(CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        "selected release is absent from its prepared subject view",
                    )),
                });
            };
            let previous = request.locked.get(&subject);
            let decision = self.lock_policy.decision(&subject, previous);
            let locked = match &decision {
                LockDecision::Prefer(identity) | LockDecision::Require(identity) => Some(identity),
                LockDecision::Unlocked => None,
            };
            let context = PreferenceContext { locked };
            let basis = assignment_basis(
                package,
                &candidates,
                &decision,
                request,
                &subject,
                &resolution.target().r_version,
            );
            let assigned = candidate_for_subject(&subject, package.release());
            let difference_context = DifferenceContext {
                selected: package.release(),
                selected_candidate,
                r_version: resolution.target().r_version.clone(),
                decision: &decision,
                preference: &context,
                subject: &subject,
                selected_packages: &selected,
                request,
            };
            // The loader's iteration order must not reach the public
            // comparison, so each alternative carries the candidate's own
            // version and identity as its sort key.
            let mut keyed: Vec<_> = candidates
                .iter()
                .filter(|candidate| candidate.identity() != package.release().identity())
                .filter_map(|candidate| {
                    difference_for_candidate(self.preference, candidate, &difference_context).map(
                        |differs_by| {
                            (
                                (
                                    candidate.release().version().clone(),
                                    identity_sort_key(candidate.identity()),
                                ),
                                AlternativeComparison {
                                    candidate: candidate_for_subject(&subject, candidate.release()),
                                    differs_by,
                                },
                            )
                        },
                    )
                })
                .collect();
            keyed.sort_by(|(left, _), (right, _)| left.cmp(right));
            let alternatives = keyed
                .into_iter()
                .map(|(_, alternative)| alternative)
                .collect();
            assignments.push(SubjectAssignment {
                subject: subject_to_decision_subject(&subject),
                assigned,
                basis,
                alternatives,
            });
        }

        Ok(AssignmentComparison { assignments })
    }

    fn load_candidates(
        &self,
        subject: &SolverKey,
    ) -> Result<Vec<PreparedCandidate>, ResolutionFailure> {
        self.loader
            .releases(subject)
            .map_err(|source| ResolutionFailure::CandidateLoad {
                package: subject.clone(),
                source: Box::new(source),
            })
    }
}

fn assignment_basis(
    selected: &rsolve_core::ResolvedPackage,
    candidates: &[PreparedCandidate],
    decision: &LockDecision,
    request: &ResolutionRequest,
    subject: &SolverKey,
    r_version: &RPackageVersion,
) -> AssignmentBasis {
    if matches!(subject, SolverKey::InstalledName(_)) {
        return AssignmentBasis::InstalledNameReservation;
    }
    if let LockDecision::Require(identity) = decision
        && identity == selected.release().identity()
    {
        return AssignmentBasis::LockedPreference {
            identity: identity.clone(),
        };
    }
    if let LockDecision::Prefer(identity) = decision
        && identity == selected.release().identity()
    {
        return AssignmentBasis::LockedPreference {
            identity: identity.clone(),
        };
    }
    if candidates.iter().any(|candidate| {
        candidate.identity() == selected.release().identity()
            && candidate
                .applicable_occurrences(subject)
                .iter()
                .any(|occurrence| {
                    occurrence.currentness() == rsolve_core::CandidateCurrentness::Current
                })
    }) {
        return AssignmentBasis::RepositoryCurrent;
    }
    let statically_compatible = candidates
        .iter()
        .filter(|candidate| {
            candidate
                .release()
                .declared_dependencies()
                .iter()
                .all(|dependency| {
                    dependency.package.name().as_str() != "R"
                        || dependency.package.constraint().satisfies(r_version)
                })
        })
        .count();
    if statically_compatible == 1 {
        return AssignmentBasis::OnlyStaticallyCompatible;
    }
    if request.roots.iter().any(|requirement| {
        dependency_key(requirement.package.name(), requirement.package.source())
            .as_ref()
            .is_some_and(|key| key == subject)
            && requirement
                .package
                .constraint()
                .clauses
                .iter()
                .any(|clause| {
                    clause.op == rsolve_core::RelationOp::Eq
                        && clause.version == *selected.release().version()
                })
    }) {
        return AssignmentBasis::ExactRootRequirement;
    }
    let _ = subject;
    AssignmentBasis::HighestCompatible
}

struct DifferenceContext<'a> {
    selected: &'a PackageRelease,
    selected_candidate: &'a PreparedCandidate,
    r_version: RPackageVersion,
    decision: &'a LockDecision,
    preference: &'a PreferenceContext<'a>,
    subject: &'a SolverKey,
    selected_packages: &'a [rsolve_core::ResolvedPackage],
    request: &'a ResolutionRequest,
}

fn difference_for_candidate(
    preference: &dyn CandidatePreference,
    candidate: &PreparedCandidate,
    difference: &DifferenceContext<'_>,
) -> Option<AssignmentDifference> {
    if let LockDecision::Require(required) = difference.decision
        && candidate.identity() != required
    {
        return Some(AssignmentDifference::RequiredLockMismatch {
            required: required.clone(),
        });
    }
    let locked = match difference.decision {
        LockDecision::Prefer(identity) | LockDecision::Require(identity) => {
            candidate.identity() == identity
        }
        LockDecision::Unlocked => false,
    };
    if let Some(cutoff) = difference.request.publication_cutoff
        && !candidate.release().is_r_base_package()
        && !locked
    {
        match candidate.release().publication() {
            Some(publication) if publication.date() > cutoff.date() => {
                return Some(AssignmentDifference::PublicationCooldown {
                    cutoff: cutoff.date(),
                });
            }
            None => return Some(AssignmentDifference::PublicationUnknown),
            Some(_) => {}
        }
    }
    if let Some(other) = difference.selected_packages.iter().find(|other| {
        other.subject() != difference.subject
            && other.name() == candidate.identity().name()
            && other.release().identity() != candidate.identity()
    }) {
        return Some(AssignmentDifference::InstalledNameConflict {
            name: candidate.identity().name().clone(),
            assigned_to: other.release().identity().clone(),
        });
    }
    if let Some(requirement) = difference.request.roots.iter().find(|requirement| {
        dependency_key(requirement.package.name(), requirement.package.source())
            .as_ref()
            .is_some_and(|key| key == difference.subject)
            && !requirement
                .package
                .constraint()
                .satisfies(candidate.release().version())
    }) {
        return Some(AssignmentDifference::RootRequirementMismatch {
            requirement: requirement.package.constraint().clone(),
        });
    }
    if let Some(dependency) =
        candidate
            .release()
            .declared_dependencies()
            .iter()
            .find(|dependency| {
                matches!(
                    dependency.kind,
                    DependencyKind::Depends | DependencyKind::Imports | DependencyKind::LinkingTo
                ) && dependency.package.name().as_str() == "R"
                    && !dependency
                        .package
                        .constraint()
                        .satisfies(&difference.r_version)
            })
    {
        return Some(AssignmentDifference::ConstraintViolatedByAssignment {
            against: DecisionSubject::R,
            requirement: dependency.package.constraint().clone(),
            assigned: DecisionCandidate::R(difference.r_version.clone()),
        });
    }
    if let Some((dependency, assigned)) = candidate
        .release()
        .declared_dependencies()
        .iter()
        .filter(|dependency| {
            matches!(
                dependency.kind,
                DependencyKind::Depends | DependencyKind::Imports | DependencyKind::LinkingTo
            ) && dependency.package.name().as_str() != "R"
        })
        .filter_map(|dependency| {
            let key = dependency_key(dependency.package.name(), dependency.package.source())?;
            let assigned = difference
                .selected_packages
                .iter()
                .find(|package| package.subject() == &key)?;
            (!dependency
                .package
                .constraint()
                .satisfies(assigned.release().version()))
            .then_some((dependency, assigned))
        })
        .next()
    {
        return Some(AssignmentDifference::ConstraintViolatedByAssignment {
            against: subject_to_decision_subject(assigned.subject()),
            requirement: dependency.package.constraint().clone(),
            assigned: release_candidate(assigned.release()),
        });
    }
    let preference_order = compare_prepared_candidates(
        preference,
        difference.subject,
        difference.selected_candidate,
        candidate,
        difference.preference,
    );
    if difference
        .preference
        .locked
        .is_some_and(|locked| candidate.identity() != locked)
        || preference_order == Ordering::Greater
    {
        return Some(AssignmentDifference::LowerPreference {
            assigned: candidate_for_subject(difference.subject, difference.selected),
        });
    }
    None
}

fn release_candidate(release: &PackageRelease) -> DecisionCandidate {
    DecisionCandidate::Release {
        identity: release.identity().clone(),
        version: release.version().clone(),
    }
}

fn candidate_for_subject(subject: &SolverKey, release: &PackageRelease) -> DecisionCandidate {
    match subject {
        SolverKey::InstalledName(name) => DecisionCandidate::InstalledName {
            name: name.clone(),
            occupied_by: release.identity().clone(),
        },
        _ => release_candidate(release),
    }
}

fn subject_to_decision_subject(subject: &SolverKey) -> DecisionSubject {
    match subject {
        SolverKey::InstalledName(name) => DecisionSubject::InstalledName(name.clone()),
        SolverKey::R => DecisionSubject::R,
        SolverKey::Registry { .. }
        | SolverKey::Repository { .. }
        | SolverKey::Bioconductor { .. }
        | SolverKey::Exact(_) => DecisionSubject::Package(subject_name(subject)),
    }
}

fn subject_name(subject: &SolverKey) -> PackageName {
    match subject {
        SolverKey::Registry { name, .. }
        | SolverKey::Repository { name, .. }
        | SolverKey::Bioconductor { name, .. }
        | SolverKey::InstalledName(name) => name.clone(),
        SolverKey::Exact(identity) => identity.name().clone(),
        SolverKey::R => PackageName::new("R").expect("R is a valid package name"),
    }
}

fn dependency_key(name: &PackageName, source: &DependencySourceConstraint) -> Option<SolverKey> {
    if name.as_str() == "R" && !matches!(source, DependencySourceConstraint::Git { .. }) {
        return Some(SolverKey::R);
    }
    Some(match source {
        DependencySourceConstraint::Any => SolverKey::InstalledName(name.clone()),
        DependencySourceConstraint::Registry { namespace } => SolverKey::Registry {
            namespace: namespace.clone(),
            name: name.clone(),
        },
        DependencySourceConstraint::Repository { repository } => SolverKey::Repository {
            repository: repository.clone(),
            name: name.clone(),
        },
        DependencySourceConstraint::Bioconductor { namespace, release } => {
            SolverKey::Bioconductor {
                namespace: namespace.clone(),
                release: release.clone(),
                name: name.clone(),
            }
        }
        DependencySourceConstraint::Exact(identity) => SolverKey::Exact(identity.clone()),
        DependencySourceConstraint::Git { .. } => return None,
    })
}

impl fmt::Display for LockDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlocked => f.write_str("unlocked"),
            Self::Prefer(identity) => write!(f, "prefer {}", identity.name()),
            Self::Require(identity) => write!(f, "require {}", identity.name()),
        }
    }
}
