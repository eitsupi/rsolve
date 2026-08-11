//! Reusable logical resolution boundary for nrr.
//!
//! PubGrub is deliberately confined to [`adapter`].  The public API contains
//! only nrr domain values and resolver-owned policy/comparison values.

mod adapter;

use std::cmp::Ordering;
use std::fmt;

use nrr_core::{
    CandidateLoader, DependencySourceConstraint, PackageName, PackageRelease, RPackageVersion,
    ReleaseIdentity, Resolution, ResolutionRequest, SolverKey, VersionConstraint,
};

pub use adapter::{ResolutionDiagnostic, ResolutionFailure};

/// Information available to a candidate ordering policy for one solve.
pub struct PreferenceContext<'a> {
    pub locked: Option<&'a ReleaseIdentity>,
    pub repository_current: Option<&'a ReleaseIdentity>,
}

/// Stable trial ordering.  It affects which compatible candidate PubGrub
/// tries first; it never changes the dependency constraints.
pub trait CandidatePreference {
    fn compare(
        &self,
        package: &SolverKey,
        left: &PackageRelease,
        right: &PackageRelease,
        context: &PreferenceContext<'_>,
    ) -> Ordering;
}

/// The minimal nrr ordering: locked, then current repository, then newest.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultCandidatePreference;

impl CandidatePreference for DefaultCandidatePreference {
    fn compare(
        &self,
        _package: &SolverKey,
        left: &PackageRelease,
        right: &PackageRelease,
        context: &PreferenceContext<'_>,
    ) -> Ordering {
        preference_rank(left, context)
            .cmp(&preference_rank(right, context))
            .then_with(|| left.version().cmp(right.version()))
            .then_with(|| {
                identity_sort_key(left.identity()).cmp(&identity_sort_key(right.identity()))
            })
    }
}

fn preference_rank(release: &PackageRelease, context: &PreferenceContext<'_>) -> u8 {
    if context.locked == Some(release.identity()) {
        3
    } else if context.repository_current == Some(release.identity()) {
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
            let current = repository_current(&candidates);
            let previous = request.locked.get(&subject);
            let decision = self.lock_policy.decision(&subject, previous);
            let locked = match &decision {
                LockDecision::Prefer(identity) | LockDecision::Require(identity) => Some(identity),
                LockDecision::Unlocked => None,
            };
            let context = PreferenceContext {
                locked,
                repository_current: current.as_ref().map(PackageRelease::identity),
            };
            let basis = assignment_basis(
                package,
                &candidates,
                &context,
                &decision,
                request,
                &subject,
                &resolution.target().r_version,
            );
            let assigned = candidate_for_subject(&subject, package.release());
            // The loader's iteration order must not reach the public
            // comparison, so each alternative carries the candidate's own
            // version and identity as its sort key.
            let mut keyed: Vec<_> = candidates
                .iter()
                .filter(|candidate| candidate.identity() != package.release().identity())
                .filter_map(|candidate| {
                    difference_for_candidate(
                        candidate,
                        package.release(),
                        resolution.target().r_version.clone(),
                        &decision,
                        &context,
                        &subject,
                        &selected,
                    )
                    .map(|differs_by| {
                        (
                            (
                                candidate.version().clone(),
                                identity_sort_key(candidate.identity()),
                            ),
                            AlternativeComparison {
                                candidate: candidate_for_subject(&subject, candidate),
                                differs_by,
                            },
                        )
                    })
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
    ) -> Result<Vec<PackageRelease>, ResolutionFailure> {
        self.loader
            .releases(subject)
            .map_err(|source| ResolutionFailure::CandidateLoad {
                package: subject.clone(),
                source: Box::new(source),
            })
    }
}

fn repository_current(candidates: &[PackageRelease]) -> Option<PackageRelease> {
    candidates
        .iter()
        .filter(|candidate| {
            candidate
                .distributions()
                .iter()
                .any(|d| d.snapshot.is_none())
        })
        .max_by(|left, right| {
            left.version().cmp(right.version()).then_with(|| {
                identity_sort_key(left.identity()).cmp(&identity_sort_key(right.identity()))
            })
        })
        .cloned()
}

fn assignment_basis(
    selected: &nrr_core::ResolvedPackage,
    candidates: &[PackageRelease],
    context: &PreferenceContext<'_>,
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
    if let Some(current) = context.repository_current
        && current == selected.release().identity()
    {
        return AssignmentBasis::RepositoryCurrent;
    }
    let statically_compatible = candidates
        .iter()
        .filter(|candidate| {
            candidate.dependencies().iter().all(|dependency| {
                dependency.name.as_str() != "R" || dependency.constraint.satisfies(r_version)
            })
        })
        .count();
    if statically_compatible == 1 {
        return AssignmentBasis::OnlyStaticallyCompatible;
    }
    if request.requirements.iter().any(|requirement| {
        dependency_key(&requirement.name, &requirement.source)
            .as_ref()
            .is_some_and(|key| key == subject)
            && requirement.constraint.clauses.iter().any(|clause| {
                clause.op == nrr_core::RelationOp::Eq
                    && clause.version == *selected.release().version()
            })
    }) {
        return AssignmentBasis::ExactRootRequirement;
    }
    let _ = subject;
    AssignmentBasis::HighestCompatible
}

fn difference_for_candidate(
    candidate: &PackageRelease,
    selected: &PackageRelease,
    r_version: RPackageVersion,
    decision: &LockDecision,
    context: &PreferenceContext<'_>,
    subject: &SolverKey,
    selected_packages: &[nrr_core::ResolvedPackage],
) -> Option<AssignmentDifference> {
    // TODO: This only checks a candidate's Depends: R constraint against the fixed R target. A
    // candidate excluded by a root version requirement or by a dependency on another assigned
    // package currently falls through to LowerPreference and is labelled with a false reason.
    // Widening the statically checkable set, or adding a distinct not-explained difference, is
    // deferred.
    if let LockDecision::Require(required) = decision
        && candidate.identity() != required
    {
        return Some(AssignmentDifference::RequiredLockMismatch {
            required: required.clone(),
        });
    }
    if let Some(other) = selected_packages.iter().find(|other| {
        other.subject() != subject
            && other.name() == candidate.identity().name()
            && other.release().identity() != candidate.identity()
    }) {
        return Some(AssignmentDifference::InstalledNameConflict {
            name: candidate.identity().name().clone(),
            assigned_to: other.release().identity().clone(),
        });
    }
    if let Some(dependency) = candidate.dependencies().iter().find(|dependency| {
        dependency.name.as_str() == "R" && !dependency.constraint.satisfies(&r_version)
    }) {
        return Some(AssignmentDifference::ConstraintViolatedByAssignment {
            against: DecisionSubject::R,
            requirement: dependency.constraint.clone(),
            assigned: DecisionCandidate::R(r_version),
        });
    }
    if context
        .locked
        .is_some_and(|locked| candidate.identity() != locked)
        || context
            .repository_current
            .is_some_and(|current| candidate.identity() != current)
        || candidate.version() < selected.version()
    {
        return Some(AssignmentDifference::LowerPreference {
            assigned: candidate_for_subject(subject, selected),
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
        SolverKey::Registry { .. } | SolverKey::Bioconductor { .. } | SolverKey::Exact(_) => {
            DecisionSubject::Package(subject_name(subject))
        }
    }
}

fn subject_name(subject: &SolverKey) -> PackageName {
    match subject {
        SolverKey::Registry { name, .. }
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
