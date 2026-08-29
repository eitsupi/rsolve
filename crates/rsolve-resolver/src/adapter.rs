//! Private PubGrub adapter.  No type from this module is part of rsolve's API.

use std::cell::RefCell;
use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;

use pubgrub::{
    Dependencies, DependencyConstraints, DependencyProvider, DerivationTree, External,
    PackageResolutionStatistics, PubGrubError, Ranges, resolve,
};
use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, DependencyKind,
    DependencySourceConstraint, PreparedCandidate, PublicationCutoff, PublicationDate,
    RPackageVersion, ReleaseIdentity, Resolution, ResolutionRequest, ResolvedDependencyEdge,
    RootExpansionPolicy, SolverKey, VersionConstraint,
};

use crate::{
    CandidatePreference, LockDecision, LockUpdatePolicy, PreferenceContext,
    compare_prepared_candidates,
};

#[cfg(test)]
use rsolve_core::PackageRelease;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct CandidateId(usize);

impl fmt::Debug for CandidateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("candidate")
    }
}

impl fmt::Display for CandidateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("candidate")
    }
}

/// The solve-local PubGrub version domain. Candidate IDs are opaque and their
/// ordinal is never used as a preference or release ordering signal.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum SolverVersion {
    Root,
    R(RPackageVersion),
    Candidate(CandidateId),
}

impl fmt::Debug for SolverVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_display(formatter)
    }
}

impl fmt::Display for SolverVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_display(formatter)
    }
}

impl SolverVersion {
    fn fmt_display(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => formatter.write_str("root"),
            Self::R(version) => write!(formatter, "R {version}"),
            Self::Candidate(_) => formatter.write_str("candidate"),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum PackageId {
    Root,
    Subject(SolverKey),
    Occupancy(rsolve_core::PackageName),
}

impl fmt::Display for PackageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => formatter.write_str("root"),
            Self::Subject(subject) => write!(formatter, "{subject:?}"),
            Self::Occupancy(name) => write!(formatter, "occupancy({name})"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProviderMessage {
    Text(String),
    Publication {
        rejections: Vec<PublicationRejection>,
    },
}

impl fmt::Display for ProviderMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(message) => formatter.write_str(message),
            Self::Publication { rejections, .. } => {
                write!(
                    formatter,
                    "{} publication-ineligible candidate(s)",
                    rejections.len()
                )
            }
        }
    }
}

#[derive(Debug)]
struct AdapterError {
    package: SolverKey,
    source: Box<CandidateLoadError>,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "loading {:#?}: {}", self.package, self.source)
    }
}

impl Error for AdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn candidate_load_error(package: SolverKey, source: CandidateLoadError) -> Box<AdapterError> {
    Box::new(AdapterError {
        package,
        source: Box::new(source),
    })
}

#[derive(Clone, Debug)]
struct LoadedSubject {
    candidates: Vec<(CandidateId, PreparedCandidate)>,
    quarantined: Vec<rsolve_core::QuarantinedCandidate>,
}

#[derive(Default)]
struct CandidateInterner {
    next: usize,
    by_identity: HashMap<ReleaseIdentity, CandidateId>,
    candidates: HashMap<CandidateId, PreparedCandidate>,
}

impl CandidateInterner {
    /// Interns only completed prepared views.  This table assigns opaque IDs
    /// and validates repeated identities; it never enriches a view after it
    /// has been made visible to PubGrub.
    fn intern(&mut self, candidate: &PreparedCandidate) -> Result<CandidateId, CandidateLoadError> {
        let identity = candidate.identity().clone();
        if let Some(id) = self.by_identity.get(&identity).copied() {
            let existing = self.candidates.get(&id).ok_or_else(|| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    "candidate interner lost the prepared candidate for an interned identity",
                )
            })?;
            if !existing.same_facts(candidate) {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    "conflicting logical metadata for interned candidate",
                ));
            };
            // A candidate's fully prepared facts are immutable once interned.
            // Composition must complete occurrence and distribution enrichment
            // before any subject is presented to the solver.
            return Ok(id);
        }
        let id = CandidateId(self.next);
        self.next = self.next.checked_add(1).ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                "candidate interner exhausted its solve-local identifier space",
            )
        })?;
        self.by_identity.insert(identity, id);
        self.candidates.insert(id, candidate.clone());
        Ok(id)
    }

    fn ids_for_name(&self, name: &rsolve_core::PackageName) -> Vec<CandidateId> {
        let mut ids = self
            .candidates
            .iter()
            .filter_map(|(id, candidate)| (candidate.identity().name() == name).then_some(*id))
            .collect::<Vec<_>>();
        ids.sort_by(|left, right| {
            identity_sort_key(self.candidates[left].identity())
                .cmp(&identity_sort_key(self.candidates[right].identity()))
        });
        ids
    }
}

struct Provider<'a> {
    loader: &'a dyn CandidateLoader,
    preference: &'a dyn CandidatePreference,
    lock_policy: &'a dyn LockUpdatePolicy,
    request: &'a ResolutionRequest,
    cache: RefCell<HashMap<SolverKey, Result<LoadedSubject, CandidateLoadError>>>,
    interner: RefCell<CandidateInterner>,
}

impl<'a> Provider<'a> {
    fn loaded(&self, subject: &SolverKey) -> Result<LoadedSubject, Box<AdapterError>> {
        if let Some(cached) = self.cache.borrow().get(subject) {
            return cached
                .clone()
                .map_err(|source| candidate_load_error(subject.clone(), source));
        }
        let loaded: Result<LoadedSubject, CandidateLoadError> = match self.loader.load(subject) {
            Ok(result) => (|| -> Result<LoadedSubject, CandidateLoadError> {
                let (releases, quarantined) = result.into_parts();
                let mut unique = Vec::new();
                for release in releases {
                    if let Some(index) = unique.iter().position(|candidate: &PreparedCandidate| {
                        candidate.identity() == release.identity()
                    }) {
                        let existing = unique.remove(index);
                        unique.push(existing.merge(release).map_err(|error| {
                            CandidateLoadError::new(
                                CandidateLoadErrorCategory::MetadataInvalid,
                                format!("conflicting metadata within subject: {error}"),
                            )
                        })?);
                    } else {
                        unique.push(release);
                    }
                }
                unique.sort_by(|left, right| {
                    identity_sort_key(left.identity()).cmp(&identity_sort_key(right.identity()))
                });
                unique.retain(|candidate| candidate.is_eligible_for(subject));
                let candidates = unique
                    .into_iter()
                    .map(|candidate| {
                        self.interner
                            .borrow_mut()
                            .intern(&candidate)
                            .map(|id| (id, candidate))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(LoadedSubject {
                    candidates,
                    quarantined,
                })
            })(),
            Err(error) => Err(error),
        };
        self.cache
            .borrow_mut()
            .insert(subject.clone(), loaded.clone());
        loaded.map_err(|source| candidate_load_error(subject.clone(), source))
    }

    fn candidates(
        &self,
        subject: &SolverKey,
    ) -> Result<Vec<(CandidateId, PreparedCandidate)>, Box<AdapterError>> {
        let loaded = self.loaded(subject)?;
        Ok(self.candidates_from_loaded(&loaded))
    }

    fn candidates_from_loaded(
        &self,
        loaded: &LoadedSubject,
    ) -> Vec<(CandidateId, PreparedCandidate)> {
        loaded.candidates.clone()
    }

    fn candidate_for_id(
        &self,
        subject: &SolverKey,
        id: CandidateId,
    ) -> Result<PreparedCandidate, Box<AdapterError>> {
        let loaded = self.loaded(subject)?;
        let Some((_, release)) = self
            .candidates_from_loaded(&loaded)
            .into_iter()
            .find(|(candidate_id, _)| *candidate_id == id)
        else {
            return Err(candidate_load_error(
                subject.clone(),
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    "selected candidate is not visible in this subject",
                ),
            ));
        };
        Ok(release.clone())
    }

    fn r_version(&self) -> &RPackageVersion {
        &self.request.target.r_version
    }

    fn lock_decision(&self, subject: &SolverKey) -> LockDecision {
        self.lock_policy
            .decision(subject, self.request.locked.get(subject))
    }

    fn r_range(&self, constraint: &VersionConstraint) -> Ranges<SolverVersion> {
        if constraint.satisfies(self.r_version()) {
            Ranges::singleton(SolverVersion::R(self.r_version().clone()))
        } else {
            Ranges::empty()
        }
    }

    fn ranges_for_subject(
        &self,
        subject: &SolverKey,
        constraint: &VersionConstraint,
    ) -> Result<Ranges<SolverVersion>, Box<AdapterError>> {
        if matches!(subject, SolverKey::R) {
            Ok(self.r_range(constraint))
        } else {
            self.candidate_ranges(subject, constraint)
        }
    }

    fn candidate_ranges(
        &self,
        subject: &SolverKey,
        constraint: &VersionConstraint,
    ) -> Result<Ranges<SolverVersion>, Box<AdapterError>> {
        let loaded = self.loaded(subject)?;
        let candidates = self.candidates_from_loaded(&loaded);
        let mut range = Ranges::empty();
        for (id, release) in candidates {
            if constraint.satisfies(release.release().version()) {
                range = range.union(&Ranges::singleton(SolverVersion::Candidate(id)));
            }
        }
        if !matches!(self.lock_decision(subject), LockDecision::Require(_))
            && range == Ranges::empty()
            && loaded
                .quarantined
                .iter()
                .any(|candidate| constraint.satisfies(candidate.version()))
        {
            let versions = loaded
                .quarantined
                .iter()
                .filter(|candidate| constraint.satisfies(candidate.version()))
                .map(|candidate| candidate.version().to_string())
                .collect::<Vec<_>>();
            return Err(candidate_load_error(
                subject.clone(),
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!(
                        "all candidates matching the requested range were quarantined: {}",
                        versions.join(", ")
                    ),
                ),
            ));
        }
        Ok(range)
    }

    fn subject_for_package(
        &self,
        package: &rsolve_core::PackageRequirement,
    ) -> Result<SolverKey, Box<AdapterError>> {
        if let DependencySourceConstraint::Git { .. } = &package.source() {
            return Err(candidate_load_error(
                SolverKey::InstalledName(package.name().clone()),
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!(
                        "Git-sourced dependencies are not supported for package {}",
                        package.name()
                    ),
                ),
            ));
        }
        if package.name().as_str() == "R" {
            return Ok(SolverKey::R);
        }
        Ok(match &package.source() {
            DependencySourceConstraint::Any => SolverKey::InstalledName(package.name().clone()),
            DependencySourceConstraint::Registry { namespace } => SolverKey::Registry {
                namespace: namespace.clone(),
                name: package.name().clone(),
            },
            DependencySourceConstraint::Bioconductor { namespace, release } => {
                SolverKey::Bioconductor {
                    namespace: namespace.clone(),
                    release: release.clone(),
                    name: package.name().clone(),
                }
            }
            DependencySourceConstraint::Repository { repository } => SolverKey::Repository {
                repository: repository.clone(),
                name: package.name().clone(),
            },
            DependencySourceConstraint::Exact(identity) => SolverKey::Exact(identity.clone()),
            DependencySourceConstraint::Git { .. } => {
                unreachable!("Git dependencies are rejected by the caller")
            }
        })
    }

    fn with_eligible_candidates<T>(
        &self,
        subject: &SolverKey,
        range: Option<&Ranges<SolverVersion>>,
        use_candidates: impl FnOnce(
            &mut Vec<(CandidateId, PreparedCandidate)>,
            &PreferenceContext<'_>,
        ) -> T,
    ) -> Result<T, Box<AdapterError>> {
        let candidates = self.candidates(subject)?;
        let decision = self.lock_decision(subject);
        let required = match &decision {
            LockDecision::Require(identity) => Some(identity),
            _ => None,
        };
        let locked = match &decision {
            LockDecision::Prefer(identity) | LockDecision::Require(identity) => {
                Some(identity.clone())
            }
            LockDecision::Unlocked => None,
        };
        let context = PreferenceContext {
            locked: locked.as_ref(),
        };
        let mut eligible = candidates
            .into_iter()
            .filter(|(id, candidate)| {
                required
                    .as_ref()
                    .is_none_or(|identity| candidate.identity() == *identity)
                    && range.is_none_or(|range| range.contains(&SolverVersion::Candidate(*id)))
            })
            .collect::<Vec<_>>();
        if self.request.publication_cutoff.is_some() {
            let candidates_before_policy = eligible.clone();
            let rejections = self.publication_rejections(subject, &eligible, locked.as_ref());
            if !rejections.is_empty() {
                eligible.retain(|(_, candidate)| {
                    !rejections.iter().any(|rejection| match rejection {
                        PublicationRejection::PublicationCooldown { identity, .. }
                        | PublicationRejection::PublicationUnknown { identity } => {
                            candidate.identity() == identity
                        }
                    })
                });
                if eligible.is_empty() {
                    eligible = candidates_before_policy;
                }
            }
        }
        Ok(use_candidates(&mut eligible, &context))
    }

    fn publication_rejections(
        &self,
        _subject: &SolverKey,
        candidates: &[(CandidateId, PreparedCandidate)],
        locked: Option<&ReleaseIdentity>,
    ) -> Vec<PublicationRejection> {
        let Some(cutoff) = self.request.publication_cutoff.map(|cutoff| cutoff.date()) else {
            return Vec::new();
        };
        let mut rejections = candidates
            .iter()
            .filter_map(|(_, candidate)| {
                if candidate.release().is_r_base_package()
                    || locked.is_some_and(|identity| candidate.identity() == identity)
                {
                    return None;
                }
                match candidate.release().publication() {
                    Some(publication) if publication.date() > cutoff => {
                        Some(PublicationRejection::PublicationCooldown {
                            identity: candidate.identity().clone(),
                            published: publication.date(),
                        })
                    }
                    Some(_) => None,
                    None => Some(PublicationRejection::PublicationUnknown {
                        identity: candidate.identity().clone(),
                    }),
                }
            })
            .collect::<Vec<_>>();
        rejections.sort_by(|left, right| {
            publication_rejection_sort_key(left).cmp(&publication_rejection_sort_key(right))
        });
        rejections
    }

    fn publication_rejections_for_candidate(
        &self,
        subject: &SolverKey,
        id: CandidateId,
    ) -> Result<Vec<PublicationRejection>, Box<AdapterError>> {
        let decision = self.lock_decision(subject);
        let required = match &decision {
            LockDecision::Require(identity) => Some(identity),
            _ => None,
        };
        let locked = match &decision {
            LockDecision::Prefer(identity) | LockDecision::Require(identity) => {
                Some(identity.clone())
            }
            LockDecision::Unlocked => None,
        };
        let candidate = self.candidate_for_id(subject, id)?;
        if required.is_some_and(|identity| candidate.identity() != identity) {
            return Ok(Vec::new());
        }
        let rejections = self.publication_rejections(subject, &[(id, candidate)], locked.as_ref());
        Ok(rejections)
    }

    fn compare_candidates(
        &self,
        subject: &SolverKey,
        left: &PreparedCandidate,
        right: &PreparedCandidate,
        context: &PreferenceContext<'_>,
    ) -> Ordering {
        compare_prepared_candidates(self.preference, subject, left, right, context)
    }

    fn sort_candidates(
        &self,
        subject: &SolverKey,
        candidates: &mut [(CandidateId, PreparedCandidate)],
        context: &PreferenceContext<'_>,
    ) {
        candidates.sort_by(|(_, left), (_, right)| {
            self.compare_candidates(subject, left, right, context)
        });
    }
}

impl DependencyProvider for Provider<'_> {
    type P = PackageId;
    type V = SolverVersion;
    type VS = Ranges<SolverVersion>;
    type Priority = (Reverse<usize>, String);
    type M = ProviderMessage;
    type Err = Box<AdapterError>;

    fn prioritize(
        &self,
        package: &Self::P,
        range: &Self::VS,
        _package_conflicts_counts: &PackageResolutionStatistics,
    ) -> Self::Priority {
        let count = match package {
            PackageId::Root => 1,
            PackageId::Subject(SolverKey::R) => {
                usize::from(range.contains(&SolverVersion::R(self.r_version().clone())))
            }
            PackageId::Subject(subject) => self
                .candidates(subject)
                .map(|candidates| {
                    candidates
                        .iter()
                        .filter(|(id, _)| range.contains(&SolverVersion::Candidate(*id)))
                        .count()
                })
                .unwrap_or(usize::MAX),
            PackageId::Occupancy(_) => 1,
        };
        (Reverse(count), format!("{package:?}"))
    }

    fn choose_version(
        &self,
        package: &Self::P,
        range: &Self::VS,
    ) -> Result<Option<Self::V>, Self::Err> {
        match package {
            PackageId::Root => Ok(range
                .contains(&SolverVersion::Root)
                .then_some(SolverVersion::Root)),
            PackageId::Subject(SolverKey::R) => Ok(range
                .contains(&SolverVersion::R(self.r_version().clone()))
                .then_some(SolverVersion::R(self.r_version().clone()))),
            PackageId::Subject(subject) => {
                self.with_eligible_candidates(subject, Some(range), |eligible, context| {
                    self.sort_candidates(subject, eligible, context);
                    eligible.pop().map(|(id, _)| SolverVersion::Candidate(id))
                })
            }
            PackageId::Occupancy(_) => {
                // Occupancy is constrained by exact singleton ranges emitted
                // by source subjects. Resolve those opaque IDs from the
                // solve-local interner rather than retaining selection state.
                let PackageId::Occupancy(name) = package else {
                    unreachable!()
                };
                Ok(self
                    .interner
                    .borrow()
                    .ids_for_name(name)
                    .into_iter()
                    .find(|id| range.contains(&SolverVersion::Candidate(*id)))
                    .map(SolverVersion::Candidate))
            }
        }
    }

    fn get_dependencies(
        &self,
        package: &Self::P,
        version: &Self::V,
    ) -> Result<Dependencies<Self::P, Self::VS, Self::M>, Self::Err> {
        match package {
            PackageId::Root => {
                if version != &SolverVersion::Root {
                    return Ok(Dependencies::Unavailable(ProviderMessage::Text(
                        "unknown root version".to_owned(),
                    )));
                }
                let mut dependencies = Vec::new();
                dependencies.push((
                    PackageId::Subject(SolverKey::R),
                    self.r_range(&self.request.r_requirement),
                ));
                for requirement in &self.request.roots {
                    let subject = self.subject_for_package(&requirement.package)?;
                    dependencies.push((
                        PackageId::Subject(subject.clone()),
                        self.ranges_for_subject(&subject, requirement.package.constraint())?,
                    ));
                }
                Ok(Dependencies::Available(DependencyConstraints::from_iter(
                    dependencies,
                )))
            }
            PackageId::Subject(SolverKey::R) => {
                Ok(Dependencies::Available(DependencyConstraints::default()))
            }
            PackageId::Subject(subject) => {
                let SolverVersion::Candidate(id) = version else {
                    return Ok(Dependencies::Unavailable(ProviderMessage::Text(
                        "unknown candidate version".to_owned(),
                    )));
                };
                let rejections = self.publication_rejections_for_candidate(subject, *id)?;
                if !rejections.is_empty() {
                    return Ok(Dependencies::Unavailable(ProviderMessage::Publication {
                        rejections,
                    }));
                }
                let candidate = self.candidate_for_id(subject, *id)?;
                let release = candidate.release();
                let name = release.identity().name().clone();
                let mut dependencies = vec![(
                    PackageId::Occupancy(name),
                    Ranges::singleton(SolverVersion::Candidate(*id)),
                )];
                for dependency in release.declared_dependencies().iter().filter(|dependency| {
                    matches!(
                        dependency.kind,
                        DependencyKind::Depends
                            | DependencyKind::Imports
                            | DependencyKind::LinkingTo
                    )
                }) {
                    if let DependencySourceConstraint::Git { .. } = dependency.package.source() {
                        return Ok(Dependencies::Unavailable(ProviderMessage::Text(format!(
                            "Git-sourced dependencies are not supported for package {}",
                            dependency.package.name()
                        ))));
                    }
                    let dependency_subject = self.subject_for_package(&dependency.package)?;
                    dependencies.push((
                        PackageId::Subject(dependency_subject.clone()),
                        self.ranges_for_subject(
                            &dependency_subject,
                            dependency.package.constraint(),
                        )?,
                    ));
                }
                Ok(Dependencies::Available(DependencyConstraints::from_iter(
                    dependencies,
                )))
            }
            PackageId::Occupancy(_) => {
                Ok(Dependencies::Available(DependencyConstraints::default()))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationRejection {
    PublicationCooldown {
        identity: ReleaseIdentity,
        published: PublicationDate,
    },
    PublicationUnknown {
        identity: ReleaseIdentity,
    },
}

fn publication_rejection_sort_key(rejection: &PublicationRejection) -> String {
    match rejection {
        PublicationRejection::PublicationCooldown { identity, .. }
        | PublicationRejection::PublicationUnknown { identity } => identity_sort_key(identity),
    }
}

fn publication_rejection_cmp(
    left: &PublicationRejection,
    right: &PublicationRejection,
) -> Ordering {
    publication_rejection_sort_key(left)
        .cmp(&publication_rejection_sort_key(right))
        .then_with(|| match (left, right) {
            (
                PublicationRejection::PublicationCooldown {
                    published: left, ..
                },
                PublicationRejection::PublicationCooldown {
                    published: right, ..
                },
            ) => left.cmp(right),
            (
                PublicationRejection::PublicationCooldown { .. },
                PublicationRejection::PublicationUnknown { .. },
            ) => Ordering::Less,
            (
                PublicationRejection::PublicationUnknown { .. },
                PublicationRejection::PublicationCooldown { .. },
            ) => Ordering::Greater,
            (
                PublicationRejection::PublicationUnknown { .. },
                PublicationRejection::PublicationUnknown { .. },
            ) => Ordering::Equal,
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolutionFailure {
    UnsupportedRootExpansion {
        package: rsolve_core::PackageName,
        policy: RootExpansionPolicy,
    },
    CandidateLoad {
        package: SolverKey,
        source: Box<CandidateLoadError>,
    },
    NoSolution {
        diagnostic: ResolutionDiagnostic,
    },
    InstalledNameConflict {
        name: rsolve_core::PackageName,
        first_identity: Box<rsolve_core::ReleaseIdentity>,
        second_identity: Box<rsolve_core::ReleaseIdentity>,
    },
    Solver {
        diagnostic: ResolutionDiagnostic,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Evidence that publication-policy rejections occurred in the final solver
/// derivation. This is diagnostic evidence only; it does not classify the
/// complete cause of the unsatisfiable request.
pub struct ResolutionDiagnostic {
    pub summary: Box<str>,
    publication_policy: Option<PublicationPolicyDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Publication-policy leaves observed in a no-solution derivation.
pub struct PublicationPolicyDiagnostic {
    pub cutoff: PublicationCutoff,
    pub rejections: Box<[PublicationRejection]>,
}

impl ResolutionDiagnostic {
    fn new(summary: impl Into<Box<str>>) -> Self {
        Self {
            summary: summary.into(),
            publication_policy: None,
        }
    }

    fn with_publication_policy(mut self, policy: Option<PublicationPolicyDiagnostic>) -> Self {
        self.publication_policy = policy;
        self
    }

    pub fn publication_policy(&self) -> Option<&PublicationPolicyDiagnostic> {
        self.publication_policy.as_ref()
    }
}

impl fmt::Display for ResolutionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRootExpansion { package, policy } => write!(
                f,
                "root expansion policy {policy:?} for package {package} is not supported",
            ),
            Self::CandidateLoad { package, source } => {
                write!(f, "candidate load for {package:?} failed: {source}")
            }
            Self::NoSolution { diagnostic } => {
                f.write_str("no resolution")?;
                if let Some(policy) = diagnostic.publication_policy() {
                    write!(
                        f,
                        " (publication policy evidence in proof: cutoff {}, {} rejection(s))",
                        policy.cutoff.date(),
                        policy.rejections.len()
                    )?;
                }
                write!(f, ": {}", diagnostic.summary)
            }
            Self::InstalledNameConflict {
                name,
                first_identity,
                second_identity,
            } => write!(
                f,
                "installed package name {name} maps to distinct identities {} and {}",
                identity_sort_key(first_identity),
                identity_sort_key(second_identity),
            ),
            Self::Solver { diagnostic } => write!(f, "resolver failure: {}", diagnostic.summary),
        }
    }
}

impl Error for ResolutionFailure {}

pub(crate) fn solve(
    loader: &dyn CandidateLoader,
    preference: &dyn CandidatePreference,
    lock_policy: &dyn LockUpdatePolicy,
    request: &ResolutionRequest,
) -> Result<Resolution, ResolutionFailure> {
    if let Some(root) = request
        .roots
        .iter()
        .find(|root| root.expansion == RootExpansionPolicy::DirectSuggests)
    {
        return Err(ResolutionFailure::UnsupportedRootExpansion {
            package: root.package.name().clone(),
            policy: root.expansion,
        });
    }
    let provider = Provider {
        loader,
        preference,
        lock_policy,
        request,
        cache: RefCell::new(HashMap::new()),
        interner: RefCell::new(CandidateInterner::default()),
    };
    let selected = resolve(&provider, PackageId::Root, SolverVersion::Root)
        .map_err(|error| map_error(error, request.publication_cutoff))?;

    let mut packages =
        BTreeMap::<rsolve_core::PackageName, (SolverKey, PreparedCandidate, Vec<SolverKey>)>::new();
    for (package, version) in selected {
        if let PackageId::Subject(subject) = package {
            if subject == SolverKey::R {
                continue;
            }
            let SolverVersion::Candidate(id) = version else {
                continue;
            };
            let candidate = provider
                .candidate_for_id(&subject, id)
                .map_err(|error| map_adapter_error(*error))?;
            if candidate.release().is_r_base_package() {
                continue;
            }
            let name = candidate.identity().name().clone();
            match packages.entry(name.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((subject.clone(), candidate, vec![subject]));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let (existing_subject, existing_candidate, subjects) = entry.get_mut();
                    if existing_candidate.identity() != candidate.identity() {
                        let (first_identity, second_identity) =
                            if identity_sort_key(existing_candidate.identity())
                                <= identity_sort_key(candidate.identity())
                            {
                                (
                                    existing_candidate.identity().clone(),
                                    candidate.identity().clone(),
                                )
                            } else {
                                (
                                    candidate.identity().clone(),
                                    existing_candidate.identity().clone(),
                                )
                            };
                        return Err(ResolutionFailure::InstalledNameConflict {
                            name,
                            first_identity: Box::new(first_identity),
                            second_identity: Box::new(second_identity),
                        });
                    }
                    let merged = existing_candidate
                        .clone()
                        .merge(candidate)
                        .map_err(|error| ResolutionFailure::CandidateLoad {
                            package: subject.clone(),
                            source: Box::new(CandidateLoadError::new(
                                CandidateLoadErrorCategory::MetadataInvalid,
                                format!("inconsistent prepared candidate: {error}"),
                            )),
                        })?;
                    *existing_candidate = merged;
                    subjects.push(subject.clone());
                    if canonical_subject_cmp(&subject, existing_subject) == Ordering::Less {
                        *existing_subject = subject;
                    }
                }
            }
        }
    }
    let mut packages = packages
        .into_values()
        .map(|(subject, candidate, subjects)| {
            let release = candidate.release();
            let effective_dependencies = release
                .declared_dependencies()
                .iter()
                .filter_map(|dependency| {
                    dependency
                        .kind
                        .effective()
                        .map(|kind| ResolvedDependencyEdge {
                            kind,
                            package: dependency.package.clone(),
                        })
                })
                .collect();
            let mut visible = subjects
                .iter()
                .flat_map(|subject| candidate.applicable_occurrences(subject))
                .map(|occurrence| (occurrence.rank(), occurrence.repository().clone()))
                .collect::<Vec<_>>();
            visible.sort();
            visible.dedup_by(|left, right| left.1 == right.1);
            rsolve_core::ResolvedPackage::new(
                subject,
                release.clone(),
                effective_dependencies,
                visible
                    .into_iter()
                    .map(|(_, repository)| repository)
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| left.name().cmp(right.name()));
    Ok(Resolution::new(request.target.clone(), packages))
}

fn identity_sort_key(identity: &rsolve_core::ReleaseIdentity) -> String {
    format!("{}:{:?}", identity.name(), identity.provenance())
}

fn canonical_subject_cmp(left: &SolverKey, right: &SolverKey) -> Ordering {
    subject_rank(left)
        .cmp(&subject_rank(right))
        .then_with(|| format!("{left:?}").cmp(&format!("{right:?}")))
}

fn subject_rank(subject: &SolverKey) -> u8 {
    match subject {
        SolverKey::InstalledName(_) => 0,
        SolverKey::Registry { .. } => 1,
        SolverKey::Bioconductor { .. } => 2,
        SolverKey::Repository { .. } => 3,
        SolverKey::Exact(_) => 4,
        SolverKey::R => 5,
    }
}

fn map_adapter_error(error: AdapterError) -> ResolutionFailure {
    ResolutionFailure::CandidateLoad {
        package: error.package,
        source: error.source,
    }
}

fn map_error(
    error: PubGrubError<Provider<'_>>,
    publication_cutoff: Option<PublicationCutoff>,
) -> ResolutionFailure {
    match error {
        PubGrubError::ErrorRetrievingDependencies { source, .. }
        | PubGrubError::ErrorChoosingVersion { source, .. }
        | PubGrubError::ErrorInShouldCancel(source) => map_adapter_error(*source),
        PubGrubError::NoSolution(tree) => ResolutionFailure::NoSolution {
            diagnostic: ResolutionDiagnostic::new(format!("{tree:?}"))
                .with_publication_policy(publication_policy_diagnostic(&tree, publication_cutoff)),
        },
    }
}

fn publication_policy_diagnostic(
    tree: &DerivationTree<PackageId, Ranges<SolverVersion>, ProviderMessage>,
    cutoff: Option<PublicationCutoff>,
) -> Option<PublicationPolicyDiagnostic> {
    let cutoff = cutoff?;
    let mut rejections = Vec::new();
    collect_publication_leaves(tree, &mut rejections);
    if rejections.is_empty() {
        return None;
    }
    rejections.sort_by(publication_rejection_cmp);
    rejections.dedup();
    Some(PublicationPolicyDiagnostic {
        cutoff,
        rejections: rejections.into_boxed_slice(),
    })
}

fn collect_publication_leaves(
    tree: &DerivationTree<PackageId, Ranges<SolverVersion>, ProviderMessage>,
    rejections: &mut Vec<PublicationRejection>,
) {
    match tree {
        DerivationTree::External(External::Custom(
            _,
            _,
            ProviderMessage::Publication {
                rejections: leaf, ..
            },
        )) => {
            rejections.extend(leaf.iter().cloned());
        }
        DerivationTree::External(_) => {}
        DerivationTree::Derived(derived) => {
            collect_publication_leaves(&derived.cause1, rejections);
            collect_publication_leaves(&derived.cause2, rejections);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pubgrub::{Derived, External};

    use super::*;

    #[test]
    fn publication_policy_evidence_deduplicates_repeated_leaves() {
        let package = rsolve_core::PackageName::new("policy").unwrap();
        let version = RPackageVersion::parse("1.0.0").unwrap();
        let identity = ReleaseIdentity::new(
            package.clone(),
            rsolve_core::Provenance::RegistryRelease {
                namespace: rsolve_core::PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        );
        let rejection = PublicationRejection::PublicationUnknown { identity };
        let leaf = DerivationTree::External(External::Custom(
            PackageId::Subject(SolverKey::InstalledName(package)),
            Ranges::singleton(SolverVersion::R(version)),
            ProviderMessage::Publication {
                rejections: vec![rejection.clone()],
            },
        ));
        let tree = DerivationTree::Derived(Derived {
            terms: Default::default(),
            shared_id: None,
            cause1: Arc::new(leaf.clone()),
            cause2: Arc::new(leaf),
        });

        let diagnostic = publication_policy_diagnostic(
            &tree,
            Some(PublicationCutoff::new(
                PublicationDate::parse("2026-06-01").unwrap(),
            )),
        )
        .unwrap();
        assert_eq!(diagnostic.rejections.as_ref(), [rejection]);
    }

    #[test]
    fn cross_branch_edges_do_not_promote_publication_to_a_failure_variant() {
        let shared_name = rsolve_core::PackageName::new("shared").unwrap();
        let policy_name = rsolve_core::PackageName::new("policychild").unwrap();
        let parent_name = rsolve_core::PackageName::new("parent").unwrap();
        let version = RPackageVersion::parse("1.0.0").unwrap();
        let shared = PackageId::Subject(SolverKey::InstalledName(shared_name));
        let policy = PackageId::Subject(SolverKey::InstalledName(policy_name.clone()));
        let parent = PackageId::Subject(SolverKey::InstalledName(parent_name));
        let rejection = PublicationRejection::PublicationUnknown {
            identity: ReleaseIdentity::new(
                policy_name,
                rsolve_core::Provenance::RegistryRelease {
                    namespace: rsolve_core::PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
        };
        let all_versions = Ranges::full();
        let unrelated_branch = DerivationTree::Derived(Derived {
            terms: Default::default(),
            shared_id: None,
            cause1: Arc::new(DerivationTree::External(External::NoVersions(
                shared.clone(),
                all_versions.clone(),
            ))),
            cause2: Arc::new(DerivationTree::External(External::FromDependencyOf(
                parent,
                all_versions.clone(),
                shared.clone(),
                all_versions.clone(),
            ))),
        });
        let publication_branch = DerivationTree::Derived(Derived {
            terms: Default::default(),
            shared_id: None,
            cause1: Arc::new(DerivationTree::External(External::FromDependencyOf(
                shared,
                all_versions.clone(),
                policy.clone(),
                all_versions.clone(),
            ))),
            cause2: Arc::new(DerivationTree::External(External::Custom(
                policy,
                all_versions,
                ProviderMessage::Publication {
                    rejections: vec![rejection.clone()],
                },
            ))),
        });
        // These branches deliberately use overlapping ranges. A flattened
        // package/edge graph would connect the NoVersions leaf to the policy
        // leaf through the sibling `shared -> policychild` edge.
        let tree = DerivationTree::Derived(Derived {
            terms: Default::default(),
            shared_id: None,
            cause1: Arc::new(unrelated_branch),
            cause2: Arc::new(publication_branch),
        });
        let cutoff = PublicationCutoff::new(PublicationDate::parse("2026-06-01").unwrap());
        let result = map_error(
            PubGrubError::<Provider<'static>>::NoSolution(tree),
            Some(cutoff),
        );
        let ResolutionFailure::NoSolution { diagnostic } = result else {
            panic!("publication evidence must not become a failure variant");
        };
        let evidence = diagnostic
            .publication_policy()
            .expect("publication leaf evidence");
        assert_eq!(evidence.cutoff, cutoff);
        assert_eq!(evidence.rejections.as_ref(), [rejection]);
    }

    fn intern_fixture_release(
        metadata: rsolve_core::ReleaseMetadata,
        channel: &str,
    ) -> PreparedCandidate {
        let package = rsolve_core::PackageName::new("fixture").unwrap();
        let version = RPackageVersion::parse("1.0.0").unwrap();
        let release = PackageRelease::try_from(rsolve_core::ReleaseObservation {
            identity: ReleaseIdentity::new(
                package.clone(),
                rsolve_core::Provenance::RegistryRelease {
                    namespace: rsolve_core::PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: package,
            observed_version: version,
            metadata,
            publication: None,
            declared_dependencies: Vec::new(),
            distributions: vec![rsolve_core::Distribution {
                registry: rsolve_core::RegistryId::new("cran").unwrap(),
                channel: rsolve_core::DistributionChannel::new(channel).unwrap(),
                snapshot: None,
                artifacts: Vec::new(),
                observed_metadata: rsolve_core::DistributionMetadata::default(),
            }],
        })
        .unwrap();
        PreparedCandidate::new(
            release,
            rsolve_core::NonRepositoryExposure::ExactOnly,
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn interning_rejects_conflicting_metadata_for_one_identity() {
        let mut interner = CandidateInterner::default();
        let first = intern_fixture_release(
            rsolve_core::ReleaseMetadata::from_pairs([("Title", "first")]).unwrap(),
            "source",
        );
        let second = intern_fixture_release(
            rsolve_core::ReleaseMetadata::from_pairs([("Title", "second")]).unwrap(),
            "source",
        );
        interner.intern(&first).unwrap();
        let error = interner.intern(&second).unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::MetadataInvalid
        );
    }

    #[test]
    fn interning_rejects_incomplete_duplicate_distribution_views() {
        let mut interner = CandidateInterner::default();
        let first = intern_fixture_release(rsolve_core::ReleaseMetadata::default(), "source");
        let second = intern_fixture_release(rsolve_core::ReleaseMetadata::default(), "binary");
        let id = interner.intern(&first).unwrap();
        let error = interner.intern(&second).unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::MetadataInvalid
        );
        assert_eq!(interner.candidates[&id].release().distributions().len(), 1);
    }
}
