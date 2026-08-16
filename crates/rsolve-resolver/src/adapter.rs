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
    DependencyRequirement, DependencySourceConstraint, PackageRelease, PublicationDate,
    RPackageVersion, RelationOp, ReleaseIdentity, Resolution, ResolutionRequest, SolverKey,
    VersionConstraint,
};

use crate::{CandidatePreference, LockDecision, LockUpdatePolicy, PreferenceContext};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum PackageId {
    Root,
    Subject(SolverKey),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProviderMessage {
    Text(String),
    Publication {
        cutoff: PublicationDate,
        rejections: Vec<PublicationRejection>,
    },
}

impl fmt::Display for ProviderMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(message) => f.write_str(message),
            Self::Publication { rejections, .. } => {
                write!(
                    f,
                    "{} publication-ineligible candidate(s)",
                    rejections.len()
                )
            }
        }
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => f.write_str("root"),
            Self::Subject(subject) => write!(f, "{subject:?}"),
        }
    }
}

#[derive(Debug)]
struct AdapterError {
    package: SolverKey,
    source: Box<CandidateLoadError>,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "loading {:#?}: {}", self.package, self.source)
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

struct Provider<'a> {
    loader: &'a dyn CandidateLoader,
    preference: &'a dyn CandidatePreference,
    lock_policy: &'a dyn LockUpdatePolicy,
    request: &'a ResolutionRequest,
    cache: RefCell<HashMap<SolverKey, Result<Vec<PackageRelease>, CandidateLoadError>>>,
}

impl<'a> Provider<'a> {
    fn candidates(&self, subject: &SolverKey) -> Result<Vec<PackageRelease>, Box<AdapterError>> {
        if let Some(cached) = self.cache.borrow().get(subject) {
            return cached
                .clone()
                .map_err(|source| candidate_load_error(subject.clone(), source));
        }
        let result = self.loader.releases(subject);
        self.cache
            .borrow_mut()
            .insert(subject.clone(), result.clone());
        result.map_err(|source| candidate_load_error(subject.clone(), source))
    }

    fn r_version(&self) -> &RPackageVersion {
        &self.request.target.r_version
    }

    fn lock_decision(&self, subject: &SolverKey) -> LockDecision {
        self.lock_policy
            .decision(subject, self.request.locked.get(subject))
    }

    fn current<'b>(&self, candidates: &'b [PackageRelease]) -> Option<&'b PackageRelease> {
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
                    format!("{:?}", left.identity()).cmp(&format!("{:?}", right.identity()))
                })
            })
    }

    fn ranges_for(&self, constraint: &VersionConstraint) -> Ranges<RPackageVersion> {
        constraint
            .clauses
            .iter()
            .map(|clause| match clause.op {
                RelationOp::Lt => Ranges::strictly_lower_than(clause.version.clone()),
                RelationOp::Le => Ranges::lower_than(clause.version.clone()),
                RelationOp::Eq => Ranges::singleton(clause.version.clone()),
                RelationOp::Ne => Ranges::singleton(clause.version.clone()).complement(),
                RelationOp::Ge => Ranges::higher_than(clause.version.clone()),
                RelationOp::Gt => Ranges::strictly_higher_than(clause.version.clone()),
            })
            .fold(Ranges::full(), |range, clause| range.intersection(&clause))
    }

    fn subject_for_dependency(
        &self,
        dependency: &DependencyRequirement,
    ) -> Result<SolverKey, Box<AdapterError>> {
        // Root requirements still report unsupported Git scopes as typed metadata
        // failures. Candidate dependencies handle this case in get_dependencies,
        // where PubGrub can reject only the candidate that declared the scope.
        if let DependencySourceConstraint::Git { .. } = &dependency.source {
            return Err(candidate_load_error(
                SolverKey::InstalledName(dependency.name.clone()),
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!(
                        "Git-sourced dependencies are not supported for package {}",
                        dependency.name
                    ),
                ),
            ));
        }
        if dependency.name.as_str() == "R" {
            return Ok(SolverKey::R);
        }
        Ok(match &dependency.source {
            DependencySourceConstraint::Any => SolverKey::InstalledName(dependency.name.clone()),
            DependencySourceConstraint::Registry { namespace } => SolverKey::Registry {
                namespace: namespace.clone(),
                name: dependency.name.clone(),
            },
            DependencySourceConstraint::Bioconductor { namespace, release } => {
                SolverKey::Bioconductor {
                    namespace: namespace.clone(),
                    release: release.clone(),
                    name: dependency.name.clone(),
                }
            }
            DependencySourceConstraint::Exact(identity) => SolverKey::Exact(identity.clone()),
            DependencySourceConstraint::Git { .. } => {
                unreachable!("Git dependencies are rejected by the caller")
            }
        })
    }

    fn with_eligible_candidates<T>(
        &self,
        subject: &SolverKey,
        range: Option<&Ranges<RPackageVersion>>,
        use_candidates: impl FnOnce(&mut Vec<PackageRelease>, &PreferenceContext<'_>) -> T,
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
        let current = self
            .current(&candidates)
            .map(|candidate| candidate.identity().clone());
        let context = PreferenceContext {
            locked: locked.as_ref(),
            repository_current: current.as_ref(),
        };
        let mut eligible: Vec<PackageRelease> = candidates
            .into_iter()
            .filter(|candidate| {
                if !required
                    .as_ref()
                    .is_none_or(|identity| candidate.identity() == *identity)
                {
                    return false;
                }
                range.is_none_or(|range| range.contains(candidate.version()))
            })
            .collect();
        if self.request.publication_cutoff.is_some() {
            let candidates_before_policy = eligible.clone();
            let rejections = self.publication_rejections(&eligible, locked.as_ref());
            if !rejections.is_empty() {
                eligible.retain(|candidate| {
                    !rejections.iter().any(|rejection| match rejection {
                        PublicationRejection::PublicationCooldown { identity, .. }
                        | PublicationRejection::PublicationUnknown { identity } => {
                            candidate.identity() == identity
                        }
                    })
                });
                // PubGrub must be allowed to inspect one rejected version so that
                // the rejection becomes an incompatibility and can backtrack.
                if eligible.is_empty() {
                    eligible = candidates_before_policy;
                }
            }
        }
        Ok(use_candidates(&mut eligible, &context))
    }

    fn publication_rejections(
        &self,
        candidates: &[PackageRelease],
        locked: Option<&ReleaseIdentity>,
    ) -> Vec<PublicationRejection> {
        let Some(cutoff) = self.request.publication_cutoff.map(|cutoff| cutoff.date()) else {
            return Vec::new();
        };
        let mut rejections = candidates
            .iter()
            .filter_map(|candidate| {
                if candidate.is_r_base_package()
                    || locked.is_some_and(|identity| candidate.identity() == identity)
                {
                    return None;
                }
                match candidate.publication() {
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

    fn publication_rejections_for_version(
        &self,
        subject: &SolverKey,
        version: &RPackageVersion,
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
        let candidates = self.candidates(subject)?;
        let matching = candidates
            .iter()
            .filter(|candidate| {
                candidate.version() == version
                    && required
                        .as_ref()
                        .is_none_or(|identity| candidate.identity() == *identity)
            })
            .cloned()
            .collect::<Vec<_>>();
        let rejections = self.publication_rejections(&matching, locked.as_ref());
        if rejections.is_empty() {
            return Ok(rejections);
        }
        if matching.iter().any(|candidate| {
            !rejections.iter().any(|rejection| match rejection {
                PublicationRejection::PublicationCooldown { identity, .. }
                | PublicationRejection::PublicationUnknown { identity } => {
                    candidate.identity() == identity
                }
            })
        }) {
            return Ok(Vec::new());
        }
        Ok(rejections)
    }

    fn compare_candidates(
        &self,
        subject: &SolverKey,
        left: &PackageRelease,
        right: &PackageRelease,
        context: &PreferenceContext<'_>,
    ) -> Ordering {
        self.preference
            .compare(subject, left, right, context)
            .then_with(|| left.version().cmp(right.version()))
            .then_with(|| format!("{:?}", left.identity()).cmp(&format!("{:?}", right.identity())))
    }

    fn sort_candidates(
        &self,
        subject: &SolverKey,
        candidates: &mut [PackageRelease],
        context: &PreferenceContext<'_>,
    ) {
        candidates.sort_by(|left, right| self.compare_candidates(subject, left, right, context));
    }

    // Candidate identity is currently canonicalized per (subject, version), so a same-version
    // alternative from a different provenance is not independently selectable within one subject.
    // A source-qualified subject and an installed-name subject can still select different
    // identities; solve() enforces installed-name occupancy after PubGrub returns and fails
    // closed without trying an alternative. Making candidate identity a first-class part of the
    // solver package/version domain remains a future solver design question.
    fn candidate_for_version(
        &self,
        subject: &SolverKey,
        version: &RPackageVersion,
    ) -> Result<PackageRelease, Box<AdapterError>> {
        let range = Ranges::singleton(version.clone());
        let candidate =
            self.with_eligible_candidates(subject, Some(&range), |eligible, context| {
                self.sort_candidates(subject, eligible, context);
                eligible.pop()
            })?;
        candidate.ok_or_else(|| {
            Box::new(AdapterError {
                package: subject.clone(),
                source: Box::new(CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("selected version {version} was not in the loaded catalog"),
                )),
            })
        })
    }
}

impl DependencyProvider for Provider<'_> {
    type P = PackageId;
    type V = RPackageVersion;
    type VS = Ranges<RPackageVersion>;
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
            PackageId::Subject(SolverKey::R) => usize::from(range.contains(self.r_version())),
            PackageId::Subject(subject) => self
                .candidates(subject)
                .map(|candidates| {
                    candidates
                        .iter()
                        .filter(|candidate| range.contains(candidate.version()))
                        .count()
                })
                .unwrap_or(usize::MAX),
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
                .contains(&RPackageVersion::parse("0.0").expect("root version"))
                .then(|| RPackageVersion::parse("0.0").expect("root version"))),
            PackageId::Subject(SolverKey::R) => Ok(range
                .contains(self.r_version())
                .then(|| self.r_version().clone())),
            PackageId::Subject(subject) => {
                self.with_eligible_candidates(subject, Some(range), |eligible, context| {
                    self.sort_candidates(subject, eligible, context);
                    eligible.pop().map(|candidate| candidate.version().clone())
                })
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
                let root_version = RPackageVersion::parse("0.0").expect("root version");
                if version != &root_version {
                    return Ok(Dependencies::Unavailable(ProviderMessage::Text(
                        "unknown root version".to_owned(),
                    )));
                }
                let mut dependencies = Vec::new();
                dependencies.push((
                    PackageId::Subject(SolverKey::R),
                    self.ranges_for(&self.request.r_requirement),
                ));
                for requirement in &self.request.requirements {
                    dependencies.push((
                        PackageId::Subject(self.subject_for_dependency(requirement)?),
                        self.ranges_for(&requirement.constraint),
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
                let rejections = self.publication_rejections_for_version(subject, version)?;
                if !rejections.is_empty() {
                    let cutoff = self
                        .request
                        .publication_cutoff
                        .expect("publication rejections require a cutoff")
                        .date();
                    return Ok(Dependencies::Unavailable(ProviderMessage::Publication {
                        cutoff,
                        rejections,
                    }));
                }
                let release = self.candidate_for_version(subject, version)?;
                let mut dependencies = Vec::new();
                for dependency in release.dependencies().iter().filter(|dependency| {
                    matches!(
                        dependency.kind,
                        DependencyKind::Depends
                            | DependencyKind::Imports
                            | DependencyKind::LinkingTo
                    )
                }) {
                    if let DependencySourceConstraint::Git { .. } = &dependency.source {
                        return Ok(Dependencies::Unavailable(ProviderMessage::Text(format!(
                            "Git-sourced dependencies are not supported for package {}",
                            dependency.name
                        ))));
                    }
                    dependencies.push((
                        PackageId::Subject(self.subject_for_dependency(dependency)?),
                        self.ranges_for(&dependency.constraint),
                    ));
                }
                Ok(Dependencies::Available(DependencyConstraints::from_iter(
                    dependencies,
                )))
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolutionFailure {
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
    PublicationIneligible {
        cutoff: PublicationDate,
        rejections: Box<[PublicationRejection]>,
    },
    Solver {
        diagnostic: ResolutionDiagnostic,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionDiagnostic {
    pub summary: Box<str>,
}

impl ResolutionDiagnostic {
    fn new(summary: impl Into<Box<str>>) -> Self {
        Self {
            summary: summary.into(),
        }
    }
}

impl fmt::Display for ResolutionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CandidateLoad { package, source } => {
                write!(f, "candidate load for {package:?} failed: {source}")
            }
            Self::NoSolution { diagnostic } => write!(f, "no resolution: {}", diagnostic.summary),
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
            Self::PublicationIneligible { cutoff, rejections } => write!(
                f,
                "publication cutoff {cutoff} rejected {} candidate(s)",
                rejections.len()
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
    let provider = Provider {
        loader,
        preference,
        lock_policy,
        request,
        cache: RefCell::new(HashMap::new()),
    };
    let root_version = RPackageVersion::parse("0.0").expect("root version");
    let selected = resolve(&provider, PackageId::Root, root_version).map_err(map_error)?;

    let mut packages = BTreeMap::<rsolve_core::PackageName, (SolverKey, PackageRelease)>::new();
    for (package, version) in selected {
        if let PackageId::Subject(subject) = package {
            if subject == SolverKey::R {
                continue;
            }
            let release = provider
                .candidate_for_version(&subject, &version)
                .map_err(|error| map_adapter_error(*error))?;
            if release.is_r_base_package() {
                continue;
            }
            let name = release.identity().name().clone();
            match packages.entry(name.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((subject, release));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let (existing_subject, existing_release) = entry.get();
                    if existing_release.identity() != release.identity() {
                        let (first_identity, second_identity) =
                            if identity_sort_key(existing_release.identity())
                                <= identity_sort_key(release.identity())
                            {
                                (
                                    existing_release.identity().clone(),
                                    release.identity().clone(),
                                )
                            } else {
                                (
                                    release.identity().clone(),
                                    existing_release.identity().clone(),
                                )
                            };
                        return Err(ResolutionFailure::InstalledNameConflict {
                            name,
                            first_identity: Box::new(first_identity),
                            second_identity: Box::new(second_identity),
                        });
                    }
                    if canonical_subject_cmp(&subject, existing_subject) == Ordering::Less {
                        entry.insert((subject, release));
                    }
                }
            }
        }
    }
    let mut packages = packages
        .into_values()
        .map(|(subject, release)| rsolve_core::ResolvedPackage::new(subject, release))
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
        SolverKey::Exact(_) => 3,
        SolverKey::R => 4,
    }
}

fn map_adapter_error(error: AdapterError) -> ResolutionFailure {
    ResolutionFailure::CandidateLoad {
        package: error.package,
        source: error.source,
    }
}

fn map_error(error: PubGrubError<Provider<'_>>) -> ResolutionFailure {
    match error {
        PubGrubError::ErrorRetrievingDependencies { source, .. }
        | PubGrubError::ErrorChoosingVersion { source, .. }
        | PubGrubError::ErrorInShouldCancel(source) => map_adapter_error(*source),
        PubGrubError::NoSolution(tree) => {
            publication_failure_from_tree(&tree).unwrap_or_else(|| ResolutionFailure::NoSolution {
                diagnostic: ResolutionDiagnostic::new(format!("{tree:?}")),
            })
        }
    }
}

fn publication_failure_from_tree(
    tree: &DerivationTree<PackageId, Ranges<RPackageVersion>, ProviderMessage>,
) -> Option<ResolutionFailure> {
    let mut reasons = Vec::new();
    collect_publication_rejections(tree, &mut reasons);
    if reasons.is_empty() {
        return None;
    }
    reasons.sort_by(|left, right| {
        left.0.cmp(&right.0).then_with(|| {
            publication_rejection_sort_key(&left.1).cmp(&publication_rejection_sort_key(&right.1))
        })
    });
    reasons.dedup();
    let cutoff = reasons[0].0;
    let rejections = reasons
        .into_iter()
        .map(|(_, rejection)| rejection)
        .collect();
    Some(ResolutionFailure::PublicationIneligible { cutoff, rejections })
}

fn collect_publication_rejections(
    tree: &DerivationTree<PackageId, Ranges<RPackageVersion>, ProviderMessage>,
    reasons: &mut Vec<(PublicationDate, PublicationRejection)>,
) {
    match tree {
        DerivationTree::External(External::Custom(
            _,
            _,
            ProviderMessage::Publication { cutoff, rejections },
        )) => reasons.extend(
            rejections
                .iter()
                .cloned()
                .map(|rejection| (*cutoff, rejection)),
        ),
        DerivationTree::External(_) => {}
        DerivationTree::Derived(derived) => {
            collect_publication_rejections(&derived.cause1, reasons);
            collect_publication_rejections(&derived.cause2, reasons);
        }
    }
}
