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
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoadResult, CandidateLoader,
    DependencyKind, DependencyRequirement, DependencySourceConstraint, PackageRelease,
    PublicationCutoff, PublicationDate, RPackageVersion, RelationOp, ReleaseIdentity, Resolution,
    ResolutionRequest, SolverKey, VersionConstraint,
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
    cache: RefCell<HashMap<SolverKey, Result<CandidateLoadResult, CandidateLoadError>>>,
}

impl<'a> Provider<'a> {
    fn loaded(&self, subject: &SolverKey) -> Result<CandidateLoadResult, Box<AdapterError>> {
        if let Some(cached) = self.cache.borrow().get(subject) {
            return cached
                .clone()
                .map_err(|source| candidate_load_error(subject.clone(), source));
        }
        let result = self.loader.load(subject);
        self.cache
            .borrow_mut()
            .insert(subject.clone(), result.clone());
        result.map_err(|source| candidate_load_error(subject.clone(), source))
    }

    fn candidates(&self, subject: &SolverKey) -> Result<Vec<PackageRelease>, Box<AdapterError>> {
        Ok(self.loaded(subject)?.into_parts().0)
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
        let loaded = self.loaded(subject)?;
        let candidates = loaded.candidates().to_vec();
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
        if eligible.is_empty()
            && range.is_some_and(|range| {
                loaded
                    .quarantined()
                    .iter()
                    .any(|candidate| range.contains(candidate.version()))
            })
        {
            let versions = loaded
                .quarantined()
                .iter()
                .filter(|candidate| range.is_none_or(|range| range.contains(candidate.version())))
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
        let candidates = self.loaded(subject)?.candidates().to_vec();
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
                    return Ok(Dependencies::Unavailable(ProviderMessage::Publication {
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
    let provider = Provider {
        loader,
        preference,
        lock_policy,
        request,
        cache: RefCell::new(HashMap::new()),
    };
    let root_version = RPackageVersion::parse("0.0").expect("root version");
    let selected = resolve(&provider, PackageId::Root, root_version)
        .map_err(|error| map_error(error, request.publication_cutoff))?;

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
    tree: &DerivationTree<PackageId, Ranges<RPackageVersion>, ProviderMessage>,
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
    tree: &DerivationTree<PackageId, Ranges<RPackageVersion>, ProviderMessage>,
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
            Ranges::singleton(version),
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
}
