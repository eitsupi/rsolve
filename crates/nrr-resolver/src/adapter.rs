//! Private PubGrub adapter.  No type from this module is part of nrr's API.

use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use nrr_core::{
    CandidateLoadError, CandidateLoader, DependencyKind, DependencyRequirement,
    DependencySourceConstraint, PackageRelease, RPackageVersion, RelationOp, Resolution,
    ResolutionRequest, SolverKey, VersionConstraint,
};
use pubgrub::{
    Dependencies, DependencyConstraints, DependencyProvider, PackageResolutionStatistics,
    PubGrubError, Ranges, resolve,
};

use crate::{CandidatePreference, LockDecision, LockUpdatePolicy, PreferenceContext};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum PackageId {
    Root,
    Subject(SolverKey),
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
            return cached.clone().map_err(|source| {
                Box::new(AdapterError {
                    package: subject.clone(),
                    source: Box::new(source),
                })
            });
        }
        let result = self.loader.releases(subject);
        self.cache
            .borrow_mut()
            .insert(subject.clone(), result.clone());
        result.map_err(|source| {
            Box::new(AdapterError {
                package: subject.clone(),
                source: Box::new(source),
            })
        })
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

    fn subject_for_dependency(&self, dependency: &DependencyRequirement) -> SolverKey {
        if dependency.name.as_str() == "R" {
            return SolverKey::R;
        }
        match &dependency.source {
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
                SolverKey::InstalledName(dependency.name.clone())
            }
        }
    }

    fn candidate_for_version(
        &self,
        subject: &SolverKey,
        version: &RPackageVersion,
    ) -> Result<PackageRelease, Box<AdapterError>> {
        self.candidates(subject)?
            .into_iter()
            .find(|candidate| candidate.version() == version)
            .ok_or_else(|| {
                Box::new(AdapterError {
                    package: subject.clone(),
                    source: Box::new(CandidateLoadError::new(
                        nrr_core::CandidateLoadErrorCategory::MetadataInvalid,
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
    type M = String;
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
                let candidates = self.candidates(subject)?;
                let decision = self.lock_decision(subject);
                let required = match &decision {
                    LockDecision::Require(identity) => Some(identity),
                    _ => None,
                };
                let locked = match &decision {
                    LockDecision::Prefer(identity) | LockDecision::Require(identity) => {
                        Some(identity)
                    }
                    LockDecision::Unlocked => None,
                };
                let current = self
                    .current(&candidates)
                    .map(|candidate| candidate.identity().clone());
                let context = PreferenceContext {
                    locked,
                    repository_current: current.as_ref(),
                };
                let mut compatible: Vec<_> = candidates
                    .into_iter()
                    .filter(|candidate| range.contains(candidate.version()))
                    .filter(|candidate| {
                        required
                            .as_ref()
                            .is_none_or(|identity| candidate.identity() == *identity)
                    })
                    .collect();
                compatible.sort_by(|left, right| {
                    self.preference
                        .compare(subject, left, right, &context)
                        .then_with(|| left.version().cmp(right.version()))
                        .then_with(|| {
                            format!("{:?}", left.identity()).cmp(&format!("{:?}", right.identity()))
                        })
                });
                Ok(compatible
                    .pop()
                    .map(|candidate| candidate.version().clone()))
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
                    return Ok(Dependencies::Unavailable("unknown root version".to_owned()));
                }
                let mut dependencies = Vec::new();
                dependencies.push((
                    PackageId::Subject(SolverKey::R),
                    self.ranges_for(&self.request.r_requirement),
                ));
                for requirement in &self.request.requirements {
                    dependencies.push((
                        PackageId::Subject(self.subject_for_dependency(requirement)),
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
                let release = self.candidate_for_version(subject, version)?;
                let dependencies = release
                    .dependencies()
                    .iter()
                    .filter(|dependency| {
                        matches!(
                            dependency.kind,
                            DependencyKind::Depends
                                | DependencyKind::Imports
                                | DependencyKind::LinkingTo
                        )
                    })
                    .map(|dependency| {
                        (
                            PackageId::Subject(self.subject_for_dependency(dependency)),
                            self.ranges_for(&dependency.constraint),
                        )
                    });
                Ok(Dependencies::Available(DependencyConstraints::from_iter(
                    dependencies,
                )))
            }
        }
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

    let mut packages = Vec::new();
    for (package, version) in selected {
        if let PackageId::Subject(subject) = package {
            if subject == SolverKey::R {
                continue;
            }
            let release = provider
                .candidate_for_version(&subject, &version)
                .map_err(|error| ResolutionFailure::CandidateLoad {
                    package: error.package,
                    source: error.source,
                })?;
            packages.push(nrr_core::ResolvedPackage::new(subject, release));
        }
    }
    packages.sort_by(|left, right| left.name().cmp(right.name()));
    Ok(Resolution::new(request.target.clone(), packages))
}

fn map_error(error: PubGrubError<Provider<'_>>) -> ResolutionFailure {
    match error {
        PubGrubError::ErrorRetrievingDependencies { source, .. }
        | PubGrubError::ErrorChoosingVersion { source, .. }
        | PubGrubError::ErrorInShouldCancel(source) => ResolutionFailure::CandidateLoad {
            package: source.package,
            source: source.source,
        },
        PubGrubError::NoSolution(tree) => ResolutionFailure::NoSolution {
            diagnostic: ResolutionDiagnostic::new(format!("{tree:?}")),
        },
    }
}
