use std::cell::Cell;
use std::collections::BTreeMap;

use rsolve_core::{
    CandidateAvailability, CandidateCurrentness, CandidateLoadError, CandidateLoadErrorCategory,
    CandidateLoadResult, CandidateLoader, DeclaredDependency, DependencyKind,
    DependencySourceConstraint, NonRepositoryExposure, PackageName, PackageNamespace,
    PackageRelease, PreparedCandidate, Provenance, RPackageVersion, RegistryId, ReleaseIdentity,
    ReleaseMetadata, ReleaseObservation, RepositoryId, RepositoryOccurrence, RepositoryRank,
    ResolutionRequest, ResolutionTarget, RootExpansionPolicy, RootRequirement, SolverKey,
    VersionConstraint,
};
use rsolve_resolver::{
    DefaultCandidatePreference, RequireLocked, ResolutionFailure, Resolver, Unlocked,
};

fn prepared(release: PackageRelease) -> PreparedCandidate {
    let occurrence = RepositoryOccurrence::new(
        RepositoryId::new("cran").unwrap(),
        RegistryId::new("cran").unwrap(),
        CandidateAvailability::Available,
        CandidateCurrentness::Current,
        RepositoryRank::new(0),
        release.distributions().to_vec(),
    )
    .unwrap();
    PreparedCandidate::new(release, NonRepositoryExposure::None, vec![occurrence]).unwrap()
}

#[derive(Default)]
struct FixtureLoader {
    candidates: BTreeMap<PackageName, Vec<PackageRelease>>,
    quarantined: BTreeMap<PackageName, Vec<RPackageVersion>>,
}

impl CandidateLoader for FixtureLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PreparedCandidate>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("fixture has no candidates for {package:?}"),
            ));
        };
        self.candidates
            .get(name)
            .cloned()
            .map(|releases| releases.into_iter().map(prepared).collect())
            .ok_or_else(|| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    format!("fixture has no candidates for {name}"),
                )
            })
    }

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        let candidates = self.releases(package)?;
        let SolverKey::InstalledName(name) = package else {
            unreachable!("releases already rejects non-installed names")
        };
        let quarantined = self
            .quarantined
            .get(name)
            .into_iter()
            .flatten()
            .cloned()
            .map(|version| rsolve_core::QuarantinedCandidate::new(version, "fixture quarantine"))
            .collect();
        Ok(CandidateLoadResult::new(candidates, quarantined))
    }
}

fn package(name: &str) -> PackageName {
    PackageName::new(name).unwrap()
}

fn release(name: &str, version: &str, dependencies: Vec<DeclaredDependency>) -> PackageRelease {
    let name = package(name);
    let version = RPackageVersion::parse(version).unwrap();
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
        metadata: ReleaseMetadata::default(),
        publication: None,
        declared_dependencies: dependencies,
        distributions: Vec::new(),
    })
    .unwrap()
}

fn request(requirements: Vec<DeclaredDependency>) -> ResolutionRequest {
    ResolutionRequest::without_lock(
        requirements
            .into_iter()
            .map(|dependency| RootRequirement {
                package: dependency.package,
                expansion: RootExpansionPolicy::HardOnly,
            })
            .collect(),
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        VersionConstraint::unconstrained(),
    )
}

fn any_dependency(name: &str, constraint: VersionConstraint) -> DeclaredDependency {
    DeclaredDependency::from_parts(
        DependencyKind::Depends,
        package(name),
        DependencySourceConstraint::Any,
        constraint,
    )
    .unwrap()
}

fn resolve(
    loader: &FixtureLoader,
    request: ResolutionRequest,
) -> Result<rsolve_core::Resolution, ResolutionFailure> {
    Resolver::new(loader, &DefaultCandidatePreference, &Unlocked).resolve(request)
}

struct NoCallLoader {
    calls: Cell<usize>,
}

impl CandidateLoader for NoCallLoader {
    fn releases(&self, _package: &SolverKey) -> Result<Vec<PreparedCandidate>, CandidateLoadError> {
        self.calls.set(self.calls.get() + 1);
        panic!("candidate loading must not start for unsupported root expansion")
    }
}

#[test]
fn direct_suggests_is_rejected_before_candidate_loading() {
    let loader = NoCallLoader {
        calls: Cell::new(0),
    };
    let request = ResolutionRequest::without_lock(
        vec![RootRequirement {
            package: rsolve_core::PackageRequirement::new(
                package("foo"),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )
            .unwrap(),
            expansion: RootExpansionPolicy::DirectSuggests,
        }],
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        VersionConstraint::unconstrained(),
    );
    let error = Resolver::new(&loader, &DefaultCandidatePreference, &Unlocked)
        .resolve(request)
        .unwrap_err();
    assert!(matches!(
        error,
        ResolutionFailure::UnsupportedRootExpansion {
            package: found,
            policy: RootExpansionPolicy::DirectSuggests,
        } if found == package("foo")
    ));
    assert_eq!(loader.calls.get(), 0);
}

#[test]
fn root_requirement_reports_quarantine_only_intersection() {
    let mut loader = FixtureLoader::default();
    loader
        .candidates
        .insert(package("foo"), vec![release("foo", "1.0", Vec::new())]);
    loader
        .quarantined
        .insert(package("foo"), vec![RPackageVersion::parse("2.0").unwrap()]);

    let error = resolve(
        &loader,
        request(vec![any_dependency(
            "foo",
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("2.0").unwrap(),
            ),
        )]),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ResolutionFailure::CandidateLoad { source, .. }
            if source.category() == CandidateLoadErrorCategory::MetadataInvalid
    ));
}

#[test]
fn valid_sibling_and_unrelated_mismatch_keep_normal_resolution_behavior() {
    let mut loader = FixtureLoader::default();
    loader
        .candidates
        .insert(package("foo"), vec![release("foo", "1.0", Vec::new())]);
    loader
        .quarantined
        .insert(package("foo"), vec![RPackageVersion::parse("2.0").unwrap()]);
    let success = resolve(
        &loader,
        request(vec![any_dependency(
            "foo",
            VersionConstraint::unconstrained(),
        )]),
    )
    .unwrap();
    assert_eq!(
        success
            .selected(&package("foo"))
            .unwrap()
            .version()
            .as_str(),
        "1.0"
    );

    loader.quarantined.clear();
    let error = resolve(
        &loader,
        request(vec![any_dependency(
            "foo",
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("2.0").unwrap(),
            ),
        )]),
    )
    .unwrap_err();
    assert!(matches!(error, ResolutionFailure::NoSolution { .. }));
}

#[test]
fn transitive_requirement_reports_quarantine_only_intersection() {
    let mut loader = FixtureLoader::default();
    loader.candidates.insert(
        package("top"),
        vec![release(
            "top",
            "1.0",
            vec![any_dependency(
                "child",
                VersionConstraint::from_clause(
                    rsolve_core::RelationOp::Ge,
                    RPackageVersion::parse("2.0").unwrap(),
                ),
            )],
        )],
    );
    loader
        .candidates
        .insert(package("child"), vec![release("child", "1.0", Vec::new())]);
    loader.quarantined.insert(
        package("child"),
        vec![RPackageVersion::parse("2.0").unwrap()],
    );

    let error = resolve(
        &loader,
        request(vec![any_dependency(
            "top",
            VersionConstraint::unconstrained(),
        )]),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ResolutionFailure::CandidateLoad { package: subject, source }
            if subject == SolverKey::InstalledName(package("child"))
                && source.category() == CandidateLoadErrorCategory::MetadataInvalid
    ));
}

#[test]
fn required_lock_keeps_lock_semantics_when_only_quarantine_intersects() {
    let mut loader = FixtureLoader::default();
    let candidate = release("foo", "1.0", Vec::new());
    let identity = candidate.identity().clone();
    loader.candidates.insert(package("foo"), vec![candidate]);
    loader
        .quarantined
        .insert(package("foo"), vec![RPackageVersion::parse("2.0").unwrap()]);
    let mut request = request(vec![any_dependency(
        "foo",
        VersionConstraint::from_clause(
            rsolve_core::RelationOp::Ge,
            RPackageVersion::parse("2.0").unwrap(),
        ),
    )]);
    request
        .locked
        .insert(SolverKey::InstalledName(package("foo")), identity);
    let error = Resolver::new(&loader, &DefaultCandidatePreference, &RequireLocked)
        .resolve(request)
        .unwrap_err();
    assert!(matches!(error, ResolutionFailure::NoSolution { .. }));
}
