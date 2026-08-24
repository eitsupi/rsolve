use std::collections::BTreeMap;

use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoadResult, CandidateLoader,
    DependencyKind, DependencyRequirement, DependencySourceConstraint, PackageName,
    PackageNamespace, PackageRelease, Provenance, RPackageVersion, ReleaseIdentity,
    ReleaseMetadata, ReleaseObservation, ResolutionRequest, ResolutionTarget, SolverKey,
    VersionConstraint,
};
use rsolve_resolver::{DefaultCandidatePreference, ResolutionFailure, Resolver, Unlocked};

#[derive(Default)]
struct FixtureLoader {
    candidates: BTreeMap<PackageName, Vec<PackageRelease>>,
    quarantined: BTreeMap<PackageName, Vec<RPackageVersion>>,
}

impl CandidateLoader for FixtureLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("fixture has no candidates for {package:?}"),
            ));
        };
        self.candidates.get(name).cloned().ok_or_else(|| {
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

fn release(name: &str, version: &str, dependencies: Vec<DependencyRequirement>) -> PackageRelease {
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
        dependencies,
        distributions: Vec::new(),
    })
    .unwrap()
}

fn request(requirements: Vec<DependencyRequirement>) -> ResolutionRequest {
    ResolutionRequest::without_lock(
        requirements,
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        VersionConstraint::unconstrained(),
    )
}

fn any_dependency(name: &str, constraint: VersionConstraint) -> DependencyRequirement {
    DependencyRequirement::new(
        DependencyKind::Depends,
        package(name),
        DependencySourceConstraint::Any,
        constraint,
    )
}

fn resolve(
    loader: &FixtureLoader,
    request: ResolutionRequest,
) -> Result<rsolve_core::Resolution, ResolutionFailure> {
    Resolver::new(loader, &DefaultCandidatePreference, &Unlocked).resolve(request)
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
