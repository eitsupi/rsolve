use std::collections::{BTreeMap, HashMap};

use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, DependencyKind,
    DependencyRequirement, DependencySourceConstraint, PackageName, PackageNamespace,
    PackageRelease, Provenance, RPackageVersion, ReleaseIdentity, ReleaseMetadata,
    ReleaseObservation, ResolutionRequest, ResolutionTarget, SolverKey, VersionConstraint,
};
use rsolve_resolver::{
    DefaultCandidatePreference, LockUpdatePolicy, PreferLocked, RBasePackageOverlay, RequireLocked,
    Resolver,
};

struct FixtureLoader {
    candidates: BTreeMap<PackageName, Vec<PackageRelease>>,
}

impl FixtureLoader {
    fn new(candidates: impl IntoIterator<Item = (PackageName, Vec<PackageRelease>)>) -> Self {
        Self {
            candidates: candidates.into_iter().collect(),
        }
    }
}

impl CandidateLoader for FixtureLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("fixture has no source-qualified candidates for {package:?}"),
            ));
        };
        self.candidates.get(name).cloned().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("fixture has no candidates for {name}"),
            )
        })
    }
}

fn target(version: &str) -> ResolutionTarget {
    ResolutionTarget::new(RPackageVersion::parse(version).unwrap())
}

fn package(name: &str) -> PackageName {
    PackageName::new(name).unwrap()
}

fn registry_release(
    name: &str,
    version: &str,
    dependencies: Vec<DependencyRequirement>,
) -> PackageRelease {
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
        metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
        publication: None,
        dependencies,
        distributions: Vec::new(),
    })
    .unwrap()
}

fn any_requirement(name: &str) -> DependencyRequirement {
    DependencyRequirement::new(
        DependencyKind::Depends,
        package(name),
        DependencySourceConstraint::Any,
        VersionConstraint::unconstrained(),
    )
}

fn matrix_loader() -> FixtureLoader {
    FixtureLoader::new([
        (
            package("Matrix"),
            vec![
                registry_release(
                    "Matrix",
                    "1.6-5",
                    vec![
                        DependencyRequirement::new(
                            DependencyKind::Depends,
                            package("R"),
                            DependencySourceConstraint::Any,
                            VersionConstraint::from_clause(
                                rsolve_core::RelationOp::Ge,
                                RPackageVersion::parse("3.5.0").unwrap(),
                            ),
                        ),
                        any_requirement("methods"),
                    ],
                ),
                registry_release(
                    "Matrix",
                    "1.7-0",
                    vec![
                        DependencyRequirement::new(
                            DependencyKind::Depends,
                            package("R"),
                            DependencySourceConstraint::Any,
                            VersionConstraint::from_clause(
                                rsolve_core::RelationOp::Ge,
                                RPackageVersion::parse("4.4.0").unwrap(),
                            ),
                        ),
                        any_requirement("methods"),
                    ],
                ),
            ],
        ),
        (
            package("methods"),
            vec![registry_release("methods", "4.4.0", Vec::new())],
        ),
    ])
}

fn matrix_request() -> ResolutionRequest {
    ResolutionRequest::without_lock(
        vec![any_requirement("Matrix")],
        target("4.3.3"),
        VersionConstraint::unconstrained(),
    )
}

fn resolve_with_policy<L: CandidateLoader>(
    loader: &RBasePackageOverlay<L>,
    request: ResolutionRequest,
    policy: &dyn LockUpdatePolicy,
) -> Result<rsolve_core::Resolution, rsolve_resolver::ResolutionFailure> {
    let preference = DefaultCandidatePreference;
    Resolver::new(loader, &preference, policy).resolve(request)
}

#[test]
fn selected_r_backtracks_and_base_dependency_is_not_installable() {
    let overlay =
        RBasePackageOverlay::new(matrix_loader(), RPackageVersion::parse("4.3.3").unwrap())
            .unwrap();
    let preference = DefaultCandidatePreference;
    let lock = PreferLocked;
    let resolution = Resolver::new(&overlay, &preference, &lock)
        .resolve(matrix_request())
        .unwrap();

    assert_eq!(
        resolution
            .selected(&package("Matrix"))
            .unwrap()
            .version()
            .as_str(),
        "1.6-5"
    );
    assert!(resolution.selected(&package("methods")).is_none());
}

#[test]
fn base_name_shadows_inner_candidate_and_source_qualified_keys_delegate() {
    let loader = matrix_loader();
    let overlay =
        RBasePackageOverlay::new(loader, RPackageVersion::parse("4.4.0").unwrap()).unwrap();

    let methods = overlay
        .releases(&SolverKey::InstalledName(package("methods")))
        .unwrap();
    assert_eq!(methods.len(), 1);
    assert!(methods[0].is_r_base_package());
    assert_eq!(methods[0].version().as_str(), "4.4.0");

    let matrix = overlay
        .releases(&SolverKey::InstalledName(package("Matrix")))
        .unwrap();
    assert!(!matrix[0].is_r_base_package());
    assert_eq!(
        matrix[0].identity().provenance(),
        &Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: RPackageVersion::parse("1.6-5").unwrap(),
        }
    );

    let source_qualified = overlay.releases(&SolverKey::Registry {
        namespace: PackageNamespace::new("cran").unwrap(),
        name: package("methods"),
    });
    assert!(source_qualified.is_err());
}

#[test]
fn soft_registry_lock_falls_back_to_environment_base_candidate() {
    let overlay =
        RBasePackageOverlay::new(matrix_loader(), RPackageVersion::parse("4.4.0").unwrap())
            .unwrap();
    let methods = package("methods");
    let registry_identity = registry_release("methods", "4.4.0", Vec::new())
        .identity()
        .clone();
    let mut locked = HashMap::new();
    locked.insert(SolverKey::InstalledName(methods.clone()), registry_identity);
    let request = ResolutionRequest::new(
        vec![any_requirement("methods")],
        target("4.4.0"),
        VersionConstraint::unconstrained(),
        locked,
    );

    let resolution = resolve_with_policy(&overlay, request, &PreferLocked).unwrap();
    assert!(resolution.selected(&methods).is_none());
}

#[test]
fn frozen_incompatible_registry_lock_fails() {
    let overlay =
        RBasePackageOverlay::new(matrix_loader(), RPackageVersion::parse("4.4.0").unwrap())
            .unwrap();
    let methods = package("methods");
    let registry_identity = registry_release("methods", "4.4.0", Vec::new())
        .identity()
        .clone();
    let mut locked = HashMap::new();
    locked.insert(SolverKey::InstalledName(methods), registry_identity);
    let request = ResolutionRequest::new(
        vec![any_requirement("methods")],
        target("4.4.0"),
        VersionConstraint::unconstrained(),
        locked,
    );

    assert!(matches!(
        resolve_with_policy(&overlay, request, &RequireLocked),
        Err(rsolve_resolver::ResolutionFailure::NoSolution { .. })
    ));
}
