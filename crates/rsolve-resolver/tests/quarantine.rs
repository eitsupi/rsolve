use std::collections::BTreeMap;

use rsolve_core::{
    CandidateAvailability, CandidateCurrentness, CandidateLoadError, CandidateLoadErrorCategory,
    CandidateLoadResult, CandidateLoader, DeclaredDependency, DependencyKind,
    DependencySourceConstraint, NonRepositoryExposure, PackageName, PackageNamespace,
    PackageRelease, PackageRequirement, PreparedCandidate, Provenance, RPackageVersion, RegistryId,
    ReleaseIdentity, ReleaseMetadata, ReleaseObservation, RepositoryId, RepositoryOccurrence,
    RepositoryRank, ResolutionRequest, ResolutionTarget, RootExpansionPolicy, RootRequirement,
    SolverKey, VersionConstraint,
};
use rsolve_resolver::{
    DefaultCandidatePreference, RequireLocked, ResolutionFailure, Resolver, Unlocked,
};

fn prepared(release: PackageRelease) -> PreparedCandidate {
    prepared_with_currentness(release, CandidateCurrentness::Current)
}

fn prepared_with_currentness(
    release: PackageRelease,
    currentness: CandidateCurrentness,
) -> PreparedCandidate {
    let occurrence = RepositoryOccurrence::new(
        RepositoryId::new("cran").unwrap(),
        RegistryId::new("cran").unwrap(),
        CandidateAvailability::Available,
        currentness,
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
        let name = match package {
            SolverKey::InstalledName(name)
            | SolverKey::Registry { name, .. }
            | SolverKey::Repository { name, .. } => name,
            _ => {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    format!("fixture has no candidates for {package:?}"),
                ));
            }
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
        let name = match package {
            SolverKey::InstalledName(name)
            | SolverKey::Registry { name, .. }
            | SolverKey::Repository { name, .. } => name,
            _ => unreachable!("releases already rejects this subject"),
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

#[derive(Default)]
struct PreparedFixtureLoader {
    candidates: BTreeMap<PackageName, Vec<PreparedCandidate>>,
}

impl CandidateLoader for PreparedFixtureLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PreparedCandidate>, CandidateLoadError> {
        let name = match package {
            SolverKey::InstalledName(name)
            | SolverKey::Registry { name, .. }
            | SolverKey::Repository { name, .. } => name,
            _ => {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    format!("fixture has no candidates for {package:?}"),
                ));
            }
        };
        self.candidates.get(name).cloned().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("fixture has no candidates for {name}"),
            )
        })
    }
}

fn package(name: &str) -> PackageName {
    PackageName::new(name).unwrap()
}

fn release(name: &str, version: &str, dependencies: Vec<DeclaredDependency>) -> PackageRelease {
    release_with_namespace(name, version, "cran", dependencies)
}

fn release_with_namespace(
    name: &str,
    version: &str,
    namespace: &str,
    dependencies: Vec<DeclaredDependency>,
) -> PackageRelease {
    let name = package(name);
    let version = RPackageVersion::parse(version).unwrap();
    PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            name.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new(namespace).unwrap(),
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
    request_with_expansion(requirements, RootExpansionPolicy::HardOnly)
}

fn request_with_expansion(
    requirements: Vec<DeclaredDependency>,
    expansion: RootExpansionPolicy,
) -> ResolutionRequest {
    ResolutionRequest::without_lock(
        requirements
            .into_iter()
            .map(|dependency| RootRequirement {
                package: dependency.package,
                expansion,
            })
            .collect(),
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        VersionConstraint::unconstrained(),
    )
}

fn any_dependency(name: &str, constraint: VersionConstraint) -> DeclaredDependency {
    dependency(DependencyKind::Depends, name, constraint)
}

fn dependency(
    kind: DependencyKind,
    name: &str,
    constraint: VersionConstraint,
) -> DeclaredDependency {
    DeclaredDependency::from_parts(
        kind,
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
    resolve_with_loader(loader, request)
}

fn resolve_with_loader(
    loader: &dyn CandidateLoader,
    request: ResolutionRequest,
) -> Result<rsolve_core::Resolution, ResolutionFailure> {
    Resolver::new(loader, &DefaultCandidatePreference, &Unlocked).resolve(request)
}

#[test]
fn direct_suggests_changes_the_root_candidate_closure() {
    let mut loader = FixtureLoader::default();
    loader.candidates.insert(
        package("foo"),
        vec![
            release(
                "foo",
                "1.0",
                vec![dependency(
                    DependencyKind::Suggests,
                    "optionalone",
                    VersionConstraint::unconstrained(),
                )],
            ),
            release(
                "foo",
                "2.0",
                vec![
                    dependency(
                        DependencyKind::Suggests,
                        "optionaltwo",
                        VersionConstraint::unconstrained(),
                    ),
                    dependency(
                        DependencyKind::Enhances,
                        "optionalignored",
                        VersionConstraint::unconstrained(),
                    ),
                ],
            ),
        ],
    );
    for name in ["optionalone", "optionaltwo", "optionalignored"] {
        loader
            .candidates
            .insert(package(name), vec![release(name, "1.0", Vec::new())]);
    }

    let hard_only = resolve(
        &loader,
        request(vec![any_dependency(
            "foo",
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Eq,
                RPackageVersion::parse("2.0").unwrap(),
            ),
        )]),
    )
    .unwrap();
    assert!(hard_only.selected(&package("optionaltwo")).is_none());
    assert!(
        hard_only
            .packages()
            .iter()
            .find(|candidate| candidate.name() == &package("foo"))
            .unwrap()
            .effective_dependencies()
            .is_empty()
    );

    let direct_v1 = resolve(
        &loader,
        request_with_expansion(
            vec![any_dependency(
                "foo",
                VersionConstraint::from_clause(
                    rsolve_core::RelationOp::Eq,
                    RPackageVersion::parse("1.0").unwrap(),
                ),
            )],
            RootExpansionPolicy::DirectSuggests,
        ),
    )
    .unwrap();
    assert_eq!(
        direct_v1
            .selected(&package("optionalone"))
            .unwrap()
            .version()
            .as_str(),
        "1.0"
    );
    assert_eq!(
        direct_v1
            .packages()
            .iter()
            .find(|candidate| candidate.name() == &package("foo"))
            .unwrap()
            .effective_dependencies()[0]
            .kind,
        rsolve_core::EffectiveDependencyKind::PromotedSuggests
    );

    let direct_v2 = resolve(
        &loader,
        request_with_expansion(
            vec![any_dependency(
                "foo",
                VersionConstraint::from_clause(
                    rsolve_core::RelationOp::Eq,
                    RPackageVersion::parse("2.0").unwrap(),
                ),
            )],
            RootExpansionPolicy::DirectSuggests,
        ),
    )
    .unwrap();
    assert!(direct_v2.selected(&package("optionalone")).is_none());
    assert!(direct_v2.selected(&package("optionalignored")).is_none());
    assert_eq!(
        direct_v2
            .selected(&package("optionaltwo"))
            .unwrap()
            .version()
            .as_str(),
        "1.0"
    );
    let v2_reasons = direct_v2
        .packages()
        .iter()
        .find(|candidate| candidate.name() == &package("foo"))
        .unwrap()
        .effective_dependencies();
    assert_eq!(v2_reasons.len(), 1);
    assert_eq!(
        v2_reasons[0].kind,
        rsolve_core::EffectiveDependencyKind::PromotedSuggests
    );
}

#[test]
fn assignment_comparison_reports_promoted_suggests_constraint_violation() {
    let mut loader = FixtureLoader::default();
    loader.candidates.insert(
        package("foo"),
        vec![
            release(
                "foo",
                "1.0",
                vec![dependency(
                    DependencyKind::Suggests,
                    "child",
                    VersionConstraint::from_clause(
                        rsolve_core::RelationOp::Ge,
                        RPackageVersion::parse("2.0").unwrap(),
                    ),
                )],
            ),
            release(
                "foo",
                "2.0",
                vec![any_dependency(
                    "child",
                    VersionConstraint::from_clause(
                        rsolve_core::RelationOp::Eq,
                        RPackageVersion::parse("1.0").unwrap(),
                    ),
                )],
            ),
        ],
    );
    loader
        .candidates
        .insert(package("child"), vec![release("child", "1.0", Vec::new())]);
    let request = request_with_expansion(
        vec![any_dependency("foo", VersionConstraint::unconstrained())],
        RootExpansionPolicy::DirectSuggests,
    );
    let compared = Resolver::new(&loader, &DefaultCandidatePreference, &Unlocked)
        .resolve_with_assignment_comparison(request)
        .unwrap();
    let foo = compared
        .comparison
        .assignments
        .iter()
        .find(|assignment| {
            assignment.subject == rsolve_resolver::DecisionSubject::InstalledName(package("foo"))
        })
        .unwrap();
    assert!(foo.alternatives.iter().any(|alternative| {
        matches!(
            alternative.differs_by,
            rsolve_resolver::AssignmentDifference::ConstraintViolatedByAssignment {
                against: rsolve_resolver::DecisionSubject::InstalledName(ref name),
                ..
            } if name == &package("child")
        )
    }));
}

#[test]
fn source_qualified_direct_suggests_can_be_only_statically_compatible() {
    let mut loader = PreparedFixtureLoader::default();
    let compatible = release_with_namespace(
        "foo",
        "1.0",
        "cran",
        vec![dependency(
            DependencyKind::Suggests,
            "R",
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("4.0").unwrap(),
            ),
        )],
    );
    let incompatible = release_with_namespace(
        "foo",
        "1.0",
        "other",
        vec![dependency(
            DependencyKind::Suggests,
            "R",
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("5.0").unwrap(),
            ),
        )],
    );
    loader.candidates.insert(
        package("foo"),
        vec![
            prepared_with_currentness(incompatible, CandidateCurrentness::Historical),
            prepared_with_currentness(compatible, CandidateCurrentness::Historical),
        ],
    );
    let request = ResolutionRequest::without_lock(
        vec![RootRequirement {
            package: PackageRequirement::new(
                package("foo"),
                DependencySourceConstraint::Repository {
                    repository: RepositoryId::new("cran").unwrap(),
                },
                VersionConstraint::unconstrained(),
            )
            .unwrap(),
            expansion: RootExpansionPolicy::DirectSuggests,
        }],
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        VersionConstraint::unconstrained(),
    );
    let compared = Resolver::new(&loader, &DefaultCandidatePreference, &Unlocked)
        .resolve_with_assignment_comparison(request)
        .unwrap();
    let foo = compared
        .comparison
        .assignments
        .iter()
        .find(|assignment| {
            assignment.subject == rsolve_resolver::DecisionSubject::Package(package("foo"))
        })
        .unwrap();
    assert_eq!(
        foo.basis,
        rsolve_resolver::AssignmentBasis::OnlyStaticallyCompatible
    );
}

#[test]
fn merged_subject_comparison_uses_direct_suggests_from_same_name_root() {
    let mut loader = FixtureLoader::default();
    loader.candidates.insert(
        package("A"),
        vec![release(
            "A",
            "1.0",
            vec![any_dependency("Foo", VersionConstraint::unconstrained())],
        )],
    );
    loader.candidates.insert(
        package("Foo"),
        vec![
            release(
                "Foo",
                "1.0",
                vec![dependency(
                    DependencyKind::Suggests,
                    "child",
                    VersionConstraint::from_clause(
                        rsolve_core::RelationOp::Ge,
                        RPackageVersion::parse("2.0").unwrap(),
                    ),
                )],
            ),
            release(
                "Foo",
                "2.0",
                vec![
                    any_dependency(
                        "child",
                        VersionConstraint::from_clause(
                            rsolve_core::RelationOp::Eq,
                            RPackageVersion::parse("1.0").unwrap(),
                        ),
                    ),
                    dependency(
                        DependencyKind::Suggests,
                        "child",
                        VersionConstraint::from_clause(
                            rsolve_core::RelationOp::Eq,
                            RPackageVersion::parse("1.0").unwrap(),
                        ),
                    ),
                ],
            ),
        ],
    );
    loader
        .candidates
        .insert(package("child"), vec![release("child", "1.0", Vec::new())]);
    let request = ResolutionRequest::without_lock(
        vec![
            RootRequirement {
                package: PackageRequirement::new(
                    package("A"),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                )
                .unwrap(),
                expansion: RootExpansionPolicy::HardOnly,
            },
            RootRequirement {
                package: PackageRequirement::new(
                    package("Foo"),
                    DependencySourceConstraint::Repository {
                        repository: RepositoryId::new("cran").unwrap(),
                    },
                    VersionConstraint::unconstrained(),
                )
                .unwrap(),
                expansion: RootExpansionPolicy::DirectSuggests,
            },
        ],
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        VersionConstraint::unconstrained(),
    );
    let compared = Resolver::new(&loader, &DefaultCandidatePreference, &Unlocked)
        .resolve_with_assignment_comparison(request)
        .unwrap();
    let foo = compared
        .resolution
        .packages()
        .iter()
        .find(|candidate| candidate.name() == &package("Foo"))
        .unwrap();
    assert!(
        foo.effective_dependencies()
            .iter()
            .any(|edge| { edge.kind == rsolve_core::EffectiveDependencyKind::PromotedSuggests })
    );
    let assignment = compared
        .comparison
        .assignments
        .iter()
        .find(|assignment| {
            assignment.subject == rsolve_resolver::DecisionSubject::InstalledName(package("Foo"))
        })
        .unwrap();
    assert!(assignment.alternatives.iter().any(|alternative| {
        matches!(
            alternative.differs_by,
            rsolve_resolver::AssignmentDifference::ConstraintViolatedByAssignment {
                against: rsolve_resolver::DecisionSubject::InstalledName(ref name),
                ..
            } if name == &package("child")
        )
    }));
}

#[test]
fn promoted_suggests_are_not_recursive() {
    let mut loader = FixtureLoader::default();
    loader.candidates.insert(
        package("foo"),
        vec![release(
            "foo",
            "1.0",
            vec![dependency(
                DependencyKind::Suggests,
                "bar",
                VersionConstraint::unconstrained(),
            )],
        )],
    );
    loader.candidates.insert(
        package("bar"),
        vec![release(
            "bar",
            "1.0",
            vec![dependency(
                DependencyKind::Suggests,
                "baz",
                VersionConstraint::unconstrained(),
            )],
        )],
    );
    loader
        .candidates
        .insert(package("baz"), vec![release("baz", "1.0", Vec::new())]);

    let resolution = resolve_with_loader(
        &loader,
        request_with_expansion(
            vec![any_dependency("foo", VersionConstraint::unconstrained())],
            RootExpansionPolicy::DirectSuggests,
        ),
    )
    .unwrap();
    assert!(resolution.selected(&package("bar")).is_some());
    assert!(resolution.selected(&package("baz")).is_none());
}

#[test]
fn hard_and_promoted_suggests_keep_both_reasons_and_constraints() {
    let mut loader = FixtureLoader::default();
    loader.candidates.insert(
        package("foo"),
        vec![release(
            "foo",
            "1.0",
            vec![
                dependency(
                    DependencyKind::Depends,
                    "target",
                    VersionConstraint::from_clause(
                        rsolve_core::RelationOp::Ge,
                        RPackageVersion::parse("2.0").unwrap(),
                    ),
                ),
                dependency(
                    DependencyKind::Suggests,
                    "target",
                    VersionConstraint::from_clause(
                        rsolve_core::RelationOp::Lt,
                        RPackageVersion::parse("3.0").unwrap(),
                    ),
                ),
            ],
        )],
    );
    loader.candidates.insert(
        package("target"),
        vec![
            release("target", "1.0", Vec::new()),
            release("target", "2.0", Vec::new()),
            release("target", "3.0", Vec::new()),
        ],
    );

    let resolution = resolve_with_loader(
        &loader,
        request_with_expansion(
            vec![any_dependency("foo", VersionConstraint::unconstrained())],
            RootExpansionPolicy::DirectSuggests,
        ),
    )
    .unwrap();
    assert_eq!(
        resolution
            .selected(&package("target"))
            .unwrap()
            .version()
            .as_str(),
        "2.0"
    );
    let reasons = resolution
        .packages()
        .iter()
        .find(|candidate| candidate.name() == &package("foo"))
        .unwrap()
        .effective_dependencies();
    assert_eq!(reasons.len(), 2);
    assert_eq!(
        reasons[0].kind,
        rsolve_core::EffectiveDependencyKind::Depends
    );
    assert_eq!(
        reasons[1].kind,
        rsolve_core::EffectiveDependencyKind::PromotedSuggests
    );
}

#[test]
fn direct_suggests_cycles_are_solved_when_each_root_opts_in() {
    let mut loader = FixtureLoader::default();
    loader.candidates.insert(
        package("foo"),
        vec![release(
            "foo",
            "1.0",
            vec![dependency(
                DependencyKind::Suggests,
                "bar",
                VersionConstraint::unconstrained(),
            )],
        )],
    );
    loader.candidates.insert(
        package("bar"),
        vec![release(
            "bar",
            "1.0",
            vec![dependency(
                DependencyKind::Suggests,
                "foo",
                VersionConstraint::unconstrained(),
            )],
        )],
    );

    let resolution = resolve_with_loader(
        &loader,
        request_with_expansion(
            vec![
                any_dependency("foo", VersionConstraint::unconstrained()),
                any_dependency("bar", VersionConstraint::unconstrained()),
            ],
            RootExpansionPolicy::DirectSuggests,
        ),
    )
    .unwrap();
    assert!(resolution.selected(&package("foo")).is_some());
    assert!(resolution.selected(&package("bar")).is_some());
}

#[test]
fn promoted_r_base_is_not_installable_and_recommended_package_remains_normal() {
    let mut loader = FixtureLoader::default();
    loader.candidates.insert(
        package("foo"),
        vec![release(
            "foo",
            "1.0",
            vec![
                dependency(
                    DependencyKind::Suggests,
                    "base",
                    VersionConstraint::unconstrained(),
                ),
                dependency(
                    DependencyKind::Suggests,
                    "Matrix",
                    VersionConstraint::unconstrained(),
                ),
            ],
        )],
    );
    loader.candidates.insert(
        package("Matrix"),
        vec![release("Matrix", "1.0", Vec::new())],
    );
    let overlay =
        rsolve_resolver::RBasePackageOverlay::new(loader, RPackageVersion::parse("4.4.0").unwrap())
            .unwrap();
    let resolution = resolve_with_loader(
        &overlay,
        request_with_expansion(
            vec![any_dependency("foo", VersionConstraint::unconstrained())],
            RootExpansionPolicy::DirectSuggests,
        ),
    )
    .unwrap();
    assert!(resolution.selected(&package("base")).is_none());
    assert_eq!(
        resolution
            .selected(&package("Matrix"))
            .unwrap()
            .version()
            .as_str(),
        "1.0"
    );
}

#[test]
fn quarantined_promoted_suggests_fail_closed() {
    let mut loader = FixtureLoader::default();
    loader.candidates.insert(
        package("foo"),
        vec![release(
            "foo",
            "1.0",
            vec![dependency(
                DependencyKind::Suggests,
                "optional",
                VersionConstraint::from_clause(
                    rsolve_core::RelationOp::Ge,
                    RPackageVersion::parse("2.0").unwrap(),
                ),
            )],
        )],
    );
    loader.candidates.insert(
        package("optional"),
        vec![release("optional", "1.0", Vec::new())],
    );
    loader.quarantined.insert(
        package("optional"),
        vec![RPackageVersion::parse("2.0").unwrap()],
    );

    let error = resolve_with_loader(
        &loader,
        request_with_expansion(
            vec![any_dependency("foo", VersionConstraint::unconstrained())],
            RootExpansionPolicy::DirectSuggests,
        ),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ResolutionFailure::CandidateLoad { source, .. }
            if source.category() == CandidateLoadErrorCategory::MetadataInvalid
    ));
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
