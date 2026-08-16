use std::collections::{BTreeMap, HashMap};

use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, DependencyKind,
    DependencyRequirement, DependencySourceConstraint, PackageName, PackageRelease, Provenance,
    PublicationCutoff, PublicationDate, ReleaseIdentity, ReleaseMetadata, ReleaseObservation,
    ResolutionRequest, ResolutionTarget, SolverKey, Target, VersionConstraint,
};
use rsolve_resolver::{
    AssignmentDifference, DefaultCandidatePreference, LockUpdatePolicy, PreferLocked,
    PublicationRejection, RBasePackageOverlay, RequireLocked, ResolutionFailure, Resolver,
};

struct FixtureLoader {
    candidates: BTreeMap<PackageName, Vec<PackageRelease>>,
}

impl CandidateLoader for FixtureLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                "fixture has no source-qualified candidates",
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

fn package(name: &str) -> PackageName {
    PackageName::new(name).unwrap()
}

fn date(value: &str) -> PublicationDate {
    PublicationDate::parse(value).unwrap()
}

fn target() -> ResolutionTarget {
    ResolutionTarget::new(
        rsolve_core::RPackageVersion::parse("4.4.0").unwrap(),
        Target::new("linux", "x86_64"),
    )
}

fn release(name: &str, version: &str, publication: Option<&str>) -> PackageRelease {
    release_with_dependencies(name, version, publication, Vec::new())
}

fn release_with_dependencies(
    name: &str,
    version: &str,
    publication: Option<&str>,
    dependencies: Vec<DependencyRequirement>,
) -> PackageRelease {
    release_with_namespace(name, version, publication, "cran", dependencies)
}

fn release_with_namespace(
    name: &str,
    version: &str,
    publication: Option<&str>,
    namespace: &str,
    dependencies: Vec<DependencyRequirement>,
) -> PackageRelease {
    let name = package(name);
    let version = rsolve_core::RPackageVersion::parse(version).unwrap();
    PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            name.clone(),
            Provenance::RegistryRelease {
                namespace: rsolve_core::PackageNamespace::new(namespace).unwrap(),
                version: version.clone(),
            },
        ),
        observed_package: name,
        observed_version: version,
        metadata: ReleaseMetadata::default(),
        publication: publication.map(|value| rsolve_core::ReleasePublication::new(date(value))),
        dependencies,
        distributions: Vec::new(),
    })
    .unwrap()
}

fn request(name: &str, locked: HashMap<SolverKey, ReleaseIdentity>) -> ResolutionRequest {
    request_with_constraint(name, VersionConstraint::unconstrained(), locked)
}

fn request_with_constraint(
    name: &str,
    constraint: VersionConstraint,
    locked: HashMap<SolverKey, ReleaseIdentity>,
) -> ResolutionRequest {
    ResolutionRequest::new(
        vec![DependencyRequirement::new(
            DependencyKind::Depends,
            package(name),
            DependencySourceConstraint::Any,
            constraint,
        )],
        target(),
        VersionConstraint::unconstrained(),
        locked,
    )
    .with_publication_cutoff(PublicationCutoff::new(date("2026-06-01")))
}

fn resolve<L: CandidateLoader>(
    loader: &L,
    policy: &dyn LockUpdatePolicy,
    request: ResolutionRequest,
) -> Result<rsolve_core::Resolution, ResolutionFailure> {
    let preference = DefaultCandidatePreference;
    Resolver::new(loader, &preference, policy).resolve(request)
}

fn compare<L: CandidateLoader>(
    loader: &L,
    policy: &dyn LockUpdatePolicy,
    request: ResolutionRequest,
) -> Result<rsolve_resolver::ComparedResolution, ResolutionFailure> {
    let preference = DefaultCandidatePreference;
    Resolver::new(loader, &preference, policy).resolve_with_assignment_comparison(request)
}

#[test]
fn cooldown_excludes_newer_release_and_selects_mature_fallback() {
    let name = package("demo");
    let loader = FixtureLoader {
        candidates: [(
            name.clone(),
            vec![
                release("demo", "1.0.0", Some("2026-01-01")),
                release("demo", "2.0.0", Some("2026-07-01")),
            ],
        )]
        .into_iter()
        .collect(),
    };
    let resolution = resolve(&loader, &PreferLocked, request("demo", HashMap::new())).unwrap();
    assert_eq!(
        resolution.selected(&name).unwrap().version().as_str(),
        "1.0.0"
    );
}

fn hard_dependency(name: &str) -> DependencyRequirement {
    hard_dependency_with_constraint(name, VersionConstraint::unconstrained())
}

fn hard_dependency_with_constraint(
    name: &str,
    constraint: VersionConstraint,
) -> DependencyRequirement {
    DependencyRequirement::new(
        DependencyKind::Depends,
        package(name),
        DependencySourceConstraint::Any,
        constraint,
    )
}

#[test]
fn publication_ineligible_transitive_dependency_backtracks_parent_version() {
    let loader = FixtureLoader {
        candidates: [
            (
                package("parent"),
                vec![
                    release_with_dependencies(
                        "parent",
                        "2.0.0",
                        Some("2026-01-01"),
                        vec![hard_dependency("child")],
                    ),
                    release("parent", "1.0.0", Some("2026-01-01")),
                ],
            ),
            (package("child"), vec![release("child", "1.0.0", None)]),
        ]
        .into_iter()
        .collect(),
    };
    let resolution = resolve(&loader, &PreferLocked, request("parent", HashMap::new())).unwrap();
    assert_eq!(
        resolution
            .selected(&package("parent"))
            .unwrap()
            .version()
            .as_str(),
        "1.0.0"
    );
}

#[test]
fn transitive_publication_proof_reports_all_stable_reasons() {
    let loader = FixtureLoader {
        candidates: [
            (
                package("parent"),
                vec![
                    release_with_dependencies(
                        "parent",
                        "2.0.0",
                        Some("2026-01-01"),
                        vec![hard_dependency("childnew")],
                    ),
                    release_with_dependencies(
                        "parent",
                        "1.0.0",
                        Some("2026-01-01"),
                        vec![hard_dependency("childunknown")],
                    ),
                ],
            ),
            (
                package("childnew"),
                vec![release("childnew", "1.0.0", Some("2026-07-01"))],
            ),
            (
                package("childunknown"),
                vec![release("childunknown", "1.0.0", None)],
            ),
        ]
        .into_iter()
        .collect(),
    };
    let error = resolve(&loader, &PreferLocked, request("parent", HashMap::new())).unwrap_err();
    let ResolutionFailure::PublicationIneligible { rejections, .. } = error else {
        panic!("expected publication policy failure from final proof");
    };
    assert!(matches!(
        rejections.as_ref(),
        [
            PublicationRejection::PublicationCooldown { identity: first, .. },
            PublicationRejection::PublicationUnknown { identity: second }
        ] if first.name().as_str() == "childnew" && second.name().as_str() == "childunknown"
    ));
}

#[test]
fn mixed_publication_and_missing_proof_remains_generic_no_solution() {
    let loader = FixtureLoader {
        candidates: [
            (
                package("parent"),
                vec![
                    release_with_dependencies(
                        "parent",
                        "2.0.0",
                        Some("2026-01-01"),
                        vec![hard_dependency("childnew")],
                    ),
                    release_with_dependencies(
                        "parent",
                        "1.0.0",
                        Some("2026-01-01"),
                        vec![hard_dependency("missing")],
                    ),
                ],
            ),
            (
                package("childnew"),
                vec![release("childnew", "1.0.0", Some("2026-07-01"))],
            ),
            (package("missing"), Vec::new()),
        ]
        .into_iter()
        .collect(),
    };
    let error = resolve(&loader, &PreferLocked, request("parent", HashMap::new())).unwrap_err();
    assert!(matches!(error, ResolutionFailure::NoSolution { .. }));
}

#[test]
fn disjoint_ranges_for_same_package_do_not_hide_unrelated_no_versions() {
    let loader = FixtureLoader {
        candidates: [
            (
                package("parent"),
                vec![
                    release_with_dependencies(
                        "parent",
                        "2.0.0",
                        Some("2026-01-01"),
                        vec![hard_dependency_with_constraint(
                            "foo",
                            VersionConstraint::from_clause(
                                rsolve_core::RelationOp::Ge,
                                rsolve_core::RPackageVersion::parse("2.0").unwrap(),
                            ),
                        )],
                    ),
                    release_with_dependencies(
                        "parent",
                        "1.0.0",
                        Some("2026-01-01"),
                        vec![hard_dependency_with_constraint(
                            "foo",
                            VersionConstraint::from_clause(
                                rsolve_core::RelationOp::Lt,
                                rsolve_core::RPackageVersion::parse("2.0").unwrap(),
                            ),
                        )],
                    ),
                ],
            ),
            (
                package("foo"),
                vec![release("foo", "2.0.0", Some("2026-07-01"))],
            ),
        ]
        .into_iter()
        .collect(),
    };
    let error = resolve(&loader, &PreferLocked, request("parent", HashMap::new())).unwrap_err();
    assert!(matches!(error, ResolutionFailure::NoSolution { .. }));
}

#[test]
fn unknown_or_cooldown_only_candidates_report_typed_failures() {
    for publication in [Some("2026-07-01"), None] {
        let loader = FixtureLoader {
            candidates: [(package("demo"), vec![release("demo", "1.0.0", publication)])]
                .into_iter()
                .collect(),
        };
        let error = resolve(&loader, &PreferLocked, request("demo", HashMap::new())).unwrap_err();
        assert!(matches!(
            error,
            ResolutionFailure::PublicationIneligible { rejections, .. }
                if rejections.len() == 1
        ));
    }
}

#[test]
fn publication_policy_is_range_aware() {
    let mature = release("demo", "1.0.0", Some("2026-01-01"));
    let newer = release("demo", "2.0.0", Some("2026-07-01"));
    let loader = FixtureLoader {
        candidates: [(package("demo"), vec![mature, newer])]
            .into_iter()
            .collect(),
    };
    let only_newer = VersionConstraint::from_clause(
        rsolve_core::RelationOp::Ge,
        rsolve_core::RPackageVersion::parse("2.0").unwrap(),
    );
    let error = resolve(
        &loader,
        &PreferLocked,
        request_with_constraint("demo", only_newer, HashMap::new()),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ResolutionFailure::PublicationIneligible { rejections, .. }
            if matches!(rejections.as_ref(), [PublicationRejection::PublicationCooldown { .. }])
    ));

    let unknown = release("demo", "2.0.0", None);
    let loader = FixtureLoader {
        candidates: [(package("demo"), vec![mature_release(), unknown])]
            .into_iter()
            .collect(),
    };
    let exact_newer = VersionConstraint::from_clause(
        rsolve_core::RelationOp::Eq,
        rsolve_core::RPackageVersion::parse("2.0").unwrap(),
    );
    let error = resolve(
        &loader,
        &PreferLocked,
        request_with_constraint("demo", exact_newer, HashMap::new()),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ResolutionFailure::PublicationIneligible { rejections, .. }
            if matches!(rejections.as_ref(), [PublicationRejection::PublicationUnknown { .. }])
    ));
}

fn mature_release() -> PackageRelease {
    release("demo", "1.0.0", Some("2026-01-01"))
}

#[test]
fn mixed_publication_rejections_are_lossless_and_stable() {
    let loader = FixtureLoader {
        candidates: [(
            package("demo"),
            vec![
                release("demo", "2.0.0", None),
                release("demo", "1.0.0", Some("2026-07-01")),
            ],
        )]
        .into_iter()
        .collect(),
    };
    let error = resolve(&loader, &PreferLocked, request("demo", HashMap::new())).unwrap_err();
    let ResolutionFailure::PublicationIneligible { rejections, .. } = error else {
        panic!("expected publication policy failure");
    };
    assert!(matches!(
        rejections.as_ref(),
        [
            PublicationRejection::PublicationCooldown { .. },
            PublicationRejection::PublicationUnknown { .. }
        ]
    ));
}

#[test]
fn same_version_eligible_identity_survives_ineligible_identity() {
    let loader = FixtureLoader {
        candidates: [(
            package("demo"),
            vec![
                release_with_namespace("demo", "1.0.0", None, "other", Vec::new()),
                release("demo", "1.0.0", Some("2026-01-01")),
            ],
        )]
        .into_iter()
        .collect(),
    };
    let resolution = resolve(&loader, &PreferLocked, request("demo", HashMap::new())).unwrap();
    assert!(matches!(
        resolution.selected(&package("demo")).unwrap().identity().provenance(),
        rsolve_core::Provenance::RegistryRelease { namespace, .. }
            if namespace.as_str() == "cran"
    ));
}

#[test]
fn normal_and_frozen_locked_identities_bypass_cutoff() {
    let locked_release = release("demo", "2.0.0", Some("2026-07-01"));
    let identity = locked_release.identity().clone();
    let loader = FixtureLoader {
        candidates: [(package("demo"), vec![locked_release])]
            .into_iter()
            .collect(),
    };
    let locked: HashMap<_, _> = [(SolverKey::InstalledName(package("demo")), identity)]
        .into_iter()
        .collect();
    assert!(resolve(&loader, &PreferLocked, request("demo", locked.clone())).is_ok());
    assert!(resolve(&loader, &RequireLocked, request("demo", locked)).is_ok());
}

#[test]
fn soft_lock_missing_from_catalog_falls_back_to_mature_candidate() {
    let locked = release("demo", "3.0.0", Some("2026-07-01"))
        .identity()
        .clone();
    let loader = FixtureLoader {
        candidates: [(package("demo"), vec![mature_release()])]
            .into_iter()
            .collect(),
    };
    let locked = [(SolverKey::InstalledName(package("demo")), locked)]
        .into_iter()
        .collect();
    let resolution = resolve(&loader, &PreferLocked, request("demo", locked)).unwrap();
    assert_eq!(
        resolution
            .selected(&package("demo"))
            .unwrap()
            .version()
            .as_str(),
        "1.0.0"
    );
}

#[test]
fn unknown_locked_identity_bypasses_cutoff_for_normal_and_frozen_policies() {
    let locked_release = release("demo", "2.0.0", None);
    let identity = locked_release.identity().clone();
    let loader = FixtureLoader {
        candidates: [(package("demo"), vec![locked_release])]
            .into_iter()
            .collect(),
    };
    let locked: HashMap<_, _> = [(SolverKey::InstalledName(package("demo")), identity)]
        .into_iter()
        .collect();
    assert!(resolve(&loader, &PreferLocked, request("demo", locked.clone())).is_ok());
    assert!(resolve(&loader, &RequireLocked, request("demo", locked)).is_ok());
}

#[test]
fn base_package_projection_is_exempt_and_not_installable() {
    let loader = FixtureLoader {
        candidates: BTreeMap::new(),
    };
    let overlay = RBasePackageOverlay::new(loader, target().r_version.clone()).unwrap();
    let resolution = resolve(&overlay, &PreferLocked, request("methods", HashMap::new())).unwrap();
    assert!(resolution.selected(&package("methods")).is_none());
}

#[test]
fn comparison_reports_stable_publication_reasons() {
    let loader = FixtureLoader {
        candidates: [(
            package("demo"),
            vec![
                release("demo", "1.0.0", Some("2026-01-01")),
                release("demo", "2.0.0", Some("2026-07-01")),
                release("demo", "3.0.0", None),
            ],
        )]
        .into_iter()
        .collect(),
    };
    let compared = compare(&loader, &PreferLocked, request("demo", HashMap::new())).unwrap();
    let assignment = compared
        .comparison
        .assignments
        .iter()
        .find(|assignment| matches!(assignment.subject, rsolve_resolver::DecisionSubject::InstalledName(ref name) if name == &package("demo")))
        .unwrap();
    assert!(assignment.alternatives.iter().any(|alternative| matches!(
        alternative.differs_by,
        AssignmentDifference::PublicationCooldown { .. }
    )));
    assert!(assignment.alternatives.iter().any(|alternative| matches!(
        alternative.differs_by,
        AssignmentDifference::PublicationUnknown
    )));
}
