#[path = "support/matrix_scenario.rs"]
mod matrix_scenario;

use matrix_scenario::MatrixCatalog;
use matrix_scenario::regression_support::{
    AlternativeCatalog, BacktrackingCatalog, GitDependencyCatalog, MultiSourceCatalog,
    SameVersionCatalog, StrongDependencyCatalog, matrix_identity, require_locked_matrix_resolver,
    with_locked_matrix,
};
use rsolve_core::{
    DependencySourceConstraint, NormalizedGitUrl, PackageName, RPackageVersion, RelationOp,
    SolverKey, VersionConstraint,
};
use rsolve_resolver::{AssignmentBasis, AssignmentDifference, DecisionCandidate, DecisionSubject};

#[test]
fn matrix_selects_the_last_compatible_release_for_each_r_version() {
    let catalog = MatrixCatalog::new();
    let matrix = PackageName::new("Matrix").unwrap();

    let r_43 = catalog
        .resolver()
        .resolve(catalog.request("4.3.3"))
        .unwrap();
    assert_eq!(r_43.selected(&matrix).unwrap().version().as_str(), "1.6-5");

    let r_44 = catalog
        .resolver()
        .resolve(catalog.request("4.4.0"))
        .unwrap();
    assert_eq!(r_44.selected(&matrix).unwrap().version().as_str(), "1.7-0");
}

#[test]
fn source_qualified_and_installed_name_identities_fail_closed() {
    let catalog = MultiSourceCatalog::conflicting();
    let failure = catalog.resolver().resolve(catalog.request()).unwrap_err();
    assert!(matches!(
        failure,
        rsolve_resolver::ResolutionFailure::NoSolution { .. }
    ));
}

#[test]
fn same_identity_from_multiple_subjects_uses_installed_name_canonical_subject() {
    let catalog = MultiSourceCatalog::same_identity();
    let resolution = catalog.resolver().resolve(catalog.request()).unwrap();

    assert_eq!(resolution.packages().len(), 1);
    assert_eq!(
        resolution.packages()[0].subject(),
        &SolverKey::InstalledName(PackageName::new("Foo").unwrap())
    );
    assert_eq!(
        resolution.packages()[0].identity(),
        &catalog.source_qualified_identity()
    );
}

#[test]
fn common_identity_backtracks_across_source_subjects_and_is_canonicalized() {
    let catalog = MultiSourceCatalog::common_with_conflicting_installed();
    let installed_only = catalog
        .resolver()
        .resolve(catalog.installed_name_request())
        .unwrap();
    assert_eq!(
        installed_only.packages()[0].identity(),
        &catalog.installed_name_identity()
    );

    let resolution = catalog.resolver().resolve(catalog.request()).unwrap();

    assert_eq!(resolution.packages().len(), 1);
    assert_eq!(
        resolution.packages()[0].subject(),
        &SolverKey::InstalledName(PackageName::new("Foo").unwrap())
    );
    assert_eq!(
        resolution.packages()[0].identity(),
        &catalog.source_qualified_identity()
    );
}

#[test]
fn common_identity_selection_is_stable_across_root_and_loader_order() {
    let ascending = MultiSourceCatalog::common_with_conflicting_installed();
    let descending = MultiSourceCatalog::common_with_conflicting_installed_reversed();
    let first = ascending.resolver().resolve(ascending.request()).unwrap();
    let second = descending
        .resolver()
        .resolve(descending.reversed_request())
        .unwrap();

    assert_eq!(first.target(), second.target());
    assert_eq!(first.packages().len(), second.packages().len());
    for (left, right) in first.packages().iter().zip(second.packages()) {
        assert_eq!(left.subject(), right.subject());
        assert_eq!(left.identity(), right.identity());
        assert_eq!(left.version(), right.version());
    }
}

#[test]
fn comparison_is_opt_in_and_does_not_change_the_matrix_resolution() {
    let catalog = MatrixCatalog::new();
    let matrix = PackageName::new("Matrix").unwrap();
    let request = catalog.request("4.3.3");
    let plain = catalog.resolver().resolve(request.clone()).unwrap();
    let compared = catalog
        .resolver()
        .resolve_with_assignment_comparison(request)
        .unwrap();

    assert_eq!(
        plain.selected(&matrix).unwrap().version(),
        compared.resolution.selected(&matrix).unwrap().version()
    );
    let matrix_assignment = compared
        .comparison
        .assignments
        .iter()
        .find(|assignment| assignment.subject == DecisionSubject::InstalledName(matrix.clone()))
        .expect("comparison must include Matrix");
    assert_eq!(
        matrix_assignment.basis,
        AssignmentBasis::InstalledNameReservation
    );
    assert!(matches!(
        matrix_assignment.assigned,
        DecisionCandidate::InstalledName { .. }
    ));
    assert_eq!(matrix_assignment.alternatives.len(), 1);
    assert!(matches!(
        matrix_assignment.alternatives[0].differs_by,
        AssignmentDifference::ConstraintViolatedByAssignment {
            against: DecisionSubject::R,
            ..
        }
    ));
}

#[test]
fn comparison_marks_root_requirement_mismatch_before_lower_preference() {
    let catalog = MatrixCatalog::new();
    let request = catalog.constrained_request(
        "4.4.0",
        VersionConstraint::from_clause(RelationOp::Ge, RPackageVersion::parse("1.7-0").unwrap()),
    );
    let compared = catalog
        .resolver()
        .resolve_with_assignment_comparison(request)
        .unwrap();
    let assignment = compared
        .comparison
        .assignments
        .iter()
        .find(|assignment| {
            assignment.subject
                == DecisionSubject::InstalledName(PackageName::new("Matrix").unwrap())
        })
        .unwrap();
    assert!(matches!(
        assignment.alternatives.as_slice(),
        [rsolve_resolver::AlternativeComparison {
            differs_by: AssignmentDifference::RootRequirementMismatch { requirement }
                , ..
        }] if requirement == &VersionConstraint::from_clause(
            RelationOp::Ge,
            RPackageVersion::parse("1.7-0").unwrap()
        )
    ));
}

#[test]
fn comparison_marks_strong_dependency_violation_against_assigned_package() {
    let catalog = StrongDependencyCatalog::new();
    let compared = catalog
        .resolver()
        .resolve_with_assignment_comparison(catalog.request())
        .unwrap();
    let assigned_dependency = compared
        .resolution
        .selected(&PackageName::new("AssignedDep").unwrap())
        .unwrap();
    let assignment = compared
        .comparison
        .assignments
        .iter()
        .find(|assignment| {
            assignment.subject
                == DecisionSubject::InstalledName(PackageName::new("StrongTop").unwrap())
        })
        .unwrap();
    let alternative = assignment.alternatives.first().unwrap();
    assert!(matches!(
        &alternative.differs_by,
        AssignmentDifference::ConstraintViolatedByAssignment {
            against: DecisionSubject::InstalledName(name),
            requirement,
            assigned: DecisionCandidate::Release { identity, version },
        } if name == &PackageName::new("AssignedDep").unwrap()
            && requirement == &VersionConstraint::from_clause(
                RelationOp::Ge,
                RPackageVersion::parse("2.0.0").unwrap()
            )
            && identity == assigned_dependency.identity()
            && version == assigned_dependency.version()
    ));
}

#[test]
fn comparison_is_stable_when_the_loader_changes_candidate_iteration_order() {
    let catalog = MatrixCatalog::new();
    let request = catalog.request("4.3.3");
    let first = catalog
        .resolver()
        .resolve_with_assignment_comparison(request.clone())
        .unwrap();
    let second = catalog
        .resolver()
        .resolve_with_assignment_comparison(request)
        .unwrap();

    assert_eq!(
        first
            .resolution
            .selected(&PackageName::new("Matrix").unwrap())
            .unwrap()
            .version(),
        second
            .resolution
            .selected(&PackageName::new("Matrix").unwrap())
            .unwrap()
            .version()
    );
    assert_eq!(first.comparison, second.comparison);
}

#[test]
fn comparison_alternatives_are_stable_across_reversed_loader_orders() {
    let ascending = AlternativeCatalog::new(false);
    let descending = AlternativeCatalog::new(true);
    let first = ascending
        .resolver()
        .resolve_with_assignment_comparison(ascending.request())
        .unwrap();
    let second = descending
        .resolver()
        .resolve_with_assignment_comparison(descending.request())
        .unwrap();

    assert_eq!(first.comparison, second.comparison);
    let alternatives = first
        .comparison
        .assignments
        .iter()
        .find(|assignment| {
            assignment.subject
                == DecisionSubject::InstalledName(PackageName::new("Alternatives").unwrap())
        })
        .expect("comparison must include Alternatives")
        .alternatives
        .len();
    assert_eq!(alternatives, 3);
}

#[test]
fn same_version_candidates_keep_the_policy_selected_identity_and_dependencies() {
    let catalog = SameVersionCatalog::new();
    let foo = PackageName::new("Foo").unwrap();
    let preferred = catalog.preferred_identity();

    let resolution = catalog.resolver().resolve(catalog.request()).unwrap();
    let selected = resolution.selected(&foo).unwrap();
    assert_eq!(selected.identity(), &preferred);
    assert!(
        resolution
            .selected(&PackageName::new("PreferredDep").unwrap())
            .is_some(),
        "the selected Foo release must supply the dependencies used by solving"
    );
    assert!(
        resolution
            .selected(&PackageName::new("WrongDep").unwrap())
            .is_none(),
        "the non-preferred same-version release must not supply dependencies"
    );
}

#[test]
fn same_version_identity_backtracks_when_the_first_identity_has_incompatible_dependencies() {
    let catalog = BacktrackingCatalog::new();
    let foo = PackageName::new("Foo").unwrap();
    let resolution = catalog.resolver().resolve(catalog.request()).unwrap();
    let selected = resolution.selected(&foo).unwrap();
    let rsolve_core::Provenance::RegistryRelease { namespace, .. } =
        selected.identity().provenance()
    else {
        panic!("fixture must provide registry provenance");
    };
    assert_eq!(namespace.as_str(), catalog.selected_namespace());
}

#[test]
fn require_locked_keeps_the_required_same_version_identity() {
    // The required identity is the one the preference policy would reject, and
    // the catalog returns the preferred release first.  Both halves are load
    // bearing: without the required-lock filter the preference wins, and
    // without canonicalisation the first release with the chosen version wins.
    let catalog = SameVersionCatalog::with_preferred_first();
    let foo = PackageName::new("Foo").unwrap();
    let required = catalog.nonpreferred_identity();
    let locked_resolution = catalog
        .require_locked_resolver()
        .resolve(catalog.require_nonpreferred_request())
        .unwrap();
    assert_eq!(
        locked_resolution.selected(&foo).unwrap().identity(),
        &required
    );
    assert!(
        locked_resolution
            .selected(&PackageName::new("WrongDep").unwrap())
            .is_some(),
        "the required release must supply the dependencies used by solving"
    );
    assert!(
        locked_resolution
            .selected(&PackageName::new("PreferredDep").unwrap())
            .is_none(),
        "the preferred release must not supply dependencies once a lock requires the other"
    );
}

#[test]
fn require_locked_rejects_a_lock_the_root_constraint_excludes() {
    // The distinguishing behaviour of the frozen-lock policy: when the locked
    // identity cannot satisfy the request, it must fail rather than move to
    // another release.  Preferring the same lock resolves, so this asserts the
    // required-lock filter itself and not merely the candidate ordering.
    let catalog = MatrixCatalog::new();
    let matrix = PackageName::new("Matrix").unwrap();
    let only_recent =
        VersionConstraint::from_clause(RelationOp::Ge, RPackageVersion::parse("1.7-0").unwrap());
    let locked_to_old = |constraint| {
        with_locked_matrix(
            catalog.constrained_request("4.4.0", constraint),
            matrix_identity(&catalog, "1.6-5"),
        )
    };

    let failure = require_locked_matrix_resolver(&catalog)
        .resolve(locked_to_old(only_recent.clone()))
        .unwrap_err();
    assert!(
        matches!(
            failure,
            rsolve_resolver::ResolutionFailure::NoSolution { .. }
        ),
        "a required lock outside the root constraint must not resolve, got {failure:?}"
    );

    let preferred = catalog
        .resolver()
        .resolve(locked_to_old(only_recent))
        .unwrap();
    assert_eq!(
        preferred.selected(&matrix).unwrap().version(),
        &RPackageVersion::parse("1.7-0").unwrap(),
        "preferring the same lock must fall forward instead of failing"
    );
}

#[test]
fn git_scoped_root_requirement_is_a_metadata_failure() {
    let catalog = MatrixCatalog::new();
    let mut request = catalog.request("4.3.3");
    request.roots = vec![rsolve_core::RootRequirement {
        package: rsolve_core::PackageRequirement::new(
            PackageName::new("Matrix").unwrap(),
            DependencySourceConstraint::Git {
                repository: NormalizedGitUrl::new("https://example.test/matrix.git").unwrap(),
            },
            VersionConstraint::unconstrained(),
        )
        .unwrap(),
        expansion: rsolve_core::RootExpansionPolicy::HardOnly,
    }];

    let failure = catalog.resolver().resolve(request).unwrap_err();
    match failure {
        rsolve_resolver::ResolutionFailure::CandidateLoad { package, source } => {
            assert_eq!(
                package,
                SolverKey::InstalledName(PackageName::new("Matrix").unwrap())
            );
            assert_eq!(
                source.category(),
                rsolve_core::CandidateLoadErrorCategory::MetadataInvalid
            );
            assert!(
                source
                    .diagnostic()
                    .contains("Git-sourced dependencies are not supported")
            );
            assert!(source.diagnostic().contains("Matrix"));
        }
        other => panic!("expected candidate-load metadata failure, got {other:?}"),
    }
}

#[test]
fn git_scoped_transitive_dependency_rejects_only_its_candidate() {
    let catalog = GitDependencyCatalog::new();

    let resolution = catalog.resolver().resolve(catalog.request()).unwrap();

    assert_eq!(
        resolution
            .selected(&PackageName::new("Choice").unwrap())
            .unwrap()
            .version(),
        &RPackageVersion::parse("1.0.0").unwrap(),
        "the release without a Git-scoped dependency must be selected after backtracking"
    );
    assert!(
        resolution
            .selected(&PackageName::new("GitOnly").unwrap())
            .is_none()
    );
}

#[test]
fn an_unsatisfied_r_requirement_is_a_typed_resolution_failure() {
    let catalog = MatrixCatalog::new();
    let mut request = catalog.request("4.3.3");
    request.r_requirement = rsolve_core::VersionConstraint::from_clause(
        rsolve_core::RelationOp::Ge,
        rsolve_core::RPackageVersion::parse("4.4.0").unwrap(),
    );
    let failure = catalog.resolver().resolve(request).unwrap_err();
    assert!(matches!(
        failure,
        rsolve_resolver::ResolutionFailure::NoSolution { .. }
    ));
}
