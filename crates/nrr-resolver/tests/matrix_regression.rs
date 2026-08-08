#[path = "support/matrix_scenario.rs"]
mod matrix_scenario;

use matrix_scenario::MatrixCatalog;
use nrr_core::PackageName;
use nrr_resolver::{AssignmentBasis, AssignmentDifference, DecisionCandidate, DecisionSubject};

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
fn an_unsatisfied_r_requirement_is_a_typed_resolution_failure() {
    let catalog = MatrixCatalog::new();
    let mut request = catalog.request("4.3.3");
    request.r_requirement = nrr_core::VersionConstraint::from_clause(
        nrr_core::RelationOp::Ge,
        nrr_core::RPackageVersion::parse("4.4.0").unwrap(),
    );
    let failure = catalog.resolver().resolve(request).unwrap_err();
    assert!(matches!(
        failure,
        nrr_resolver::ResolutionFailure::NoSolution { .. }
    ));
}
