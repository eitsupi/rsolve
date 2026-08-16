use rsolve_core::{DependencyKind, DependencySourceConstraint, Provenance, RelationOp};
use rsolve_provider::cran::{CranCatalog, CranRecordError, DependencyParseError};

const SYNTHETIC_PACKAGES: &[u8] = include_bytes!("fixtures/cran-2026-08-08/synthetic-PACKAGES");

#[test]
fn converts_all_dependency_kinds_and_preserves_r_as_a_requirement() {
    let catalog = CranCatalog::from_packages(
        b"Package: demo\nVersion: 1.0.0\n\
Depends: R (>= 4.4), methods\n\
Imports: Matrix (>= 1.6-5), stats\n\
LinkingTo: cpp11 (>= 0.1.0), Rcpp\n\
Suggests: testthat (== 3.2.0), knitr\n\
Enhances: foo (> 1.0), bar\n\
Published: fictional\n\
Unknown-Field: retained\n\n",
    )
    .unwrap();

    let candidates = catalog.candidates_named("demo").unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(catalog.candidates_named("R").unwrap().is_empty());
    assert!(catalog.diagnostics().is_empty());

    let release = &candidates[0];
    assert!(matches!(
        release.identity().provenance(),
        Provenance::RegistryRelease { namespace, version }
            if namespace.as_str() == "cran" && version.as_str() == "1.0.0"
    ));
    assert_eq!(
        release.metadata().fields().get("Unknown-Field"),
        Some(&"retained".to_owned())
    );
    assert_eq!(release.dependencies().len(), 10);

    let expected = [
        (DependencyKind::Depends, "R", Some((RelationOp::Ge, "4.4"))),
        (DependencyKind::Depends, "methods", None),
        (
            DependencyKind::Imports,
            "Matrix",
            Some((RelationOp::Ge, "1.6-5")),
        ),
        (DependencyKind::Imports, "stats", None),
        (
            DependencyKind::LinkingTo,
            "cpp11",
            Some((RelationOp::Ge, "0.1.0")),
        ),
        (DependencyKind::LinkingTo, "Rcpp", None),
        (
            DependencyKind::Suggests,
            "testthat",
            Some((RelationOp::Eq, "3.2.0")),
        ),
        (DependencyKind::Suggests, "knitr", None),
        (
            DependencyKind::Enhances,
            "foo",
            Some((RelationOp::Gt, "1.0")),
        ),
        (DependencyKind::Enhances, "bar", None),
    ];
    for (dependency, (kind, name, constraint)) in release.dependencies().iter().zip(expected) {
        assert_eq!(dependency.kind, kind);
        assert_eq!(dependency.name.as_str(), name);
        assert!(matches!(
            (&dependency.source, constraint),
            (DependencySourceConstraint::Any, _)
        ));
        match constraint {
            Some((op, version)) => {
                assert_eq!(dependency.constraint.clauses.len(), 1);
                assert_eq!(dependency.constraint.clauses[0].op, op);
                assert_eq!(dependency.constraint.clauses[0].version.as_str(), version);
            }
            None => assert!(dependency.constraint.is_unconstrained()),
        }
    }
}

#[test]
fn folded_dependencies_and_absent_optional_fields_are_handled() {
    let catalog = CranCatalog::from_packages(SYNTHETIC_PACKAGES).unwrap();
    let folded = catalog.candidates_named("rsolvefixture.folded").unwrap();
    assert_eq!(folded.len(), 1);
    assert_eq!(folded[0].dependencies().len(), 25);
    assert_eq!(
        folded[0].dependencies()[0].name.as_str(),
        "rsolvefixture.suggest.00"
    );
    assert_eq!(
        folded[0].dependencies()[24].name.as_str(),
        "rsolvefixture.suggest.24"
    );

    let plain = &catalog.candidates_named("rsolvefixture.plain").unwrap()[0];
    assert!(plain.dependencies().is_empty());
    assert!(catalog.candidates_named("missing").unwrap().is_empty());
    assert_eq!(catalog.package_count(), 4);
    assert_eq!(catalog.candidate_count(), 4);
}

#[test]
fn malformed_records_are_skipped_with_a_diagnostic() {
    let catalog = CranCatalog::from_packages(
        b"Package: good\nVersion: 1.0.0\nLicense: fictional\n\n\
Package: malformed\nVersion: 1.0.0\nDepends: valid, broken (>=)\n\n\
Package: later\nVersion: 2.0.0\n\n",
    )
    .unwrap();

    assert_eq!(catalog.candidate_count(), 2);
    assert!(catalog.candidates_named("malformed").unwrap().is_empty());
    assert_eq!(catalog.diagnostics().len(), 1);
    let diagnostic = &catalog.diagnostics()[0];
    assert_eq!(diagnostic.record_index(), 1);
    assert_eq!(diagnostic.package(), Some("malformed"));
    assert!(matches!(
        diagnostic.error(),
        CranRecordError::Dependency {
            field: "Depends",
            source: DependencyParseError::MissingConstraintVersion,
            ..
        }
    ));
}

#[test]
fn duplicate_fields_are_rejected_case_insensitively() {
    for (first, second) in [
        ("Package", "package"),
        ("Version", "VERSION"),
        ("Depends", "depends"),
        ("Imports", "IMPORTS"),
        ("LinkingTo", "linkingto"),
        ("Suggests", "SUGGESTS"),
        ("Enhances", "enhances"),
        ("License", "license"),
    ] {
        let input =
            format!("Package: demo\nVersion: 1.0.0\n{first}: value-one\n{second}: value-two\n");
        let catalog = CranCatalog::from_packages(input.as_bytes()).unwrap();

        assert!(catalog.is_empty(), "duplicate {first} should be rejected");
        assert!(matches!(
            catalog.diagnostics()[0].error(),
            CranRecordError::DuplicateField(_)
        ));
    }
}

#[test]
fn single_equals_dependency_constraint_is_rejected() {
    let catalog =
        CranCatalog::from_packages(b"Package: demo\nVersion: 1.0.0\nDepends: foo (= 1.0)\n")
            .unwrap();

    assert!(catalog.is_empty());
    assert!(matches!(
        catalog.diagnostics()[0].error(),
        CranRecordError::Dependency {
            field: "Depends",
            source: DependencyParseError::InvalidConstraintSyntax,
            ..
        }
    ));
}

#[test]
fn missing_required_fields_are_skipped_but_dcf_errors_fail_the_index() {
    let catalog = CranCatalog::from_packages(
        b"Package: missing-version\nLicense: fictional\n\nPackage: valid\nVersion: 1.0.0\n\n",
    )
    .unwrap();
    assert_eq!(catalog.candidate_count(), 1);
    assert!(matches!(
        catalog.diagnostics()[0].error(),
        CranRecordError::MissingField("Version")
    ));

    let error = CranCatalog::from_packages(b"Package invalid\n").unwrap_err();
    assert!(error.to_string().contains("invalid CRAN PACKAGES DCF"));
}
