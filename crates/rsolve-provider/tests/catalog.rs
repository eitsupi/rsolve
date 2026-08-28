use rsolve_core::{
    DependencyKind, DependencySourceConstraint, Provenance, PublicationDate, RelationOp,
};
use rsolve_provider::cran::{CranCatalog, CranCatalogError, CranRecordError, DependencyParseError};

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
Published: 2026-06-24 19:14:59 UTC\n\
Unknown-Field: retained\n\n",
    )
    .unwrap();

    let candidates = catalog.candidates_named("demo").unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(catalog.candidates_named("R").unwrap().is_empty());

    let release = &candidates[0];
    assert!(matches!(
        release.identity().provenance(),
        Provenance::RegistryRelease { namespace, version }
            if namespace.as_str() == "cran" && version.as_str() == "1.0.0"
    ));
    assert_eq!(
        release
            .metadata()
            .fields()
            .get("Unknown-Field")
            .map(String::as_str),
        Some("retained")
    );
    assert_eq!(
        release.publication().map(|publication| publication.date()),
        Some(PublicationDate::parse("2026-06-24").unwrap())
    );
    assert_eq!(release.declared_dependencies().len(), 10);

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
    for (dependency, (kind, name, constraint)) in
        release.declared_dependencies().iter().zip(expected)
    {
        assert_eq!(dependency.kind, kind);
        assert_eq!(dependency.package.name().as_str(), name);
        assert!(matches!(
            (&dependency.package.source(), constraint),
            (DependencySourceConstraint::Any, _)
        ));
        match constraint {
            Some((op, version)) => {
                assert_eq!(dependency.package.constraint().clauses.len(), 1);
                assert_eq!(dependency.package.constraint().clauses[0].op, op);
                assert_eq!(
                    dependency.package.constraint().clauses[0].version.as_str(),
                    version
                );
            }
            None => assert!(dependency.package.constraint().is_unconstrained()),
        }
    }
}

#[test]
fn dependency_splitter_matches_r_terminal_empty_segment_rules() {
    let cases = [
        ("", Ok(vec![])),
        ("rsolvefixture.one,", Ok(vec!["rsolvefixture.one"])),
        ("rsolvefixture.one,,rsolvefixture.two", Err(())),
        ("rsolvefixture.one,,", Err(())),
        ("rsolvefixture.one,  ", Err(())),
    ];
    for (value, expected) in cases {
        let input = format!("Package: dependency.case\nVersion: 1.0.0\nImports: {value}\n\n");
        let result = CranCatalog::from_packages(input.as_bytes());
        match expected {
            Ok(names) => {
                let catalog = result.expect("R-compatible dependency field");
                let release = &catalog.candidates_named("dependency.case").unwrap()[0];
                assert_eq!(
                    release
                        .declared_dependencies()
                        .iter()
                        .map(|dependency| dependency.package.name().as_str())
                        .collect::<Vec<_>>(),
                    names
                );
            }
            Err(()) => {
                let error = result.expect_err("malformed empty dependency token");
                assert!(matches!(
                    error.diagnostics()[0].error(),
                    CranRecordError::Dependency {
                        field: "Imports",
                        source: DependencyParseError::EmptyEntry,
                        ..
                    }
                ));
            }
        }
    }
}

#[test]
fn root_candidate_excludes_recommended_overlay_metadata() {
    let catalog = CranCatalog::from_packages(
        b"Package: Matrix\nVersion: 1.7-6\nDepends: R (>= 4.4), methods\nMD5sum: same\n\n\
Package: Matrix\nVersion: 1.7-6\nDepends: R (>= 4.7), methods\nPath: 4.7.0/Recommended\nMD5sum: same\n\n",
    )
    .unwrap();
    let release = &catalog.candidates_named("Matrix").unwrap()[0];
    assert_eq!(catalog.candidate_count(), 1);
    assert_eq!(release.version().as_str(), "1.7-6");
    assert!(!release.metadata().fields().contains_key("Path"));
    assert_eq!(release.declared_dependencies().len(), 2);
    assert_eq!(
        release
            .declared_dependencies()
            .iter()
            .find(|dependency| dependency.package.name().as_str() == "R")
            .expect("R dependency")
            .package
            .constraint()
            .clauses[0]
            .version
            .as_str(),
        "4.4"
    );
}

#[test]
fn recommended_overlay_without_root_produces_no_candidate() {
    let catalog = CranCatalog::from_packages(
        b"Package: Matrix\nVersion: 1.0.0\nDepends: R (>= 4.7.0)\nPath: 4.7.0/Recommended\nMD5sum: same\n\n",
    )
    .unwrap();
    assert_eq!(catalog.candidate_count(), 0);
}

#[test]
fn overlay_before_root_without_md5_does_not_change_root_candidate() {
    let catalog = CranCatalog::from_packages(
        b"Package: Matrix\nVersion: 1.0.0\nDepends: R (>= 4.7.0)\nPath: 4.7.0/Recommended\n\n\
Package: Matrix\nVersion: 1.0.0\nDepends: R (>= 3.0.0)\n\n",
    )
    .unwrap();
    let release = &catalog.candidates_named("Matrix").unwrap()[0];
    assert_eq!(catalog.candidate_count(), 1);
    assert_eq!(
        release.declared_dependencies()[0]
            .package
            .constraint()
            .clauses[0]
            .version
            .as_str(),
        "3.0.0"
    );
}

#[test]
fn valid_mismatched_recommended_overlay_is_excluded_from_root_candidate() {
    let input = b"Package: Matrix\nVersion: 1.0.0\nDepends: R (>= 3.0.0)\nMD5sum: same\n\n\
Package: Matrix\nVersion: 1.0.0\nDepends: R (>= 4.7.0)\nPath: 4.7.0/Recommended\nMD5sum: different\n\n";
    let catalog = CranCatalog::from_packages(input).unwrap();
    let release = &catalog.candidates_named("Matrix").unwrap()[0];
    assert_eq!(catalog.candidate_count(), 1);
    assert_eq!(
        release.declared_dependencies()[0]
            .package
            .constraint()
            .clauses[0]
            .version
            .as_str(),
        "3.0.0"
    );
}

#[test]
fn unknown_or_invalid_recommended_paths_fail_closed() {
    for path in ["4.7.0/Other", "not-a-version/Recommended"] {
        let input = format!(
            "Package: Matrix\nVersion: 1.0.0\nDepends: R (>= 3.0.0)\nMD5sum: same\n\n\
Package: Matrix\nVersion: 1.0.0\nDepends: R (>= 4.7.0)\nPath: {path}\nMD5sum: different\n\n"
        );
        let error = CranCatalog::from_packages(input.as_bytes()).unwrap_err();
        assert!(matches!(
            error.diagnostics()[0].error(),
            CranRecordError::InvalidPath { .. }
        ));
    }
}

#[test]
fn invalid_recommended_overlays_remain_fail_closed() {
    let cases = [
        (
            "Package: Matrix\nVersion: 1.7-6\nDepends: R (>= 4.4), methods\nMD5sum: same\n\n\
Package: Matrix\nVersion: 1.7-6\nDepends: R (>= 4.7), methods\nPath: 4.7.0/Recommended/extra\nMD5sum: same\n\n",
            "overlay path has an extra slash",
        ),
        (
            "Package: Matrix\nVersion: 1.7-6\nDepends: R (>= 4.4), methods\nMD5sum: same\n\n\
Package: Matrix\nVersion: 1.7-6\nDepends: R (>= 4.7),, methods\nPath: 4.7.0/Recommended\nMD5sum: same\n\n",
            "semantic dependency diagnostic",
        ),
    ];
    for (input, description) in cases {
        let error = CranCatalog::from_packages(input.as_bytes()).unwrap_err();
        assert!(!error.diagnostics().is_empty(), "{description}");
        if description == "semantic dependency diagnostic" {
            assert!(matches!(
                error.diagnostics()[0].error(),
                CranRecordError::Dependency { .. }
            ));
        } else {
            assert!(
                matches!(
                    error.diagnostics()[0].error(),
                    CranRecordError::InvalidPath { .. }
                ),
                "{description}"
            );
        }
    }
}

#[test]
fn p3m_overlay_shape_is_order_independent_and_allows_missing_md5() {
    for input in [
        b"Package: boot\nVersion: 1.0.0\nDepends: R (>= 4.7.0)\nPath: 4.7.0/Recommended\n\n\
Package: boot\nVersion: 1.0.0\nDepends: R (>= 3.0.0)\n\n" as &[u8],
        b"Package: boot\nVersion: 1.0.0\nDepends: R (>= 3.0.0)\n\n\
Package: boot\nVersion: 1.0.0\nDepends: R (>= 4.7.0)\nPath: 4.7.0/Recommended\n\n",
    ] {
        let catalog = CranCatalog::from_packages(input).expect("p3m overlay catalog");
        let release = &catalog.candidates_named("boot").unwrap()[0];
        assert_eq!(catalog.candidate_count(), 1);
        assert_eq!(
            release.declared_dependencies()[0]
                .package
                .constraint()
                .clauses[0]
                .version
                .as_str(),
            "3.0.0"
        );
        assert!(!release.metadata().fields().contains_key("Path"));
    }
}

#[test]
fn published_date_forms_are_first_class_and_missing_is_unknown() {
    let catalog = CranCatalog::from_packages(
        b"Package: dateonly\nVersion: 1.0.0\nPublished: 2026-06-24\n\n\
Package: bare.datetime\nVersion: 1.0.0\nPublished: 2026-06-24 19:14:59\n\n\
Package: datetime\nVersion: 1.0.0\nPublished: 2026-06-24 19:14:59 UTC\n\n\
Package: missing\nVersion: 1.0.0\n\n\
",
    )
    .unwrap();
    let expected = PublicationDate::parse("2026-06-24").unwrap();
    let date_only = catalog.candidates_named("dateonly").unwrap()[0]
        .publication()
        .map(|publication| publication.date())
        .unwrap();
    let timezone_free = catalog.candidates_named("bare.datetime").unwrap()[0]
        .publication()
        .map(|publication| publication.date())
        .unwrap();
    let utc = catalog.candidates_named("datetime").unwrap()[0]
        .publication()
        .map(|publication| publication.date())
        .unwrap();
    assert_eq!(date_only, expected);
    assert_eq!(timezone_free, expected);
    assert_eq!(utc, expected);
    assert!(
        catalog.candidates_named("missing").unwrap()[0]
            .publication()
            .is_none()
    );
}

#[test]
fn invalid_published_date_is_a_semantic_diagnostic() {
    let error =
        CranCatalog::from_packages(b"Package: invalid\nVersion: 1.0.0\nPublished: 2026-02-29\n\n")
            .unwrap_err();
    let CranCatalogError::Semantic(diagnostics) = error else {
        panic!("expected semantic diagnostics");
    };
    assert!(diagnostics.iter().any(|diagnostic| {
        matches!(
            diagnostic.error(),
            CranRecordError::InvalidPublicationDate { .. }
        )
    }));
}

#[test]
fn invalid_published_datetime_spellings_are_semantic_diagnostics() {
    for (index, value) in [
        "2026-06-24T19:14:59",
        "2026-06-24 19:14:59.1",
        "2026-06-24 19:14:59+00:00",
        "2026-06-24 19:14:59Z",
        "2026-06-24 19:14:59 utc",
        "2026-06-24 19:14:59 UTC extra",
        "2026-02-29 19:14:59",
        "2026-06-24 24:00:00",
        "2026-06-24 19:60:00",
        "2026-06-24 19:14:60",
    ]
    .into_iter()
    .enumerate()
    {
        let package = format!("invalid.datetime{index}");
        let input = format!("Package: {package}\nVersion: 1.0.0\nPublished: {value}\n\n");
        let error = CranCatalog::from_packages(input.as_bytes()).unwrap_err();
        assert!(matches!(
            error.diagnostics()[0].error(),
            CranRecordError::InvalidPublicationDate { .. }
        ));
    }
}

#[test]
fn folded_dependencies_and_absent_optional_fields_are_handled() {
    let catalog = CranCatalog::from_packages(SYNTHETIC_PACKAGES).unwrap();
    let folded = catalog.candidates_named("rsolvefixture.folded").unwrap();
    assert_eq!(folded.len(), 1);
    assert_eq!(folded[0].declared_dependencies().len(), 25);
    assert_eq!(
        folded[0].declared_dependencies()[0].package.name().as_str(),
        "rsolvefixture.suggest.00"
    );
    assert_eq!(
        folded[0].declared_dependencies()[24]
            .package
            .name()
            .as_str(),
        "rsolvefixture.suggest.24"
    );

    let plain = &catalog.candidates_named("rsolvefixture.plain").unwrap()[0];
    assert!(plain.declared_dependencies().is_empty());
    assert!(catalog.candidates_named("missing").unwrap().is_empty());
    assert_eq!(catalog.package_count(), 4);
    assert_eq!(catalog.candidate_count(), 4);
}

#[test]
fn malformed_records_fail_catalog_with_typed_diagnostic() {
    let error = CranCatalog::from_packages(
        b"Package: good\nVersion: 1.0.0\nLicense: fictional\n\n\
Package: malformed\nVersion: 1.0.0\nDepends: valid, broken (>=)\n\n\
Package: later\nVersion: 2.0.0\n\n",
    )
    .unwrap_err();
    assert!(error.to_string().contains("record 1 (malformed)"));
    assert!(
        error
            .to_string()
            .contains("1 semantic CRAN PACKAGES record(s)")
    );
    assert_eq!(error.diagnostics().len(), 1);
    let diagnostic = &error.diagnostics()[0];
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
fn multiple_semantic_diagnostics_are_lossless_and_source_ordered() {
    let error = CranCatalog::from_packages(
        b"Package: good\nVersion: 1.0.0\n\n\
Package: firstbad\nVersion: not-a-version\n\n\
Package: secondbad\nLicense: fictional\n\n",
    )
    .unwrap_err();
    assert!(error.to_string().contains("record 1 (firstbad)"));
    assert!(
        error
            .to_string()
            .contains("R version component 0 is not numeric")
    );
    assert!(error.to_string().contains("and 1 additional diagnostic(s)"));
    assert_eq!(error.diagnostics().len(), 2);
    assert_eq!(error.diagnostics()[0].record_index(), 1);
    assert_eq!(error.diagnostics()[0].package(), Some("firstbad"));
    assert_eq!(error.diagnostics()[1].record_index(), 2);
    assert_eq!(error.diagnostics()[1].package(), Some("secondbad"));
    assert!(matches!(
        error.diagnostics()[0].error(),
        CranRecordError::InvalidVersion(_)
    ));
    assert!(matches!(
        error.diagnostics()[1].error(),
        CranRecordError::MissingField("Version")
    ));
}

#[test]
fn conflicting_same_identity_metadata_fails_catalog_as_domain_diagnostic() {
    let error = CranCatalog::from_packages(
        b"Package: conflict\nVersion: 1.0.0\nLicense: first\n\n\
Package: conflict\nVersion: 1.0.0\nLicense: second\n\n",
    )
    .unwrap_err();
    assert_eq!(error.diagnostics().len(), 1);
    assert!(matches!(
        error.diagnostics()[0].error(),
        CranRecordError::Domain(_)
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
        let error = CranCatalog::from_packages(input.as_bytes()).unwrap_err();
        assert!(matches!(
            error.diagnostics()[0].error(),
            CranRecordError::DuplicateField(_)
        ));
    }
}

#[test]
fn single_equals_dependency_constraint_is_rejected() {
    let error =
        CranCatalog::from_packages(b"Package: demo\nVersion: 1.0.0\nDepends: foo (= 1.0)\n")
            .unwrap_err();
    assert!(matches!(
        error.diagnostics()[0].error(),
        CranRecordError::Dependency {
            field: "Depends",
            source: DependencyParseError::InvalidConstraintSyntax,
            ..
        }
    ));
}

#[test]
fn missing_required_fields_fail_but_dcf_errors_remain_distinct() {
    let error = CranCatalog::from_packages(
        b"Package: missing-version\nLicense: fictional\n\nPackage: valid\nVersion: 1.0.0\n\n",
    )
    .unwrap_err();
    assert!(matches!(
        error.diagnostics()[0].error(),
        CranRecordError::MissingField("Version")
    ));

    let error = CranCatalog::from_packages(b"Package invalid\n").unwrap_err();
    assert!(error.to_string().contains("invalid CRAN PACKAGES DCF"));
}
