use super::{CranCatalog, CranCatalogRecordContext, CranRecordError};
use rsolve_core::PackageName;

const MATCHING_ARCHIVE: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-overlay-PACKAGES.rds"
);

const MATCHING_PLAIN: &[u8] = b"Package: Matrix\nVersion: 1.7-6\nLicense: RSOLVE Fictional Terms Matrix\nMD5sum: 00000000000000000000000000000031\n\nPackage: Matrix\nVersion: 1.7-6\nLicense: RSOLVE Fictional Terms Matrix\nMD5sum: 00000000000000000000000000000031\nPath: 4.7.0/Recommended\n";

fn assert_overlay_is_retained_losslessly(observations: &[super::CranCatalogObservation]) {
    assert_eq!(observations.len(), 2);
    assert!(matches!(
        observations[0].scope(),
        super::CranCatalogRecordScope::Root
    ));
    assert!(matches!(
        observations[1].scope(),
        super::CranCatalogRecordScope::RecommendedOverlay { .. }
    ));
    assert!(
        observations[1]
            .fields()
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("Path") && value == "4.7.0/Recommended")
    );
}

#[test]
fn md5sum_is_evidence_only_and_not_release_semantics() {
    let without = super::validated_observations_from_fields(vec![(
        0,
        None,
        vec![
            ("Package".into(), "Matrix".into()),
            ("Version".into(), "1.7-6".into()),
            ("License".into(), "BSD-3-Clause".into()),
        ],
    )])
    .unwrap();
    let with = super::validated_observations_from_fields(vec![(
        0,
        None,
        vec![
            ("Package".into(), "Matrix".into()),
            ("Version".into(), "1.7-6".into()),
            ("License".into(), "BSD-3-Clause".into()),
            ("MD5sum".into(), "00000000000000000000000000000031".into()),
        ],
    )])
    .unwrap();
    assert_eq!(
        without[0].release().metadata_digest(),
        with[0].release().metadata_digest()
    );
    assert!(
        with[0]
            .fields()
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("MD5sum"))
    );
}

#[test]
fn plain_lossless_observations_share_matching_overlay_selection() {
    let catalog = CranCatalog::from_packages(MATCHING_PLAIN).unwrap();
    assert_eq!(catalog.candidate_count(), 1);
    let observations = CranCatalog::observations_from_packages(MATCHING_PLAIN).unwrap();
    assert_overlay_is_retained_losslessly(&observations);
}

#[test]
fn archive_lossless_observations_share_matching_overlay_selection() {
    let catalog = CranCatalog::from_archive_index_rds(MATCHING_ARCHIVE).unwrap();
    assert_eq!(catalog.candidate_count(), 1);
    let observations = CranCatalog::observations_from_archive_index_rds(MATCHING_ARCHIVE).unwrap();
    assert_overlay_is_retained_losslessly(&observations);
}

#[test]
fn mismatched_overlay_is_root_candidate_regardless_of_input_order() {
    let root = b"Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.1.0)\nMD5sum: root\n\n";
    let overlay = b"Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.7)\nMD5sum: overlay\nPath: 4.7.0/Recommended\n\n";
    for input in [
        [root.as_slice(), overlay.as_slice()].concat(),
        [overlay.as_slice(), root.as_slice()].concat(),
    ] {
        let catalog = CranCatalog::from_packages(&input).unwrap();
        assert_eq!(catalog.candidate_count(), 1);
        assert_eq!(
            catalog.candidates_named("survival").unwrap()[0]
                .version()
                .to_string(),
            "3.8-11"
        );
        let observations = CranCatalog::observations_from_packages(&input).unwrap();
        assert_eq!(observations.len(), 2);
    }
}

#[test]
fn overlay_only_never_becomes_a_root_candidate() {
    let input =
        b"Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.7)\nPath: 4.7.0/Recommended\n";
    let catalog = CranCatalog::from_packages(input).unwrap();
    assert_eq!(catalog.candidate_count(), 0);
    let observations = CranCatalog::observations_from_packages(input).unwrap();
    assert_eq!(observations.len(), 1);
}

#[test]
fn invalid_recommended_path_fails_closed() {
    for path in [
        "Recommended",
        "4.7.0/Recommended/extra",
        "latest/Recommended",
    ] {
        let input = format!("Package: survival\nVersion: 3.8-11\nPath: {path}\n");
        let error = CranCatalog::from_packages(input.as_bytes()).unwrap_err();
        assert!(matches!(
            error.diagnostics()[0].error(),
            super::CranRecordError::InvalidPath { .. }
        ));
    }
}

#[test]
fn description_path_is_preserved_as_root_metadata() {
    let input = b"Package: survival\nVersion: 3.8-11\nPath: source/archive\n";
    let catalog = CranCatalog::from_description(input).unwrap();
    let release = &catalog.candidates_named("survival").unwrap()[0];
    assert_eq!(
        release.metadata().fields().get("Path").map(String::as_str),
        Some("source/archive")
    );

    let observations = CranCatalog::observations_from_description(input).unwrap();
    assert_eq!(observations.len(), 1);
    assert!(matches!(
        observations[0].scope(),
        super::CranCatalogRecordScope::Root
    ));
    assert!(
        observations[0]
            .fields()
            .iter()
            .any(|(name, value)| name == "Path" && value == "source/archive")
    );
}

#[test]
fn conflicting_pathless_roots_fail_closed() {
    let input = b"Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.1.0)\n\nPackage: survival\nVersion: 3.8-11\nDepends: R (>= 4.7)\n";
    let error = CranCatalog::from_packages(input).unwrap_err();
    assert!(matches!(
        error.diagnostics()[0].error(),
        super::CranRecordError::Domain(_)
    ));
}

#[test]
fn mixed_parse_and_domain_diagnostics_remain_in_source_order() {
    let input = b"Package: Matrix\nVersion: 1.0\nLicense: root\n\n\
Package: malformed\n\n\
Package: Matrix\nVersion: 1.0\nLicense: conflicting\n";
    let error = CranCatalog::from_packages(input).unwrap_err();
    let diagnostics = error.diagnostics();
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(diagnostics[0].record_index(), 1);
    assert!(matches!(
        diagnostics[0].error(),
        super::CranRecordError::MissingField("Version")
    ));
    assert_eq!(diagnostics[1].record_index(), 2);
    assert!(matches!(
        diagnostics[1].error(),
        super::CranRecordError::Domain(_)
    ));
}

#[test]
fn provider_archive_projection_quarantines_release_local_dependency_errors() {
    let records = vec![
        (
            0,
            Some("rsolvefixture.history".to_owned()),
            vec![
                ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                ("Version".to_owned(), "1.0".to_owned()),
                ("License".to_owned(), "fixture".to_owned()),
            ],
        ),
        (
            1,
            Some("rsolvefixture.history".to_owned()),
            vec![
                ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                ("Version".to_owned(), "1.1".to_owned()),
                ("License".to_owned(), "fixture".to_owned()),
            ],
        ),
        (
            2,
            Some("rsolvefixture.history".to_owned()),
            vec![
                ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                ("Version".to_owned(), "1.2".to_owned()),
                ("Depends".to_owned(), "libxml (>= )".to_owned()),
            ],
        ),
    ];
    let projection = super::provider_observations_from_fields(
        records,
        CranCatalogRecordContext::PackagesIndex,
        Some(&PackageName::new("rsolvefixture.history").unwrap()),
    );
    assert_eq!(projection.observations.len(), 2);
    assert_eq!(projection.rejections.len(), 1);
    assert_eq!(projection.rejections[0].record_index(), 2);
    assert_eq!(
        projection.rejections[0].package().unwrap().as_str(),
        "rsolvefixture.history"
    );
    assert_eq!(projection.rejections[0].version().unwrap().as_str(), "1.2");
    assert!(matches!(
        projection.rejections[0].error(),
        CranRecordError::Dependency { .. }
    ));
    let catalog = CranCatalog::from_provider_observations(&projection.observations);
    assert_eq!(catalog.candidate_count(), 2);
    assert!(
        catalog
            .candidates_named("rsolvefixture.history")
            .unwrap()
            .iter()
            .all(|release| release.version().as_str() != "1.2")
    );
}

#[test]
fn provider_projection_checks_path_before_release_semantics() {
    let records = vec![(
        0,
        Some("rsolvefixture.history".to_owned()),
        vec![
            ("Package".to_owned(), "rsolvefixture.history".to_owned()),
            ("Version".to_owned(), "1.0".to_owned()),
            ("Path".to_owned(), "broken-path".to_owned()),
            ("Depends".to_owned(), "libxml (>= )".to_owned()),
        ],
    )];
    let projection = super::provider_observations_from_fields(
        records,
        CranCatalogRecordContext::PackagesIndex,
        Some(&PackageName::new("rsolvefixture.history").unwrap()),
    );
    assert!(projection.observations.is_empty());
    assert!(matches!(
        projection.rejections[0].error(),
        CranRecordError::InvalidPath { .. }
    ));
    assert_eq!(projection.rejections[0].version().unwrap().as_str(), "1.0");
}

#[test]
fn provider_projection_rejects_unexpected_package_and_preserves_raw_fields() {
    let records = vec![(
        0,
        Some("other".to_owned()),
        vec![
            ("Package".to_owned(), "other".to_owned()),
            ("Version".to_owned(), "1.0".to_owned()),
            ("Depends".to_owned(), "R".to_owned()),
        ],
    )];
    let projection = super::provider_observations_from_fields(
        records,
        CranCatalogRecordContext::PackagesIndex,
        Some(&PackageName::new("rsolvefixture.history").unwrap()),
    );
    assert!(projection.observations.is_empty());
    let rejection = &projection.rejections[0];
    assert!(matches!(
        rejection.error(),
        CranRecordError::UnexpectedPackage { .. }
    ));
    assert_eq!(rejection.fields().len(), 3);
}

#[test]
fn provider_projection_aggregates_equivalent_valid_duplicates() {
    let fields = |version: &str| {
        vec![
            ("Package".to_owned(), "rsolvefixture.history".to_owned()),
            ("Version".to_owned(), version.to_owned()),
            ("License".to_owned(), "fixture".to_owned()),
        ]
    };
    let projection = super::provider_observations_from_fields(
        vec![(0, None, fields("1.0")), (1, None, fields("1.0.0"))],
        CranCatalogRecordContext::PackagesIndex,
        Some(&PackageName::new("rsolvefixture.history").unwrap()),
    );
    assert_eq!(projection.observations.len(), 2);
    assert!(projection.rejections.is_empty());
    let catalog = CranCatalog::from_provider_observations(&projection.observations);
    assert_eq!(catalog.candidate_count(), 1);
}

#[test]
fn provider_projection_makes_valid_and_rejected_duplicate_identity_hard() {
    let records = vec![
        (
            0,
            None,
            vec![
                ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                ("Version".to_owned(), "1.0".to_owned()),
                ("Depends".to_owned(), "libxml (>= )".to_owned()),
            ],
        ),
        (
            1,
            None,
            vec![
                ("Package".to_owned(), "rsolvefixture.history".to_owned()),
                ("Version".to_owned(), "1.0.0".to_owned()),
            ],
        ),
    ];
    let projection = super::provider_observations_from_fields(
        records,
        CranCatalogRecordContext::PackagesIndex,
        Some(&PackageName::new("rsolvefixture.history").unwrap()),
    );
    assert!(projection.observations.len() <= 1);
    assert!(projection.rejections.iter().any(|rejection| matches!(
        rejection.error(),
        CranRecordError::Domain(rsolve_core::PackageReleaseError::ConflictingMetadata {
            field: "duplicate identity"
        })
    )));
}
