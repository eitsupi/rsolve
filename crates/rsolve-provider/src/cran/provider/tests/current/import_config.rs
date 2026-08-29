#[test]
fn current_index_import_projects_catalog_and_evidence_from_one_parse() {
    crate::cran::archive_index::reset_archive_import_count();
    let (catalog, observations) = CranRefreshSession::<FixtureTransport>::parse_current_body(
        CranCurrentIndexRepresentation::Rds,
        NATIVE_UTF8_CURRENT,
    )
    .unwrap();
    assert!(!catalog.is_empty());
    assert!(!observations.is_empty());
    assert_eq!(crate::cran::archive_index::archive_import_count(), 1);

    let plain = b"Package: Matrix\nVersion: 1.7-0\nLicense: BSD\n";
    crate::cran::catalog::reset_packages_import_count();
    let (catalog, observations) = CranRefreshSession::<FixtureTransport>::parse_current_body(
        CranCurrentIndexRepresentation::PlainDcf,
        plain,
    )
    .unwrap();
    assert_eq!(catalog.candidate_count(), 1);
    assert_eq!(observations.len(), 1);
    assert_eq!(crate::cran::catalog::packages_import_count(), 1);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plain).unwrap();
    let gzip = encoder.finish().unwrap();
    crate::cran::catalog::reset_packages_import_count();
    let (_, observations) = CranRefreshSession::<FixtureTransport>::parse_current_body(
        CranCurrentIndexRepresentation::Gzip,
        &gzip,
    )
    .unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(crate::cran::catalog::packages_import_count(), 1);
}

#[test]
fn current_rds_provider_path_assumes_utf8_for_native_format_two_strings() {
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let catalog = session
        .ensure_current()
        .expect("provider CRAN UTF-8 contract should accept native format-2 strings");
    assert_eq!(
        catalog.candidates_named("Matrix").unwrap()[0]
            .metadata()
            .fields()
            .get("License")
            .map(String::as_str),
        Some("RSOLVE UTF-8 fixture ™")
    );
}

#[test]
fn current_rds_provider_path_rejects_invalid_native_utf8() {
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: INVALID_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let error = session
        .ensure_current()
        .expect_err("invalid native UTF-8 must fail closed");
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
}

#[test]
fn concrete_loader_validates_and_canonicalizes_base_without_requests() {
    for (input, expected) in [
        (
            " https://cran.invalid/mirror ",
            "https://cran.invalid/mirror",
        ),
        (
            "https://cran.invalid/mirror/",
            "https://cran.invalid/mirror/",
        ),
        (
            " https://cran.invalid/mirror/// ",
            "https://cran.invalid/mirror///",
        ),
    ] {
        assert_eq!(canonical_base_url(input).unwrap(), expected.into());
    }
    assert!(
        CranSnapshotRefresher::new(CranMetadataConfig::for_repository(
            "https://cran.invalid/mirror///",
        ))
        .is_ok()
    );
    for input in [
        "",
        "ftp://cran.invalid",
        "https://",
        "https://cran.invalid?mirror=1",
        "https://cran.invalid/#mirror",
        "https://user:pass@cran.invalid",
        "https://cran.invalid:0",
        "https://cran.invalid/../mirror",
        "https://cran.invalid\\..\\mirror",
        "https://cran.invalid/ordinary\\path",
    ] {
        assert!(matches!(
            CranSnapshotRefresher::new(CranMetadataConfig::for_repository(input)),
            Err(CranSnapshotRefresherError::InvalidBaseUrl { .. })
        ));
    }
}

#[test]
fn refresher_preserves_refresh_metadata_configuration() {
    let refresher = CranSnapshotRefresher::new(
        CranMetadataConfig::for_repository("https://cran.invalid").with_refresh_metadata(),
    )
    .unwrap();
    assert!(refresher.refresh_metadata_enabled());
}

#[test]
fn refresher_preserves_custom_allpackages_feed_endpoint() {
    let refresher = CranSnapshotRefresher::new(CranMetadataConfig::new(
        "https://cran.invalid",
        "https://feed.invalid/custom-ALLPACKAGES.zst",
    ))
    .unwrap();
    assert_eq!(
        refresher.allpackages_feed_endpoint().as_ref(),
        "https://feed.invalid/custom-ALLPACKAGES.zst"
    );
}

#[test]
fn refresher_preserves_publication_cutoff_history_policy() {
    let refresher = CranSnapshotRefresher::new(
        CranMetadataConfig::for_repository("https://cran.invalid").without_allpackages_history(),
    )
    .unwrap();
    assert!(!refresher.allpackages_history_enabled());
}
use super::*;
use flate2::{Compression, write::GzEncoder};
use std::io::Write;
