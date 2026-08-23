use super::*;

#[test]
fn current_rds_provider_path_assumes_utf8_for_native_format_two_strings() {
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
    );
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
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
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
    );
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
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
    assert_eq!(
        canonical_base_url(" https://cran.invalid/mirror/// ").unwrap(),
        "https://cran.invalid/mirror".into()
    );
    assert!(CranSnapshotRefresher::new("https://cran.invalid/mirror///").is_ok());
    for input in [
        "",
        "ftp://cran.invalid",
        "https://",
        "https://cran.invalid?mirror=1",
        "https://cran.invalid/#mirror",
    ] {
        assert!(matches!(
            CranSnapshotRefresher::new(input),
            Err(CranSnapshotRefresherError::InvalidBaseUrl { .. })
        ));
    }
}

#[test]
fn current_and_archive_same_identity_merge_or_fail_on_metadata_conflict() {
    let consistent = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: RSOLVE Fictional Terms Matrix\nNeedsCompilation: yes\n";
    let transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 200,
            body: consistent.to_vec(),
        },
    );
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    assert_eq!(
        snapshot
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap()
            ))
            .unwrap()
            .len(),
        2
    );

    let conflicting = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: conflicting\nNeedsCompilation: yes\n";
    let transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 200,
            body: conflicting.to_vec(),
        },
    );
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let error = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
    assert!(
        error
            .diagnostic()
            .contains("conflicting CRAN release metadata")
    );
}

#[test]
fn recommended_overlay_does_not_invalidate_unrelated_current_candidates() {
    let current = b"Package: rlang\nVersion: 1.1.0\nLicense: MIT\n\n\
Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.1.0)\nMD5sum: root\n\n\
Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.7)\nMD5sum: overlay\nPath: 4.7.0/Recommended\n";
    let transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 200,
            body: current.to_vec(),
        },
    );
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let catalog = session
        .ensure_current()
        .expect("a Recommended overlay must not make the complete current index invalid");
    assert_eq!(catalog.candidates_named("rlang").unwrap().len(), 1);
    assert_eq!(catalog.candidates_named("survival").unwrap().len(), 1);

    let evidence = session.evidence.borrow();
    let survival = evidence
        .iter()
        .filter(|observation| observation.package.as_str() == "survival")
        .collect::<Vec<_>>();
    assert_eq!(survival.len(), 2);
    let overlay = survival
        .iter()
        .find(|observation| {
            observation
                .fields
                .iter()
                .any(|field| field.name.eq_ignore_ascii_case("Path"))
        })
        .expect("Recommended overlay evidence");
    assert!(matches!(
        overlay.scope,
        crate::cran::catalog::CranCatalogRecordScope::RecommendedOverlay { .. }
    ));
    assert_eq!(
        overlay.artifact.as_ref().unwrap().locator,
        "https://cran.invalid/src/contrib/4.7.0/Recommended/survival_3.8-11.tar.gz"
    );
    let root = survival
        .iter()
        .find(|observation| {
            !observation
                .fields
                .iter()
                .any(|field| field.name.eq_ignore_ascii_case("Path"))
        })
        .expect("CRAN root evidence");
    assert!(matches!(
        root.scope,
        crate::cran::catalog::CranCatalogRecordScope::Root
    ));
    assert_eq!(
        root.artifact.as_ref().unwrap().locator,
        "https://cran.invalid/src/contrib/survival_3.8-11.tar.gz"
    );
}

#[test]
fn current_index_transport_or_status_failures_remain_transport_failures() {
    for responses in [
        HashMap::new(),
        HashMap::from([
            (
                current_rds_url(),
                TransportResponse {
                    status: 404,
                    body: Vec::new(),
                },
            ),
            (
                current_gzip_url(),
                TransportResponse {
                    status: 410,
                    body: Vec::new(),
                },
            ),
            (
                current_plain_url(),
                TransportResponse {
                    status: 503,
                    body: Vec::new(),
                },
            ),
        ]),
    ] {
        let transport = FixtureTransport {
            responses,
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        let error = session.ensure_current().unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::TransportFailure
        );
    }
}

#[test]
fn current_index_http_success_with_invalid_schema_is_metadata_invalid() {
    let mut responses = HashMap::new();
    responses.insert(
        current_rds_url(),
        TransportResponse {
            status: 200,
            body: WRONG_ROOT.to_vec(),
        },
    );
    responses.insert(
        current_gzip_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
    );
    responses.insert(
        current_plain_url(),
        TransportResponse {
            status: 503,
            body: Vec::new(),
        },
    );
    let transport = FixtureTransport {
        responses,
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let error = session.ensure_current().unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
}

#[test]
fn current_absence_with_absent_archive_sources_is_empty() {
    let mut transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 200,
            body: b"Package: other\nVersion: 1.0.0\n".to_vec(),
        },
    );
    transport.responses.insert(
        history_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .expect("empty current result");
    assert!(
        snapshot
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap()
            ))
            .unwrap()
            .is_empty()
    );
    assert_eq!(requests.borrow().len(), 5);
    assert!(requests.borrow().iter().any(|url| url == &fast_url()));
    assert!(requests.borrow().iter().any(|url| url == &history_url()));
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::ArchiveHistory
            && matches!(
                diagnostic.status_detail(),
                CranFastPathStatus::Absent { status: 404 }
            )
    }));
}
