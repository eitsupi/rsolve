use super::*;

#[test]
fn invalid_fast_path_shapes_match_fast_catalog() {
    let fast = provider(FixtureTransport::fallback(FAST.to_vec(), 200));
    let expected = logical_signature(&fast);
    for invalid in [
        b"truncated RDS".as_slice(),
        WRONG_ROOT,
        MISSING_VERSION,
        SEMANTIC_INVALID_FAST,
    ] {
        let fallback = provider(FixtureTransport::fallback(invalid.to_vec(), 200));
        assert_eq!(logical_signature(&fallback), expected);
        assert!(matches!(
            fallback.diagnostics()[0].status_detail(),
            CranFastPathStatus::Invalid { status: 200, .. }
        ));
    }
}

#[test]
fn invalid_gzip_current_index_falls_back_to_plain_once() {
    let current = b"Package: rsolvefixture.plain\nVersion: 3.0.0\n";
    let transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: b"not gzip".to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: current.to_vec(),
            ..TransportResponse::default()
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let snapshot = session
        .refresh_packages(&[PackageName::new("rsolvefixture.plain").unwrap()])
        .unwrap();
    assert_eq!(
        snapshot
            .releases(&SolverKey::InstalledName(
                PackageName::new("rsolvefixture.plain").unwrap()
            ))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(requests.borrow()[0], current_gzip_url());
    assert_eq!(requests.borrow()[1], current_rds_url());
    assert_eq!(requests.borrow()[2], current_plain_url());
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Gzip)
            && matches!(
                diagnostic.status_detail(),
                CranFastPathStatus::Invalid { .. }
            )
    }));
}

#[test]
fn invalid_gzip_current_index_falls_back_to_rds() {
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: b"not gzip".to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 500,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    assert_eq!(requests.borrow()[0], current_gzip_url());
    assert_eq!(requests.borrow()[1], current_rds_url());
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Gzip)
            && matches!(
                diagnostic.status_detail(),
                CranFastPathStatus::Invalid { .. }
            )
    }));
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Rds)
            && matches!(diagnostic.status_detail(), CranFastPathStatus::Available)
    }));
}

#[test]
fn invalid_rds_current_index_falls_back_to_plain() {
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: vec![0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: b"Package: rsolvefixture.plain\nVersion: 3.0.0\n".to_vec(),
            ..TransportResponse::default()
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    session
        .refresh_packages(&[PackageName::new("rsolvefixture.plain").unwrap()])
        .unwrap();
    assert_eq!(requests.borrow()[0], current_gzip_url());
    assert_eq!(requests.borrow()[1], current_rds_url());
    assert_eq!(requests.borrow()[2], current_plain_url());
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Rds)
            && matches!(
                diagnostic.status_detail(),
                CranFastPathStatus::Invalid { .. }
            )
    }));
}

#[test]
fn valid_gzip_current_index_wins_without_rds_and_reports_progress_once() {
    let current = b"Package: rsolvefixture.plain\nVersion: 3.0.0\n";
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(current).unwrap();
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: b"invalid RDS".to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: encoder.finish().unwrap(),
            ..TransportResponse::default()
        },
        TransportResponse::new(500, Vec::new()),
    );
    let requests = Rc::clone(&transport.requests);
    let events = Rc::new(std::cell::RefCell::new(Vec::new()));
    let capture = Rc::clone(&events);
    let callback = Rc::new(move |event| capture.borrow_mut().push(event));
    let mut session = CranRefreshSession::new_with_progress(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        None,
        None,
        Some(callback),
    );
    session
        .refresh_packages(&[PackageName::new("rsolvefixture.plain").unwrap()])
        .unwrap();
    assert_eq!(requests.borrow()[0], current_gzip_url());
    assert!(
        !requests
            .borrow()
            .iter()
            .any(|request| request.url == current_rds_url())
    );
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Gzip)
            && matches!(diagnostic.status_detail(), CranFastPathStatus::Available)
    }));
    let events = events.borrow();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, CranRefreshProgress::CurrentIndexStarted))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, CranRefreshProgress::CurrentIndexCompleted { .. }))
            .count(),
        1
    );
}

#[test]
fn history_transport_and_metadata_failures_remain_hard_failures() {
    let cases = [
        (
            500,
            Vec::new(),
            CandidateLoadErrorCategory::TransportFailure,
        ),
        (
            200,
            b"invalid history".to_vec(),
            CandidateLoadErrorCategory::MetadataInvalid,
        ),
    ];
    for (history_status, history_body, expected_category) in cases {
        let mut transport = session_transport(
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
            TransportResponse {
                status: 200,
                body: b"Package: Matrix\nVersion: 1.8-0\n".to_vec(),
                ..TransportResponse::default()
            },
        );
        transport.responses.insert(
            history_url(),
            TransportResponse {
                status: history_status,
                body: history_body,
                ..TransportResponse::default()
            },
        );
        let mut session = CranRefreshSession::new(
            Rc::new(transport),
            CranMetadataConfig::new("https://cran.invalid", ""),
        );
        let error = session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .unwrap_err();
        assert_eq!(error.category(), expected_category);
        assert!(session.diagnostics.iter().any(|diagnostic| {
            diagnostic.source() == CranRefreshSource::ArchiveHistory
                && diagnostic.status() == Some(history_status)
        }));
        if history_status == 200 {
            assert!(error.diagnostic().contains("invalid CRAN archive history"));
            assert!(!error.diagnostic().ends_with("HTTP 200"));
        }
    }
}

#[test]
fn history_transport_error_is_hard_failure_after_absent_fast_path() {
    let mut transport = session_transport(
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
        TransportResponse {
            status: 200,
            body: b"Package: Matrix\nVersion: 1.8-0\n".to_vec(),
            ..TransportResponse::default()
        },
    );
    transport.responses.remove(&history_url());
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let error = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::TransportFailure
    );
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::ArchiveHistory
            && diagnostic.status().is_none()
            && matches!(
                diagnostic.status_detail(),
                CranFastPathStatus::Invalid { status: 0, .. }
            )
    }));
}

#[test]
fn fast_path_transport_error_is_diagnostic_and_falls_back() {
    let current = b"Package: Matrix\nVersion: 1.8-0\n";
    let mut transport = session_transport(
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
        TransportResponse {
            status: 200,
            body: current.to_vec(),
            ..TransportResponse::default()
        },
    );
    transport.responses.remove(&fast_url());
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    let diagnostic = session
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.endpoint() == fast_url())
        .unwrap();
    assert_eq!(diagnostic.status(), None);
    assert!(matches!(
        diagnostic.status_detail(),
        CranFastPathStatus::Invalid {
            status: 0,
            diagnostic,
        } if diagnostic.contains("archive fast path for Matrix failed: transport failure")
    ));
}

#[test]
fn fast_path_unexpected_status_keeps_transport_diagnostic() {
    let mut transport = session_transport(
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
        TransportResponse {
            status: 200,
            body: b"Package: Matrix\nVersion: 1.8-0\n".to_vec(),
            ..TransportResponse::default()
        },
    );
    transport
        .responses
        .insert(fast_url(), TransportResponse::new(500, Vec::new()));
    transport
        .responses
        .insert(history_url(), TransportResponse::new(404, Vec::new()));
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let error = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::TransportFailure
    );
    let diagnostic = session
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.endpoint() == fast_url())
        .unwrap();
    assert!(matches!(
        diagnostic.status_detail(),
        CranFastPathStatus::Invalid {
            status: 500,
            diagnostic,
        } if diagnostic.contains("archive fast path for Matrix returned unexpected HTTP 500")
    ));
}

#[test]
fn size_mismatch_is_a_hard_acquisition_error() {
    let mut size_transport = FixtureTransport::fallback(Vec::new(), 404);
    size_transport
        .responses
        .get_mut(&old_url())
        .unwrap()
        .body
        .pop();
    let size_provider = provider(size_transport);
    let error = size_provider
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::TransportFailure
    );
    assert!(error.diagnostic().contains("size mismatch"));
}

#[test]
fn semantically_invalid_description_is_metadata_invalid() {
    let mut transport = FixtureTransport::fallback(Vec::new(), 404);
    let mut invalid = invalid_description_tar();
    invalid.resize(OLD_TAR.len(), 0);
    transport.responses.insert(
        old_url(),
        TransportResponse {
            status: 200,
            body: invalid.clone(),
            ..TransportResponse::default()
        },
    );
    invalid.resize(NEW_TAR.len(), 0);
    transport.responses.insert(
        new_url(),
        TransportResponse {
            status: 200,
            body: invalid,
            ..TransportResponse::default()
        },
    );
    let provider = provider(transport);
    let error = provider
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
    assert!(error.diagnostic().contains("invalid DESCRIPTION"));
    assert!(
        error
            .diagnostic()
            .contains("R version component 0 is not numeric")
    );
}
