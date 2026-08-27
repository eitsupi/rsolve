use super::*;

#[test]
fn absent_fast_path_falls_back_lazily_without_reprobe() {
    let transport = FixtureTransport::fallback(Vec::new(), 404);
    let requests = Rc::clone(&transport.requests);
    let provider = provider(transport);
    assert!(matches!(
        provider.diagnostics()[0].status_detail(),
        CranFastPathStatus::Unsupported { status: 404 }
    ));
    assert_eq!(requests.borrow().len(), 2);
    assert_eq!(requests.borrow()[0], fast_url());
    assert_eq!(requests.borrow()[1], history_url());
    assert_eq!(logical_signature(&provider).len(), 2);
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &fast_url())
            .count(),
        1
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &history_url())
            .count(),
        1
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &old_url())
            .count(),
        1
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &new_url())
            .count(),
        1
    );
    assert_eq!(logical_signature(&provider).len(), 2);
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &old_url())
            .count(),
        1
    );
}

#[test]
fn snapshot_distinguishes_unrefreshed_from_refreshed_empty_packages() {
    let empty = PackageName::new("rsolvefixture.empty").unwrap();
    let unknown = PackageName::new("rsolvefixture.unknown").unwrap();
    let snapshot = CranCandidateSnapshot::from_candidates([(empty.clone(), Vec::new())]);
    assert!(snapshot.contains_package(&empty));
    assert!(!snapshot.needs_refresh(&SolverKey::InstalledName(empty.clone())));
    assert!(
        snapshot
            .releases(&SolverKey::InstalledName(empty))
            .unwrap()
            .is_empty()
    );
    assert!(snapshot.needs_refresh(&SolverKey::InstalledName(unknown.clone())));
    assert_eq!(
        snapshot
            .releases(&SolverKey::InstalledName(unknown))
            .unwrap_err()
            .category(),
        CandidateLoadErrorCategory::NotFound
    );
}

#[test]
fn gone_fast_path_is_absent_and_shared_history_is_fetched_once() {
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
    transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 410,
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
    assert_eq!(
        session
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.endpoint() == fast_url())
            .unwrap()
            .status_detail(),
        &CranFastPathStatus::Unsupported { status: 410 }
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &history_url())
            .count(),
        1
    );
}

#[test]
fn absent_fast_path_and_absent_history_use_current_candidates_only() {
    let current = b"Package: Matrix\nVersion: 1.8-0\n";
    for (fast_status, history_status) in [(404, 404), (404, 410), (410, 404), (410, 410)] {
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
        transport.responses.insert(
            fast_url(),
            TransportResponse {
                status: fast_status,
                body: Vec::new(),
                ..TransportResponse::default()
            },
        );
        transport.responses.insert(
            history_url(),
            TransportResponse {
                status: history_status,
                body: Vec::new(),
                ..TransportResponse::default()
            },
        );
        let requests = Rc::clone(&transport.requests);
        let mut session = CranRefreshSession::new(
            Rc::new(transport),
            CranMetadataConfig::new("https://cran.invalid", ""),
        );
        let snapshot = session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .expect("current-only refresh");
        assert_eq!(
            snapshot
                .releases(&SolverKey::InstalledName(
                    PackageName::new("Matrix").unwrap()
                ))
                .unwrap()
                .len(),
            1
        );
        assert!(!requests.borrow().iter().any(|url| url == &old_url()));
        assert!(session.diagnostics.iter().any(|diagnostic| {
            diagnostic.source() == CranRefreshSource::ArchiveHistory
                && diagnostic.status_detail()
                    == &CranFastPathStatus::Absent {
                        status: history_status,
                    }
        }));
        let fast_index = session
            .diagnostics
            .iter()
            .position(|diagnostic| diagnostic.source() == CranRefreshSource::ArchiveFastPath)
            .unwrap();
        let history_index = session
            .diagnostics
            .iter()
            .position(|diagnostic| diagnostic.source() == CranRefreshSource::ArchiveHistory)
            .unwrap();
        assert!(fast_index < history_index);
    }
}

#[test]
fn archive_candidates_are_retained_when_current_index_lacks_package() {
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
            body: b"Package: other\nVersion: 1.0.0\n".to_vec(),
            ..TransportResponse::default()
        },
    );
    transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 200,
            body: FAST.to_vec(),
            ..TransportResponse::default()
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .expect("archive-only candidates");
    assert_eq!(
        snapshot
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap()
            ))
            .unwrap()
            .len(),
        2
    );
    assert!(requests.borrow().iter().any(|url| url == &fast_url()));
    assert!(!requests.borrow().iter().any(|url| url == &history_url()));
}

#[test]
fn fast_path_failure_is_not_hidden_by_absent_history() {
    for fast_response in [
        TransportResponse {
            status: 500,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: WRONG_ROOT.to_vec(),
            ..TransportResponse::default()
        },
    ] {
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
            .insert(fast_url(), fast_response.clone());
        transport.responses.insert(
            history_url(),
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
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .unwrap_err();
        assert_eq!(
            error.category(),
            if fast_response.status == 200 {
                CandidateLoadErrorCategory::MetadataInvalid
            } else {
                CandidateLoadErrorCategory::TransportFailure
            }
        );
        assert!(session.diagnostics.iter().any(|diagnostic| {
            diagnostic.source() == CranRefreshSource::ArchiveHistory
                && matches!(
                    diagnostic.status_detail(),
                    CranFastPathStatus::Absent { status: 404 }
                )
        }));
    }
}

#[test]
fn unsupported_fast_path_and_empty_sources_are_negative_cached() {
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
            body: b"Package: Other\nVersion: 1.0.0\n".to_vec(),
            ..TransportResponse::default()
        },
    );
    transport.responses.insert(
        history_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let package = PackageName::new("Matrix").unwrap();
    for _ in 0..2 {
        let snapshot = session
            .refresh_packages(std::slice::from_ref(&package))
            .unwrap();
        assert!(
            snapshot
                .releases(&SolverKey::InstalledName(package.clone()))
                .unwrap()
                .is_empty()
        );
    }
    let request_count = requests.borrow().len();
    let diagnostic_count = session.diagnostics.len();
    assert_eq!(request_count, 5);
    assert_eq!(diagnostic_count, 6);
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &fast_url())
            .count(),
        1
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &history_url())
            .count(),
        1
    );
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::ArchiveFastPath
            && diagnostic.status_detail() == &CranFastPathStatus::Unsupported { status: 404 }
    }));
}

#[test]
fn invalid_fast_path_failure_is_negative_cached_with_stable_error() {
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
        fast_url(),
        TransportResponse {
            status: 500,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    transport.responses.insert(
        history_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let package = PackageName::new("Matrix").unwrap();
    let first = session
        .refresh_packages(std::slice::from_ref(&package))
        .unwrap_err();
    let request_count = requests.borrow().len();
    let diagnostic_count = session.diagnostics.len();
    let second = session
        .refresh_packages(std::slice::from_ref(&package))
        .unwrap_err();
    assert_eq!(
        first.category(),
        CandidateLoadErrorCategory::TransportFailure
    );
    assert_eq!(second.category(), first.category());
    assert_eq!(second.diagnostic(), first.diagnostic());
    assert_eq!(requests.borrow().len(), request_count);
    assert_eq!(session.diagnostics.len(), diagnostic_count);
}

#[test]
fn tarball_transport_and_metadata_failures_are_negative_cached() {
    let mut malformed = OLD_TAR.to_vec();
    malformed[0] ^= 1;
    for (status, body, category) in [
        (
            503,
            Vec::new(),
            CandidateLoadErrorCategory::TransportFailure,
        ),
        (200, malformed, CandidateLoadErrorCategory::MetadataInvalid),
    ] {
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
            .insert(old_url(), TransportResponse::new(status, body));
        let requests = Rc::clone(&transport.requests);
        let mut session = CranRefreshSession::new(
            Rc::new(transport),
            CranMetadataConfig::new("https://cran.invalid", ""),
        );
        let package = PackageName::new("Matrix").unwrap();
        let first = session
            .refresh_packages(std::slice::from_ref(&package))
            .unwrap_err();
        let request_count = requests.borrow().len();
        let diagnostic_count = session.diagnostics.len();
        let second = session
            .refresh_packages(std::slice::from_ref(&package))
            .unwrap_err();
        assert_eq!(first.category(), category);
        assert_eq!(second.category(), first.category());
        assert_eq!(second.diagnostic(), first.diagnostic());
        assert_eq!(requests.borrow().len(), request_count);
        assert_eq!(session.diagnostics.len(), diagnostic_count);
    }
}

#[test]
fn history_only_enumerates_file_info_facts() {
    let entries = enumerate_archive_rds(HISTORY).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].package().as_str(), "Matrix");
    assert_eq!(
        entries[0].source_archive_relative_path(),
        "Matrix/Matrix_1.6-5.tar.gz"
    );
    assert_eq!(entries[0].version().as_str(), "1.6-5");
    assert_eq!(entries[0].size(), OLD_TAR.len() as u64);
    assert_eq!(entries[0].mtime(), 1_790_000_000);
}

#[test]
fn history_rejects_non_canonical_archive_paths() {
    for fixture in INVALID_HISTORY_PATHS {
        assert!(matches!(
            enumerate_archive_rds(fixture),
            Err(CranHistoryError::InvalidArchivePath { .. })
        ));
    }
}

#[test]
fn provider_keeps_unsafe_percent_paths_as_hard_failures() {
    for fixture in INVALID_HISTORY_PATHS.iter().take(11) {
        assert!(
            crate::cran::history::enumerate_archive_rds_for_provider(fixture).is_err(),
            "unsafe history path unexpectedly became a package-local rejection"
        );
    }
}

#[test]
fn history_accepts_safe_nested_archive_paths() {
    let entries = enumerate_archive_rds(NESTED_HISTORY).expect("nested history fixture");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].package().as_str(), "Matrix");
    assert_eq!(
        entries[0].source_archive_relative_path(),
        "Matrix/legacy/Matrix_1.6-5.tar.gz"
    );
}

#[test]
fn provider_quarantines_foreign_nested_archive_rows() {
    assert!(matches!(
        enumerate_archive_rds(FOREIGN_NESTED_HISTORY),
        Err(CranHistoryError::InvalidArchivePath { .. })
    ));
    let projection =
        crate::cran::history::enumerate_archive_rds_for_provider(FOREIGN_NESTED_HISTORY)
            .expect("foreign nested row is release-local");
    assert!(projection.entries.is_empty());
    assert_eq!(projection.rejections.len(), 1);
    assert_eq!(projection.rejections[0].package_hint().as_str(), "calibFit");
    assert_eq!(
        projection.rejections[0].raw_path(),
        "calibFit/Ancestry/calib_0.1.02.tar.gz"
    );
}

#[test]
fn provider_projects_root_data_frame_package_local_rejections() {
    let projection =
        crate::cran::history::enumerate_archive_rds_for_provider(ROOT_NESTED_MIXED_HISTORY)
            .expect("root data.frame package-local rows are isolatable");
    assert_eq!(projection.entries.len(), 1);
    assert_eq!(projection.entries[0].package().as_str(), "Matrix");
    assert_eq!(
        projection.entries[0].source_archive_relative_path(),
        "Matrix/legacy/Matrix_1.6-5.tar.gz"
    );
    assert_eq!(projection.rejections.len(), 2);

    let foreign = projection
        .rejections
        .iter()
        .find(|rejection| rejection.package_hint().as_str() == "calibFit")
        .expect("foreign nested filename should be attributed to its container");
    assert_eq!(foreign.row(), 1);
    assert_eq!(foreign.raw_path(), "calibFit/Ancestry/calib_0.1.02.tar.gz");
    assert!(foreign.reason().contains("invalid archive path"));

    let legacy = projection
        .rejections
        .iter()
        .find(|rejection| rejection.package_hint().as_str() == "dse")
        .expect("invalid legacy version should be attributed to its container");
    assert_eq!(legacy.row(), 2);
    assert_eq!(legacy.raw_path(), "dse/dse_R2000.4-1.tar.gz");
    assert!(legacy.reason().contains("invalid archive path"));
}

#[test]
fn provider_keeps_root_data_frame_unsafe_paths_as_hard_failures() {
    assert!(matches!(
        crate::cran::history::enumerate_archive_rds_for_provider(ROOT_UNSAFE_PERCENT_HISTORY),
        Err(CranHistoryError::InvalidArchivePath { .. })
    ));
}

#[test]
fn provider_projects_legacy_version_as_a_package_local_rejection() {
    let projection =
        crate::cran::history::enumerate_archive_rds_for_provider(LEGACY_VERSION_HISTORY)
            .expect("legacy version is package-local");
    assert!(projection.entries.is_empty());
    assert_eq!(projection.rejections.len(), 1);
    let rejection = &projection.rejections[0];
    assert_eq!(rejection.package_hint().as_str(), "dse");
    assert_eq!(rejection.row(), 0);
    assert_eq!(rejection.raw_path(), "dse/dse_R2000.4-1.tar.gz");
    assert!(rejection.reason().contains("invalid archive path"));

    let package = PackageName::new("dse").unwrap();
    let provider = CranProvider::from_source(
        FixtureTransport::fallback(Vec::new(), 404),
        "https://cran.invalid",
        package.clone(),
        CandidateSource::Fallback {
            entries: Rc::from(Vec::<ArchiveEntry>::new().into_boxed_slice()),
            rejections: Rc::from(projection.rejections.into_boxed_slice()),
        },
        Vec::new(),
        None,
        None,
    );
    let error = provider
        .releases(&SolverKey::InstalledName(package))
        .expect_err("all rejected history must be metadata-invalid");
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
    assert!(error.diagnostic().contains("dse_R2000.4-1.tar.gz"));
}
