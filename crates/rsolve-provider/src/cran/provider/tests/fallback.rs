use super::*;

#[test]
fn absent_fast_path_falls_back_lazily_without_reprobe() {
    let transport = FixtureTransport::fallback(Vec::new(), 404);
    let requests = Rc::clone(&transport.requests);
    let provider = provider(transport);
    assert!(matches!(
        provider.diagnostics()[0].status_detail(),
        CranFastPathStatus::Absent { status: 404 }
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
    transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 410,
            body: Vec::new(),
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
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
        &CranFastPathStatus::Absent { status: 410 }
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
        transport.responses.insert(
            fast_url(),
            TransportResponse {
                status: fast_status,
                body: Vec::new(),
            },
        );
        transport.responses.insert(
            history_url(),
            TransportResponse {
                status: history_status,
                body: Vec::new(),
            },
        );
        let requests = Rc::clone(&transport.requests);
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
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
        fast_url(),
        TransportResponse {
            status: 200,
            body: FAST.to_vec(),
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
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
        },
        TransportResponse {
            status: 200,
            body: WRONG_ROOT.to_vec(),
        },
    ] {
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
                body: b"Package: Matrix\nVersion: 1.8-0\n".to_vec(),
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
            },
        );
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
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
