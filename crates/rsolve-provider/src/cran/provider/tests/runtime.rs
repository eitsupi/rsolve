use super::*;

#[test]
fn runtime_loader_caches_each_package_provider_and_its_candidates() {
    let transport = FixtureTransport::fallback(Vec::new(), 404);
    let requests = Rc::clone(&transport.requests);
    let loader = runtime_loader(transport);
    let package = SolverKey::InstalledName(PackageName::new("Matrix").unwrap());

    assert_eq!(loader.releases(&package).unwrap().len(), 2);
    assert!(matches!(
        loader.diagnostics()[0].status_detail(),
        CranFastPathStatus::Absent { status: 404 }
    ));
    assert_eq!(requests.borrow().len(), 4);
    assert_eq!(requests.borrow()[0], fast_url());
    assert_eq!(requests.borrow()[1], history_url());
    assert_eq!(requests.borrow()[2], old_url());
    assert_eq!(requests.borrow()[3], new_url());

    assert_eq!(loader.releases(&package).unwrap().len(), 2);
    assert_eq!(requests.borrow().len(), 4);
}

#[test]
fn runtime_loader_invalid_fast_path_falls_back_to_history() {
    let transport = FixtureTransport::fallback(WRONG_ROOT.to_vec(), 200);
    let requests = Rc::clone(&transport.requests);
    let loader = runtime_loader(transport);
    let package = SolverKey::InstalledName(PackageName::new("Matrix").unwrap());

    assert_eq!(loader.releases(&package).unwrap().len(), 2);
    assert!(matches!(
        loader.diagnostics()[0].status_detail(),
        CranFastPathStatus::Invalid { status: 200, .. }
    ));
    assert_eq!(requests.borrow().len(), 4);
    assert_eq!(requests.borrow()[0], fast_url());
    assert_eq!(requests.borrow()[1], history_url());
}

#[test]
fn refresh_session_falls_back_to_plain_current_and_freezes_without_network() {
    let current = b"Package: Matrix\nVersion: 1.8-0\nLicense: RSOLVE Fictional Current\n";
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
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    let before = requests.borrow().len();
    let releases = snapshot
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    assert_eq!(releases.len(), 3);
    assert_eq!(requests.borrow().len(), before);
    assert_eq!(requests.borrow()[0], current_rds_url());
    assert_eq!(requests.borrow()[1], current_gzip_url());
    assert_eq!(requests.borrow()[2], current_plain_url());
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &history_url())
            .count(),
        1
    );
    assert!(
        !requests
            .borrow()
            .iter()
            .any(|url| url.contains("/Archive/methods/PACKAGES.rds"))
    );
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source()
            == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::PlainDcf)
    }));
}

#[test]
fn runtime_loader_size_mismatch_is_a_hard_acquisition_error() {
    let mut transport = FixtureTransport::fallback(Vec::new(), 404);
    transport.responses.get_mut(&old_url()).unwrap().body.pop();
    let loader = runtime_loader(transport);
    let error = loader
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
