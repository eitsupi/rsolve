use sha2::{Digest, Sha256};

#[test]
fn current_index_is_authoritative_over_same_identity_archive_metadata() {
    let consistent = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: RSOLVE Fictional Terms Matrix\nNeedsCompilation: yes\n";
    let transport = session_transport(
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
            body: consistent.to_vec(),
            ..TransportResponse::default()
        },
    );
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    let releases = snapshot
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    assert_eq!(releases.len(), 2);
    assert_eq!(
        releases
            .iter()
            .find(|release| release.version().to_string() == "1.7-0")
            .and_then(|release| release.metadata().fields().get("License"))
            .map(String::as_str),
        Some("RSOLVE Fictional Terms Matrix")
    );

    let conflicting = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: conflicting\nNeedsCompilation: yes\n";
    let transport = session_transport(
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
            body: conflicting.to_vec(),
            ..TransportResponse::default()
        },
    );
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    let releases = snapshot
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    assert_eq!(releases.len(), 2);
    assert_eq!(
        releases
            .iter()
            .find(|release| release.version().to_string() == "1.7-0")
            .and_then(|release| release.metadata().fields().get("License"))
            .map(String::as_str),
        Some("conflicting")
    );
}

#[test]
fn current_projection_storage_failure_does_not_retry_transport() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let body = current_gzip_body();
    let first_transport = session_transport(
        TransportResponse::new(404, Vec::new()),
        TransportResponse {
            status: 200,
            body: body.clone(),
            headers: TransportResponseHeaders {
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "max-age=3600".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:00Z".parse().unwrap()),
        Some(cache),
    );
    first.ensure_current().unwrap();
    drop(first);

    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_gzip_url(), RawCacheRepresentation::CurrentGzip)
        .unwrap();
    let digest = Sha256::digest(&body);
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let projection = cache.projection_path_in_namespace(
        crate::cran::provider::raw_cache::ProjectionNamespace::Current,
        &key,
        &digest,
    );
    std::fs::remove_file(&projection).unwrap();
    std::fs::create_dir(&projection).unwrap();

    let second_transport = FixtureTransport {
        responses: HashMap::new(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let requests = second_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(cache),
    );
    let error = second.ensure_current().unwrap_err();
    assert!(error.diagnostic().contains("projection storage failed"));
    let observed = requests.borrow();
    assert!(
        observed.is_empty(),
        "unexpected recovery requests: {observed:?}"
    );
}

#[test]
fn corrupt_current_package_projection_rebuilds_from_cached_raw_without_transport() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let body = current_gzip_body();
    let first_transport = session_transport(
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(200, body.clone()),
        TransportResponse::new(404, Vec::new()),
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:00Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    first.ensure_current().unwrap();
    drop(first);

    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_gzip_url(), RawCacheRepresentation::CurrentGzip)
        .unwrap();
    let digest = Sha256::digest(&body);
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let projection = cache.projection_path_in_namespace(
        crate::cran::provider::raw_cache::ProjectionNamespace::Current,
        &key,
        &digest,
    );
    crate::cran::provider::raw_cache::projection::overwrite_projection_package(
        &projection,
        "Matrix",
        vec![0xff],
    );

    let mut second_transport = session_transport(
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    second_transport
        .responses
        .insert(history_url(), TransportResponse::new(404, Vec::new()));
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", "").without_allpackages_history(),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    CranRefreshSession::<FixtureTransport>::reset_current_projection_build_count();
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .expect("corrupt package payload should self-heal from the raw cache");
    assert_eq!(
        CranRefreshSession::<FixtureTransport>::current_projection_build_count(),
        1
    );
    assert!(
        !requests
            .borrow()
            .iter()
            .any(|request| request.url == current_gzip_url()),
        "unexpected current index recovery requests: {:?}",
        requests.borrow()
    );
}

#[test]
fn semantically_invalid_current_package_projection_rebuilds_from_cached_raw() {
    #[derive(serde::Serialize)]
    struct TestRecord {
        record_index: usize,
        package: String,
        fields: Vec<(String, String)>,
    }

    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let body = current_gzip_body();
    let first_transport = session_transport(
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(200, body.clone()),
        TransportResponse::new(404, Vec::new()),
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:00Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    first.ensure_current().unwrap();
    drop(first);

    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_gzip_url(), RawCacheRepresentation::CurrentGzip)
        .unwrap();
    let digest = Sha256::digest(&body);
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let projection = cache.projection_path_in_namespace(
        crate::cran::provider::raw_cache::ProjectionNamespace::Current,
        &key,
        &digest,
    );
    let payload = postcard::to_stdvec(&vec![TestRecord {
        record_index: 0,
        package: "Matrix".into(),
        fields: vec![
            ("Package".into(), "Matrix".into()),
            ("Version".into(), "not-a-version".into()),
        ],
    }])
    .unwrap();
    crate::cran::provider::raw_cache::projection::overwrite_projection_package(
        &projection,
        "Matrix",
        payload,
    );

    let mut second_transport = session_transport(
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    second_transport
        .responses
        .insert(history_url(), TransportResponse::new(404, Vec::new()));
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", "").without_allpackages_history(),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    CranRefreshSession::<FixtureTransport>::reset_current_projection_build_count();
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .expect("semantic projection corruption should self-heal");
    assert_eq!(
        CranRefreshSession::<FixtureTransport>::current_projection_build_count(),
        1
    );
    assert!(
        !requests
            .borrow()
            .iter()
            .any(|request| request.url == current_gzip_url())
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
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let catalog = session
        .ensure_current()
        .expect("a Recommended overlay must not make the complete current index invalid");
    assert_eq!(catalog.candidates_named("rlang").unwrap().len(), 1);
    assert_eq!(catalog.candidates_named("survival").unwrap().len(), 1);
    session
        .refresh_package(&PackageName::new("survival").unwrap())
        .unwrap();

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
                    ..TransportResponse::default()
                },
            ),
            (
                current_gzip_url(),
                TransportResponse {
                    status: 410,
                    body: Vec::new(),
                    ..TransportResponse::default()
                },
            ),
            (
                current_plain_url(),
                TransportResponse {
                    status: 503,
                    body: Vec::new(),
                    ..TransportResponse::default()
                },
            ),
        ]),
    ] {
        let transport = FixtureTransport {
            responses,
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let mut session = CranRefreshSession::new(
            Rc::new(transport),
            CranMetadataConfig::new("https://cran.invalid", ""),
        );
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
            ..TransportResponse::default()
        },
    );
    responses.insert(
        current_gzip_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    responses.insert(
        current_plain_url(),
        TransportResponse {
            status: 503,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    let transport = FixtureTransport {
        responses,
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let error = session.ensure_current().unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
}

#[test]
fn persistent_current_index_cache_reuse_avoids_a_second_request() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "max-age=3600".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse {
            status: 200,
            body: current_gzip_body(),
            headers: TransportResponseHeaders {
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "max-age=3600".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
    );
    let first_requests = first_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    CranRefreshSession::<FixtureTransport>::reset_current_projection_build_count();
    first.ensure_current().unwrap();
    assert_eq!(
        CranRefreshSession::<FixtureTransport>::current_projection_build_count(),
        1
    );
    assert_eq!(
        first_requests
            .borrow()
            .iter()
            .filter(|request| request.url == current_gzip_url())
            .count(),
        1
    );

    let second_transport = session_transport(
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let second_requests = second_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    CranRefreshSession::<FixtureTransport>::reset_current_projection_build_count();
    second.ensure_current().unwrap();
    assert_eq!(
        CranRefreshSession::<FixtureTransport>::current_projection_build_count(),
        0
    );
    assert!(second.evidence.borrow().is_empty());
    assert!(second_requests.borrow().is_empty());
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let evidence = second.evidence.borrow();
    let current_evidence = evidence
        .iter()
        .filter(|observation| observation.source.representation == "gzip")
        .collect::<Vec<_>>();
    assert!(!current_evidence.is_empty());
    assert!(
        current_evidence
            .iter()
            .all(|observation| observation.package.as_str() == "Matrix")
    );
}

#[test]
fn current_projection_preserves_global_record_indices_for_lazy_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(
        &mut encoder,
        b"Package: other\nVersion: 1.0\nLicense: MIT\n\n\
Package: Matrix\nVersion: 1.7-6\nLicense: MIT\n",
    )
    .unwrap();
    let body = encoder.finish().unwrap();
    let transport = session_transport(
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(200, body),
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:00Z".parse().unwrap()),
        Some(cache),
    );
    session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let evidence = session.evidence.borrow();
    let current = evidence
        .iter()
        .filter(|observation| observation.source.representation == "gzip")
        .collect::<Vec<_>>();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].package.as_str(), "Matrix");
    assert_eq!(current[0].record_index, 1);
}

#[test]
fn refresh_metadata_revalidates_a_fresh_raw_cache_entry() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = session_transport(
        TransportResponse::new(200, NATIVE_UTF8_CURRENT.to_vec()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    first.ensure_current().unwrap();

    let second_transport = session_transport(
        TransportResponse::new(200, NATIVE_UTF8_CURRENT.to_vec()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let requests = second_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", "").with_refresh_metadata(),
        Some(t0),
        Some(cache),
    );
    assert!(second.refresh_metadata);
    second.ensure_current().unwrap();
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|request| request.url == current_rds_url())
            .count(),
        1
    );
}

#[test]
fn persistent_refresh_path_uses_current_cache_across_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "max-age=3600".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    crate::cran::provider::refresh_and_publish_with_transport(
        &store,
        first_transport,
        "https://cran.invalid",
        &[PackageName::new("Matrix").unwrap()],
    )
    .unwrap();

    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_rds_url(), RawCacheRepresentation::CurrentRds)
        .unwrap();
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Hit(_)));
    let second_transport = FixtureTransport::fallback(FAST.to_vec(), 200);
    let requests = second_transport.requests.clone();
    crate::cran::provider::refresh_and_publish_with_transport(
        &store,
        second_transport,
        "https://cran.invalid",
        &[PackageName::new("Matrix").unwrap()],
    )
    .unwrap();
    assert!(
        !requests
            .borrow()
            .iter()
            .any(|request| request.url == current_rds_url())
    );
}

#[test]
fn stale_current_cache_revalidates_with_validators_and_304() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let etag = "\"current-etag\"";
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                etag: Some(etag.into()),
                last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".into()),
                retry_after: None,
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "no-cache".into(),
                ),
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    first.ensure_current().unwrap();

    let second_transport = session_transport(
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: TransportResponseHeaders {
                etag: Some("\"refreshed-etag\"".into()),
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "max-age=120".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let second_requests = second_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_rds_url(), RawCacheRepresentation::CurrentRds)
        .unwrap();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(cache),
    );
    second.ensure_current().unwrap();
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let requests = second_requests.borrow();
    let request = requests
        .iter()
        .find(|request| request.url == current_rds_url())
        .unwrap();
    assert_eq!(request.validators.if_none_match.as_deref(), Some(etag));
    assert_eq!(
        request.validators.if_modified_since.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    drop(requests);
    let evidence = second.evidence.borrow();
    let source = &evidence[0].source;
    assert_eq!(source.observed_at, "2026-08-23T00:00:00Z");
    assert_eq!(source.etag.as_deref(), Some("\"refreshed-etag\""));
    assert_eq!(
        source.last_modified.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    let RawCacheLookup::Hit(entry) = RawCache::open(&store).unwrap().lookup(&key) else {
        panic!("expected revalidated raw cache entry")
    };
    assert_eq!(entry.observed_at, t0);
    assert_eq!(entry.validated_at, "2026-08-23T00:00:01Z".parse().unwrap());
    assert_eq!(entry.etag.as_deref(), Some("\"refreshed-etag\""));
    assert_eq!(
        entry.last_modified.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    assert_eq!(
        entry.cache_control,
        crate::cran::provider::cache_policy::CacheControlHeader::Valid("max-age=120".into())
    );
}

#[test]
fn stale_current_cache_304_no_store_evicts_entry_after_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                etag: Some("\"current-etag\"".into()),
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "no-cache".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    first.ensure_current().unwrap();

    let second_transport = session_transport(
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: TransportResponseHeaders {
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "no-store".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    second
        .ensure_current()
        .expect("validated cached body remains usable for this refresh");
    let key = crate::cran::provider::raw_cache::RawCache::open(&store)
        .unwrap()
        .key(&current_rds_url(), RawCacheRepresentation::CurrentRds)
        .unwrap();
    assert!(matches!(
        crate::cran::provider::raw_cache::RawCache::open(&store)
            .unwrap()
            .lookup(&key),
        RawCacheLookup::Missing
    ));
}

#[test]
fn fresh_semantically_invalid_current_cache_recovers_unconditionally() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_rds_url(), RawCacheRepresentation::CurrentRds)
        .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    cache
        .publish(
            &key,
            RawCacheWrite {
                status: 200,
                body: WRONG_ROOT.to_vec(),
                observed_at: t0,
                validated_at: t0,
                etag: None,
                last_modified: None,
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "max-age=3600".into(),
                ),
            },
        )
        .unwrap();
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    session.ensure_current().unwrap();
    let requests = requests.borrow();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url == current_rds_url())
            .count(),
        1
    );
}

#[test]
fn stale_current_cache_without_validators_uses_unconditional_request() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "no-cache".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    first.ensure_current().unwrap();

    let second_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let requests = second_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(cache),
    );
    second.ensure_current().unwrap();
    let request = requests
        .borrow()
        .iter()
        .find(|request| request.url == current_rds_url())
        .unwrap()
        .clone();
    assert_eq!(request.validators, TransportValidators::default());
}

#[test]
fn invalid_network_current_response_is_not_persisted() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_rds_url(), RawCacheRepresentation::CurrentRds)
        .unwrap();
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: WRONG_ROOT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:00Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    assert!(session.ensure_current().is_err());
    assert!(matches!(
        crate::cran::provider::raw_cache::RawCache::open(&store)
            .unwrap()
            .lookup(&key),
        RawCacheLookup::Missing
    ));
}

#[test]
fn current_absence_with_absent_archive_sources_is_empty() {
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
use super::*;
use crate::cran::provider::raw_cache::{
    RawCache, RawCacheLookup, RawCacheRepresentation, RawCacheWrite,
};
