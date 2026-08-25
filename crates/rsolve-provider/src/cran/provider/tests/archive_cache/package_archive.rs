#[test]
fn empty_package_archive_stale_cache_reuses_body_after_304() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let etag = "\"empty-archive-etag\"";
    let mut first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=3600".into()),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    first_transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 200,
            body: EMPTY_FAST.to_vec(),
            headers: TransportResponseHeaders {
                etag: Some(etag.into()),
                cache_control: CacheControlHeader::Valid("no-cache".into()),
                ..TransportResponseHeaders::default()
            },
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();

    let mut second_transport = empty_transport();
    second_transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=120".into()),
                ..TransportResponseHeaders::default()
            },
        },
    );
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .expect("304 empty archive cache");
    assert_eq!(requests.borrow().len(), 1);
    assert_eq!(requests.borrow()[0].url, fast_url());
    assert_eq!(
        requests.borrow()[0].validators.if_none_match.as_deref(),
        Some(etag)
    );
    let diagnostic = second
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.endpoint() == fast_url())
        .expect("empty archive 304 diagnostic");
    assert_eq!(diagnostic.status(), Some(304));
    assert_eq!(diagnostic.status_detail(), &CranFastPathStatus::Available);
}

#[test]
fn mixed_archive_semantic_rejection_stays_on_fast_path_without_history_or_tarballs() {
    let mut transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    transport.responses.insert(
        fast_url(),
        TransportResponse::new(200, mixed_semantic_archive_index()),
    );
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let releases = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(
        releases
            .candidates()
            .iter()
            .filter(|release| release.version().as_str() == "1.6-5"
                || release.version().as_str() == "1.7-0")
            .count(),
        1
    );
    assert!(!requests.borrow().iter().any(|request| {
        request.url == history_url() || request.url == old_url() || request.url == new_url()
    }));
    let diagnostic = session
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.endpoint() == fast_url())
        .expect("partial fast-path diagnostic");
    assert!(matches!(
        diagnostic.status_detail(),
        CranFastPathStatus::AvailableWithRejections {
            count: 1,
            diagnostic,
        } if diagnostic.contains("first: record 0 (Matrix):")
    ));
    let evidence = session.evidence.borrow();
    let rejected = evidence
        .iter()
        .find(|observation| {
            matches!(
                observation.axes.semantics,
                crate::snapshot::SemanticsStateV1::Invalid
            )
        })
        .expect("archive rejection evidence");
    assert_eq!(rejected.package.as_str(), "Matrix");
    assert!(rejected.release.is_none());
    assert!(matches!(
        rejected.axes.namespace,
        crate::snapshot::NamespaceStateV1::Established
    ));
}

#[test]
fn nlme_dependency_rejection_survives_fresh_and_304_archive_cache_replay() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let cache_headers = TransportResponseHeaders {
        etag: Some("\"nlme-archive\"".into()),
        cache_control: CacheControlHeader::Valid("max-age=3600".into()),
        ..TransportResponseHeaders::default()
    };
    let mut first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: cache_headers.clone(),
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    first_transport.responses.insert(
        fast_url_for("nlme"),
        TransportResponse {
            status: 200,
            body: NLME_ARCHIVE.to_vec(),
            headers: cache_headers.clone(),
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let package = PackageName::new("nlme").unwrap();
    let first_result = first.refresh_package(&package).expect("network archive");
    assert_eq!(
        release_signature(first_result.candidates()),
        vec!["3.1-167", "3.1-168"]
    );
    assert_eq!(first_result.quarantined().len(), 1);
    assert_eq!(first_result.quarantined()[0].version().as_str(), "3.1-166");

    let fresh_transport = empty_transport();
    let fresh_requests = fresh_transport.requests.clone();
    let mut fresh = CranRefreshSession::new_with_clock(
        Rc::new(fresh_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let fresh_result = fresh
        .refresh_package(&package)
        .expect("fresh archive cache");
    assert!(fresh_requests.borrow().is_empty());
    assert_eq!(
        release_signature(fresh_result.candidates()),
        vec!["3.1-167", "3.1-168"]
    );
    assert_eq!(fresh_result.quarantined().len(), 1);

    let mut stale_transport = empty_transport();
    stale_transport.responses.insert(
        current_rds_url(),
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: cache_headers.clone(),
        },
    );
    stale_transport.responses.insert(
        fast_url_for("nlme"),
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: cache_headers,
        },
    );
    let stale_requests = stale_transport.requests.clone();
    let mut stale = CranRefreshSession::new_with_clock(
        Rc::new(stale_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T01:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let stale_result = stale.refresh_package(&package).expect("304 archive cache");
    assert_eq!(
        release_signature(stale_result.candidates()),
        vec!["3.1-167", "3.1-168"]
    );
    assert_eq!(stale_result.quarantined().len(), 1);
    assert_eq!(stale_requests.borrow().len(), 2);
    assert!(
        stale_requests
            .borrow()
            .iter()
            .all(|request| request.validators.if_none_match.as_deref() == Some("\"nlme-archive\""))
    );
}

#[test]
fn nlme_invalid_version_survives_fresh_and_304_archive_cache_replay() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let cache_headers = TransportResponseHeaders {
        etag: Some("\"nlme-invalid-version-archive\"".into()),
        cache_control: CacheControlHeader::Valid("max-age=3600".into()),
        ..TransportResponseHeaders::default()
    };
    let mut first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: cache_headers.clone(),
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    first_transport.responses.insert(
        fast_url_for("nlme"),
        TransportResponse {
            status: 200,
            body: NLME_INVALID_VERSION_ARCHIVE.to_vec(),
            headers: cache_headers.clone(),
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let package = PackageName::new("nlme").unwrap();
    let first_result = first.refresh_package(&package).expect("network archive");
    assert_eq!(
        release_signature(first_result.candidates()),
        vec!["3.1-167", "3.1-168"]
    );
    assert!(first_result.quarantined().is_empty());
    let evidence = first.evidence.borrow();
    let observation = evidence
        .iter()
        .find(|observation| {
            observation.package.as_str() == "nlme"
                && matches!(
                    observation.axes.semantics,
                    crate::snapshot::SemanticsStateV1::Invalid
                )
        })
        .expect("nlme archive evidence");
    assert!(observation.artifact.is_none());
    assert!(matches!(
        observation.axes.occurrence,
        crate::snapshot::OccurrenceStateV1::ObservationOnly
    ));
    assert!(matches!(
        observation.axes.semantics,
        crate::snapshot::SemanticsStateV1::Invalid
    ));

    let fresh_transport = empty_transport();
    let fresh_requests = fresh_transport.requests.clone();
    let mut fresh = CranRefreshSession::new_with_clock(
        Rc::new(fresh_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let fresh_result = fresh
        .refresh_package(&package)
        .expect("fresh archive cache");
    assert!(fresh_requests.borrow().is_empty());
    assert_eq!(
        release_signature(fresh_result.candidates()),
        vec!["3.1-167", "3.1-168"]
    );
    assert!(fresh_result.quarantined().is_empty());

    let mut stale_transport = empty_transport();
    stale_transport.responses.insert(
        current_rds_url(),
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: cache_headers.clone(),
        },
    );
    stale_transport.responses.insert(
        fast_url_for("nlme"),
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: cache_headers,
        },
    );
    let stale_requests = stale_transport.requests.clone();
    let mut stale = CranRefreshSession::new_with_clock(
        Rc::new(stale_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T01:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let stale_result = stale.refresh_package(&package).expect("304 archive cache");
    assert_eq!(
        release_signature(stale_result.candidates()),
        vec!["3.1-167", "3.1-168"]
    );
    assert!(stale_result.quarantined().is_empty());
    assert_eq!(stale_requests.borrow().len(), 2);
    assert!(stale_requests.borrow().iter().all(|request| {
        request.validators.if_none_match.as_deref() == Some("\"nlme-invalid-version-archive\"")
    }));
}

#[test]
fn archive_rejection_survives_snapshot_roundtrip_and_keeps_valid_sibling_visible() {
    let (_directory, store) = store();
    let mut transport = session_transport(
        TransportResponse::new(200, NATIVE_UTF8_CURRENT.to_vec()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    transport.responses.insert(
        fast_url(),
        TransportResponse::new(200, mixed_semantic_archive_index()),
    );
    let loader = refresh_and_publish_with_transport(
        &store,
        transport,
        "https://cran.invalid",
        &[PackageName::new("Matrix").unwrap()],
    )
    .expect("mixed archive snapshot should publish");
    let releases = loader
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    assert!(
        releases
            .iter()
            .any(|release| release.version().as_str() == "1.7-0")
    );
    assert!(
        releases
            .iter()
            .any(|release| release.version().as_str() == "1.7-6")
    );
    assert_eq!(loader.header().observation_count, 3);

    let offline = store.read_current().unwrap();
    let offline_releases = offline
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    assert_eq!(
        offline_releases
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>(),
        releases
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn invalid_version_archive_survives_snapshot_roundtrip_and_keeps_valid_siblings_visible() {
    let (_directory, store) = store();
    let mut transport = session_transport(
        TransportResponse::new(200, NATIVE_UTF8_CURRENT.to_vec()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    transport.responses.insert(
        fast_url_for("nlme"),
        TransportResponse::new(200, NLME_INVALID_VERSION_ARCHIVE.to_vec()),
    );
    let loader = refresh_and_publish_with_transport(
        &store,
        transport,
        "https://cran.invalid",
        &[PackageName::new("nlme").unwrap()],
    )
    .expect("invalid-version archive snapshot should publish");
    let releases = loader
        .releases(&SolverKey::InstalledName(PackageName::new("nlme").unwrap()))
        .unwrap();
    assert_eq!(
        releases
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>(),
        vec!["3.1-167", "3.1-168"]
    );
    assert_eq!(loader.header().observation_count, 3);

    let offline = store.read_current().unwrap();
    let offline_releases = offline
        .releases(&SolverKey::InstalledName(PackageName::new("nlme").unwrap()))
        .unwrap();
    assert_eq!(
        offline_releases
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>(),
        vec!["3.1-167", "3.1-168"]
    );
}

#[test]
fn mixed_archive_fresh_raw_cache_replay_is_network_free_and_deterministic() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let mut first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=3600".into()),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    first_transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 200,
            body: mixed_semantic_archive_index(),
            headers: TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=3600".into()),
                ..TransportResponseHeaders::default()
            },
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let first_releases = first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let expected_releases = release_signature(first_releases.candidates());
    let expected_detail = partial_fast_path_detail(&first);

    let second_transport = empty_transport();
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let second_releases = second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(requests.borrow().is_empty());
    assert_eq!(
        release_signature(second_releases.candidates()),
        expected_releases
    );
    assert_eq!(partial_fast_path_detail(&second), expected_detail);
    assert!(!requests.borrow().iter().any(|request| {
        request.url == history_url() || request.url == old_url() || request.url == new_url()
    }));
}

#[test]
fn mixed_archive_stale_304_replay_is_deterministic_without_fallback() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let etag = "\"mixed-archive-etag\"";
    let mut first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=3600".into()),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    first_transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 200,
            body: mixed_semantic_archive_index(),
            headers: TransportResponseHeaders {
                etag: Some(etag.into()),
                cache_control: CacheControlHeader::Valid("no-cache".into()),
                ..TransportResponseHeaders::default()
            },
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let first_releases = first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let expected_releases = release_signature(first_releases.candidates());
    let expected_detail = partial_fast_path_detail(&first);

    let mut second_transport = empty_transport();
    second_transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=120".into()),
                ..TransportResponseHeaders::default()
            },
        },
    );
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let second_releases = second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(
        release_signature(second_releases.candidates()),
        expected_releases
    );
    assert_eq!(partial_fast_path_detail(&second), expected_detail);
    assert_eq!(
        second
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.endpoint() == fast_url())
            .unwrap()
            .status(),
        Some(304)
    );
    assert_eq!(requests.borrow().len(), 1);
    assert_eq!(
        requests.borrow()[0].validators.if_none_match.as_deref(),
        Some(etag)
    );
    assert!(!requests.borrow().iter().any(|request| {
        request.url == history_url() || request.url == old_url() || request.url == new_url()
    }));
}

#[test]
fn all_archive_semantic_rejections_fail_without_fallback_or_raw_cache_publish() {
    let (_directory, store) = store();
    let mut transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=3600".into()),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    transport.responses.insert(
        fast_url(),
        TransportResponse::new(200, all_semantic_invalid_archive_index()),
    );
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let error = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .expect_err("all semantic rows must fail closed");
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
    assert!(!requests.borrow().iter().any(|request| {
        request.url == history_url() || request.url == old_url() || request.url == new_url()
    }));
    let key = RawCache::open(&store)
        .unwrap()
        .key(&fast_url(), RawCacheRepresentation::PackageArchiveIndexRds)
        .unwrap();
    assert!(matches!(
        RawCache::open(&store).unwrap().lookup(&key),
        RawCacheLookup::Missing
    ));
}

#[test]
fn archive_identity_failure_is_hard_without_history_fallback() {
    let mut transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    transport.responses.insert(
        fast_url(),
        TransportResponse::new(200, ROOT_DUPLICATE_ARCHIVE.to_vec()),
    );
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let error = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .expect_err("identity conflicts must fail closed");
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
    assert!(
        !requests
            .borrow()
            .iter()
            .any(|request| request.url == history_url())
    );
}

#[test]
fn tarball_fallback_does_not_receive_metadata_validators_or_enter_raw_cache() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let current = TransportResponse {
        status: 200,
        body: NATIVE_UTF8_CURRENT.to_vec(),
        headers: TransportResponseHeaders {
            cache_control: CacheControlHeader::Valid("max-age=3600".into()),
            ..TransportResponseHeaders::default()
        },
    };
    let mut first_transport = session_transport(
        current,
        TransportResponse::new(404, vec![]),
        TransportResponse::new(404, vec![]),
    );
    first_transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 200,
            body: FAST.to_vec(),
            headers: TransportResponseHeaders {
                etag: Some("\"fast-etag\"".into()),
                cache_control: CacheControlHeader::Valid("no-cache".into()),
                ..TransportResponseHeaders::default()
            },
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let entries_before_fallback = std::fs::read_dir(store.root().join("raw-cache/v1"))
        .unwrap()
        .count();

    let mut second_transport = empty_transport();
    second_transport
        .responses
        .insert(fast_url(), TransportResponse::new(404, Vec::new()));
    second_transport.responses.insert(
        history_url(),
        TransportResponse {
            status: 200,
            body: HISTORY.to_vec(),
            ..TransportResponse::default()
        },
    );
    second_transport.responses.insert(
        old_url(),
        TransportResponse {
            status: 200,
            body: OLD_TAR.to_vec(),
            ..TransportResponse::default()
        },
    );
    second_transport.responses.insert(
        new_url(),
        TransportResponse {
            status: 200,
            body: NEW_TAR.to_vec(),
            ..TransportResponse::default()
        },
    );
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let entries_after_fallback = std::fs::read_dir(store.root().join("raw-cache/v1"))
        .unwrap()
        .count();
    assert_eq!(entries_after_fallback, entries_before_fallback + 1);
    let requests = requests.borrow();
    assert_eq!(
        requests
            .iter()
            .find(|request| request.url == fast_url())
            .unwrap()
            .validators
            .if_none_match
            .as_deref(),
        Some("\"fast-etag\"")
    );
    for url in [old_url(), new_url()] {
        assert_eq!(
            requests
                .iter()
                .find(|request| request.url == url)
                .unwrap()
                .validators,
            TransportValidators::default()
        );
    }
}

#[test]
fn invalid_cached_archive_body_is_retried_and_invalid_200_is_not_published() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let cache = RawCache::open(&store).unwrap();
    let key = cache
        .key(&history_url(), RawCacheRepresentation::ArchiveHistoryRds)
        .unwrap();
    cache
        .publish(
            &key,
            RawCacheWrite {
                status: 200,
                body: b"not an archive".to_vec(),
                observed_at: t0,
                validated_at: t0,
                etag: Some("\"bad-cache\"".into()),
                last_modified: None,
                cache_control: CacheControlHeader::Valid("max-age=3600".into()),
            },
        )
        .unwrap();
    let transport = FixtureTransport {
        responses: [(
            history_url(),
            TransportResponse {
                status: 200,
                body: b"still invalid".to_vec(),
                ..TransportResponse::default()
            },
        )]
        .into_iter()
        .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let error = match session.ensure_history() {
        Ok(_) => panic!("invalid archive response unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
    assert_eq!(requests.borrow().len(), 1);
    let RawCacheLookup::Hit(entry) = RawCache::open(&store).unwrap().lookup(&key) else {
        panic!("invalid response must not replace the cache entry")
    };
    assert_eq!(entry.body, b"not an archive");
}
use super::*;
use crate::cran::provider::cache_policy::CacheControlHeader;
use crate::cran::provider::raw_cache::{
    RawCache, RawCacheLookup, RawCacheRepresentation, RawCacheWrite,
};

#[test]
fn package_archive_fresh_cache_hit_avoids_network() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let current = TransportResponse {
        status: 200,
        body: NATIVE_UTF8_CURRENT.to_vec(),
        headers: TransportResponseHeaders {
            cache_control: CacheControlHeader::Valid("max-age=3600".into()),
            ..TransportResponseHeaders::default()
        },
    };
    let fast = TransportResponse {
        status: 200,
        body: FAST.to_vec(),
        headers: TransportResponseHeaders {
            cache_control: CacheControlHeader::Valid("max-age=3600".into()),
            ..TransportResponseHeaders::default()
        },
    };
    let first_transport = session_transport(
        current.clone(),
        TransportResponse::new(404, vec![]),
        TransportResponse::new(404, vec![]),
    );
    let mut first_transport = first_transport;
    first_transport.responses.insert(fast_url(), fast);
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();

    let second_transport = empty_transport();
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(requests.borrow().is_empty());
}

#[test]
fn empty_package_archive_network_response_is_available_without_fallback() {
    let mut transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    transport
        .responses
        .insert(fast_url(), TransportResponse::new(200, EMPTY_FAST.to_vec()));
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let releases = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .expect("empty archive fast path");
    assert_eq!(releases.candidates().len(), 1);
    assert!(
        requests
            .borrow()
            .iter()
            .any(|request| request.url == fast_url())
    );
    assert!(!requests.borrow().iter().any(|request| {
        request.url == history_url() || request.url == old_url() || request.url == new_url()
    }));
    let diagnostic = session
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.endpoint() == fast_url())
        .expect("empty archive fast-path diagnostic");
    assert_eq!(diagnostic.status_detail(), &CranFastPathStatus::Available);
}

#[test]
fn empty_package_archive_fresh_cache_hit_avoids_network() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let mut first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=3600".into()),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    first_transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 200,
            body: EMPTY_FAST.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=3600".into()),
                ..TransportResponseHeaders::default()
            },
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();

    let second_transport = empty_transport();
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .expect("fresh empty archive cache");
    assert!(requests.borrow().is_empty());
    assert_eq!(
        second
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.endpoint() == fast_url())
            .map(|diagnostic| diagnostic.status_detail()),
        Some(&CranFastPathStatus::Available)
    );
}
