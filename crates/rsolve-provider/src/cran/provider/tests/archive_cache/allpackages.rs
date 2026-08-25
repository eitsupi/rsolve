#[test]
fn allpackages_complete_feed_avoids_package_archive_request() {
    let (directory, store) = store();
    let entries = matrix_history_entries();
    assert!(!entries.is_empty());
    let transport = allpackages_transport(allpackages_fixture_body(&entries, true, None), false);
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let result = session.refresh_package(&PackageName::new("Matrix").unwrap());
    let result = result.unwrap();
    assert!(result.candidates().len() >= entries.len());
    assert!(session.evidence.borrow().iter().any(|observation| {
        observation.artifact.as_ref().is_some_and(|artifact| {
            artifact
                .checksums
                .iter()
                .any(|checksum| checksum.algorithm == "sha256-original")
        })
    }));
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|request| request.url
                == "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds")
            .count(),
        0
    );
    drop(directory);
}

#[test]
fn refresh_progress_orders_metadata_before_snapshot_publish_and_reports_fallback_once() {
    let (_directory, store) = store();
    let entries = matrix_history_entries();
    let omitted_entry = entries
        .iter()
        .position(|entry| {
            entry.package().as_str() == "Matrix" && entry.version().to_string() != "1.7-6"
        })
        .expect("fixture contains a historical Matrix release");
    let events = Rc::new(std::cell::RefCell::new(Vec::new()));
    let capture = Rc::clone(&events);
    let callback = Rc::new(move |event| capture.borrow_mut().push(event));
    crate::cran::provider::refresh_and_publish_with_transport_and_progress(
        &store,
        allpackages_transport(
            allpackages_fixture_body(&entries, true, Some(omitted_entry)),
            true,
        ),
        "https://cloud.r-project.org",
        &[
            PackageName::new("Matrix").unwrap(),
            PackageName::new("Matrix").unwrap(),
        ],
        Some(callback),
    )
    .unwrap();
    let events = events.borrow();
    let position = |predicate: fn(&CranRefreshProgress) -> bool| {
        events
            .iter()
            .position(predicate)
            .expect("progress event is present")
    };
    let current =
        position(|event| matches!(event, CranRefreshProgress::CurrentIndexCompleted { .. }));
    let history =
        position(|event| matches!(event, CranRefreshProgress::ArchiveHistoryCompleted { .. }));
    let qualified =
        position(|event| matches!(event, CranRefreshProgress::AllPackagesQualified { .. }));
    let fallback =
        position(|event| matches!(event, CranRefreshProgress::PackageLocalFallbackStarted));
    let published =
        position(|event| matches!(event, CranRefreshProgress::SnapshotPublishStarted { .. }));
    assert!(current < published);
    assert!(history < published);
    assert!(qualified < published);
    assert!(fallback < published);
    assert!(
        events
            .iter()
            .filter(|event| matches!(event, CranRefreshProgress::PackageLocalFallbackStarted))
            .count()
            == 1
    );
}

#[test]
fn allpackages_current_gap_keeps_current_and_bulk_history() {
    let (directory, store) = store();
    let entries = matrix_history_entries();
    let transport = allpackages_transport(allpackages_fixture_body(&entries, false, None), false);
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let result = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(
        result
            .candidates()
            .iter()
            .any(|release| release.version().to_string() == "1.7-6")
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|request| request.url
                == "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds")
            .count(),
        0
    );
    drop(directory);
}

#[test]
fn allpackages_fresh_second_session_reuses_projection_without_requests_or_rebuild() {
    let (_directory, store) = store();
    let entries = matrix_history_entries();
    let feed = allpackages_fixture_body(&entries, true, None);
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(allpackages_transport(feed.clone(), false)),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let first_result = first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let signature = release_signature(first_result.candidates());

    crate::cran::provider::allpackages::reset_test_counters();
    let second_transport = allpackages_transport(feed.clone(), false);
    let second_requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let second_result = second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(release_signature(second_result.candidates()), signature);
    assert!(second_requests.borrow().is_empty());
    assert_eq!(crate::cran::provider::allpackages::test_counters(), (0, 0));
    assert_eq!(
        crate::cran::provider::allpackages::classify_current_count(),
        0
    );

    // A changed qualification binding is not a reusable decision even when
    // every raw artifact remains fresh. The normal path must reclassify it.
    let qualification_path = RawCache::open(&store).unwrap().qualification_path();
    let mut mismatched = crate::cran::provider::qualification::load_result(&qualification_path)
        .unwrap()
        .unwrap();
    mismatched.current_digest = "changed-current-surface".into();
    crate::cran::provider::qualification::publish(&qualification_path, &mismatched).unwrap();
    crate::cran::provider::allpackages::reset_test_counters();
    crate::cran::provider::raw_cache::projection::reset_visit_package_records_count();
    let third_transport = allpackages_transport(feed, false);
    let third_requests = third_transport.requests.clone();
    let mut third = CranRefreshSession::new_with_clock(
        Rc::new(third_transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:02Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    third
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(third_requests.borrow().is_empty());
    assert!(crate::cran::provider::allpackages::classify_current_count() > 0);
    assert_eq!(
        crate::cran::provider::raw_cache::projection::visit_package_records_count(),
        1
    );
}

#[test]
fn allpackages_forced_refresh_304_and_same_digest_200_reopen_projection() {
    let (_directory, store) = store();
    let entries = matrix_history_entries();
    let feed = allpackages_fixture_body(&entries, true, None);
    let headers = TransportResponseHeaders {
        etag: Some("\"allpackages-e2e\"".into()),
        cache_control: CacheControlHeader::Valid("max-age=3600".into()),
        ..TransportResponseHeaders::default()
    };
    let mut first_transport = allpackages_transport(feed.clone(), false);
    first_transport.responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES.gz".into(),
        TransportResponse {
            status: 200,
            body: current_gzip_body(),
            headers: headers.clone(),
        },
    );
    first_transport.responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES.rds".into(),
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: headers.clone(),
        },
    );
    first_transport.responses.insert(
        "https://cloud.r-project.org/src/contrib/Meta/archive.rds".into(),
        TransportResponse {
            status: 200,
            body: HISTORY.to_vec(),
            headers: headers.clone(),
        },
    );
    first_transport.responses.insert(
        ALLPACKAGES_FIXTURE_URL.into(),
        TransportResponse {
            status: 200,
            body: feed.clone(),
            headers: headers.clone(),
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let signature = release_signature(
        first
            .refresh_package(&PackageName::new("Matrix").unwrap())
            .unwrap()
            .candidates(),
    );
    let qualification_path = RawCache::open(&store).unwrap().qualification_path();
    let mut degraded = crate::cran::provider::qualification::load_result(&qualification_path)
        .unwrap()
        .unwrap();
    degraded.status = crate::cran::provider::qualification::Status::Unknown;
    degraded.failure_count = 3;
    degraded.next_probe_at = Some("2026-08-26T00:00:00Z".into());
    crate::cran::provider::qualification::publish(&qualification_path, &degraded).unwrap();

    let mut not_modified = allpackages_transport(Vec::new(), false);
    for url in [
        "https://cloud.r-project.org/src/contrib/PACKAGES.gz".to_owned(),
        "https://cloud.r-project.org/src/contrib/PACKAGES.rds".to_owned(),
        "https://cloud.r-project.org/src/contrib/Meta/archive.rds".to_owned(),
        ALLPACKAGES_FIXTURE_URL.to_owned(),
    ] {
        not_modified.responses.insert(
            url,
            TransportResponse {
                status: 304,
                body: Vec::new(),
                headers: headers.clone(),
            },
        );
    }
    let requests = not_modified.requests.clone();
    crate::cran::provider::allpackages::reset_test_counters();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(not_modified),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL)
            .with_refresh_metadata(),
        Some("2026-08-25T01:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let second_result = second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(release_signature(second_result.candidates()), signature);
    assert_eq!(requests.borrow().len(), 3);
    assert_eq!(crate::cran::provider::allpackages::test_counters(), (0, 0));
    assert!(crate::cran::provider::allpackages::classify_current_count() > 0);
    assert!(requests.borrow().iter().all(|request| {
        request.validators.if_none_match.as_deref() == Some("\"allpackages-e2e\"")
    }));
    let qualification = crate::cran::provider::qualification::load_result(
        &RawCache::open(&store).unwrap().qualification_path(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        qualification.status,
        crate::cran::provider::qualification::Status::Positive
    );
    assert_eq!(qualification.failure_count, 0);
    assert_eq!(qualification.next_probe_at, None);

    let mut same_body = allpackages_transport(Vec::new(), false);
    same_body.responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES.gz".into(),
        TransportResponse {
            status: 200,
            body: current_gzip_body(),
            headers: headers.clone(),
        },
    );
    same_body.responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES.rds".into(),
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: headers.clone(),
        },
    );
    same_body.responses.insert(
        "https://cloud.r-project.org/src/contrib/Meta/archive.rds".into(),
        TransportResponse {
            status: 200,
            body: HISTORY.to_vec(),
            headers: headers.clone(),
        },
    );
    same_body.responses.insert(
        ALLPACKAGES_FIXTURE_URL.into(),
        TransportResponse {
            status: 200,
            body: feed,
            headers,
        },
    );
    crate::cran::provider::allpackages::reset_test_counters();
    let mut third = CranRefreshSession::new_with_clock(
        Rc::new(same_body),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL)
            .with_refresh_metadata(),
        Some("2026-08-25T02:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let third_result = third
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(release_signature(third_result.candidates()), signature);
    assert_eq!(crate::cran::provider::allpackages::test_counters(), (0, 0));
    assert!(crate::cran::provider::allpackages::classify_current_count() > 0);
}

#[test]
fn corrupt_projection_reports_diagnostic_falls_back_and_rebuilds_next_session() {
    let (_directory, store) = store();
    let entries = matrix_history_entries();
    let feed = allpackages_fixture_body(&entries, true, None);
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(allpackages_transport(feed.clone(), false)),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let cache = RawCache::open(&store).unwrap();
    let key = cache
        .key(
            ALLPACKAGES_FIXTURE_URL,
            RawCacheRepresentation::AllPackagesZstd,
        )
        .unwrap();
    let projection = cache.projection_path(&key, &feed);
    std::fs::write(&projection, b"corrupt projection").unwrap();
    assert!(projection.exists());

    let mut second_transport = allpackages_transport(feed.clone(), true);
    second_transport.responses.insert(
        ALLPACKAGES_FIXTURE_URL.into(),
        TransportResponse::new(500, Vec::new()),
    );
    let second_requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(second.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::AllPackages
            && matches!(diagnostic.status_detail(), CranFastPathStatus::Invalid { diagnostic, .. } if diagnostic.contains("projection"))
    }));
    assert!(second_requests.borrow().iter().any(|request| {
        request.url == "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds"
    }));

    crate::cran::provider::allpackages::reset_test_counters();
    let mut third = CranRefreshSession::new_with_clock(
        Rc::new(allpackages_transport(feed, true)),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL)
            .with_refresh_metadata(),
        Some("2026-08-25T00:00:02Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    third
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(crate::cran::provider::allpackages::test_counters(), (1, 1));
}

#[test]
fn custom_mirror_positive_reuses_actual_canonical_qualification_until_ttl() {
    let (_directory, store) = store();
    let entries = matrix_history_entries();
    let feed = allpackages_fixture_body(&entries, true, None);
    let mut first_transport = custom_mirror_transport(feed.clone(), HISTORY, false);
    let no_cache_headers = TransportResponseHeaders {
        cache_control: CacheControlHeader::Valid("no-cache".into()),
        ..TransportResponseHeaders::default()
    };
    first_transport.responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES.rds".into(),
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: no_cache_headers.clone(),
        },
    );
    first_transport.responses.insert(
        "https://cloud.r-project.org/src/contrib/Meta/archive.rds".into(),
        TransportResponse {
            status: 200,
            body: HISTORY.to_vec(),
            headers: no_cache_headers,
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://mirror.invalid", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let first_result = first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let signature = release_signature(first_result.candidates());
    let raw_cache = RawCache::open(&store).unwrap();
    let record = crate::cran::provider::qualification::load_result(&raw_cache.qualification_path())
        .unwrap()
        .unwrap();
    assert_eq!(
        record.status,
        crate::cran::provider::qualification::Status::Positive
    );
    assert!(!record.canonical_current_digest.is_empty());
    assert!(!record.canonical_archive_digest.is_empty());
    assert_eq!(record.canonical_current_digest, record.current_digest);
    assert_eq!(record.canonical_archive_digest, record.archive_digest);

    crate::cran::provider::allpackages::reset_test_counters();
    let second_transport = empty_transport();
    let second_requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://mirror.invalid", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T12:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let second_result = second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(release_signature(second_result.candidates()), signature);
    assert!(second_requests.borrow().is_empty());
    assert_eq!(crate::cran::provider::allpackages::test_counters(), (0, 0));
    assert_eq!(
        crate::cran::provider::allpackages::classify_current_count(),
        0
    );

    let third_transport = custom_mirror_transport(feed.clone(), HISTORY, false);
    let third_requests = third_transport.requests.clone();
    let mut third = CranRefreshSession::new_with_clock(
        Rc::new(third_transport),
        CranMetadataConfig::new("https://mirror.invalid", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-26T01:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    third
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(
        third_requests.borrow().iter().any(|request| {
            request.url == "https://cloud.r-project.org/src/contrib/PACKAGES.rds"
        })
    );
    assert!(third_requests.borrow().iter().any(|request| {
        request.url == "https://cloud.r-project.org/src/contrib/Meta/archive.rds"
    }));

    // An explicit refresh must revalidate canonical evidence even inside the
    // normal 24-hour qualification reuse window.
    let forced_transport = custom_mirror_transport(feed, HISTORY, false);
    let forced_requests = forced_transport.requests.clone();
    let mut forced = CranRefreshSession::new_with_clock(
        Rc::new(forced_transport),
        CranMetadataConfig::new("https://mirror.invalid", ALLPACKAGES_FIXTURE_URL)
            .with_refresh_metadata(),
        Some("2026-08-26T02:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    forced
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(
        forced_requests.borrow().iter().any(|request| {
            request.url == "https://cloud.r-project.org/src/contrib/PACKAGES.rds"
        })
    );
    assert!(forced_requests.borrow().iter().any(|request| {
        request.url == "https://cloud.r-project.org/src/contrib/Meta/archive.rds"
    }));
}

#[test]
fn malformed_positive_qualification_is_rebuilt_in_same_refresh() {
    let (_directory, store) = store();
    let entries = matrix_history_entries();
    let feed = allpackages_fixture_body(&entries, true, None);
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(custom_mirror_transport(feed.clone(), HISTORY, false)),
        CranMetadataConfig::new("https://mirror.invalid", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let raw_cache = RawCache::open(&store).unwrap();
    let qualification_path = raw_cache.qualification_path();
    assert_eq!(
        crate::cran::provider::qualification::load_result(&qualification_path)
            .unwrap()
            .unwrap()
            .status,
        crate::cran::provider::qualification::Status::Positive
    );
    std::fs::write(&qualification_path, b"malformed qualification").unwrap();

    let second_transport = empty_transport();
    let second_requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://mirror.invalid", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T01:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(second_requests.borrow().is_empty());
    assert!(second.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::AllPackages
            && matches!(diagnostic.status_detail(), CranFastPathStatus::Invalid { diagnostic, .. } if diagnostic.contains("invalid ALLPACKAGES qualification"))
    }));
    let recovered = crate::cran::provider::qualification::load_result(&qualification_path)
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.status,
        crate::cran::provider::qualification::Status::Positive
    );
    assert!(!recovered.canonical_current_digest.is_empty());
}

#[test]
fn custom_mirror_negative_cooldown_and_malformed_qualification_are_observable() {
    let (_directory, store) = store();
    let entries = matrix_history_entries();
    let feed = allpackages_fixture_body(&entries, true, None);
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(custom_mirror_transport(feed.clone(), NESTED_HISTORY, true)),
        CranMetadataConfig::new("https://mirror.invalid", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let raw_cache = RawCache::open(&store).unwrap();
    let qualification_path = raw_cache.qualification_path();
    let record = crate::cran::provider::qualification::load_result(&qualification_path)
        .unwrap()
        .unwrap();
    assert_eq!(
        record.status,
        crate::cran::provider::qualification::Status::Negative
    );
    assert_eq!(record.current_digest, record.canonical_current_digest);
    assert_ne!(record.archive_digest, record.canonical_archive_digest);
    let cooldown_at = record
        .next_probe_at
        .as_deref()
        .unwrap()
        .parse::<jiff::Timestamp>()
        .unwrap()
        - jiff::SignedDuration::from_secs(1);

    let cooldown_transport = empty_transport();
    let cooldown_requests = cooldown_transport.requests.clone();
    let mut cooldown = CranRefreshSession::new_with_clock(
        Rc::new(cooldown_transport),
        CranMetadataConfig::new("https://mirror.invalid", ALLPACKAGES_FIXTURE_URL),
        Some(cooldown_at),
        Some(RawCache::open(&store).unwrap()),
    );
    cooldown
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(cooldown_requests.borrow().is_empty());
    assert!(cooldown.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::AllPackages
            && matches!(diagnostic.status_detail(), CranFastPathStatus::Invalid { diagnostic, .. } if diagnostic.contains("qualification"))
    }));

    std::fs::write(&qualification_path, b"malformed qualification").unwrap();
    let malformed_transport = empty_transport();
    let malformed_requests = malformed_transport.requests.clone();
    let mut malformed = CranRefreshSession::new_with_clock(
        Rc::new(malformed_transport),
        CranMetadataConfig::new("https://mirror.invalid", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T02:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    malformed
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(malformed_requests.borrow().is_empty());
    assert!(malformed.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::AllPackages
            && matches!(diagnostic.status_detail(), CranFastPathStatus::Invalid { diagnostic, .. } if diagnostic.contains("invalid ALLPACKAGES qualification"))
    }));
}

#[test]
fn allpackages_retry_after_persists_cooldown_and_explicit_refresh_resets_it() {
    let (_directory, store) = store();
    let entries = matrix_history_entries();
    let feed = allpackages_fixture_body(&entries, true, None);
    let mut failed_transport = allpackages_transport(feed.clone(), true);
    failed_transport.responses.insert(
        ALLPACKAGES_FIXTURE_URL.into(),
        TransportResponse {
            status: 503,
            body: Vec::new(),
            headers: TransportResponseHeaders {
                retry_after: Some("7200".into()),
                ..TransportResponseHeaders::default()
            },
        },
    );
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(failed_transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    drop(first);

    let raw_cache = RawCache::open(&store).unwrap();
    let qualification_path = raw_cache.qualification_path();
    let failed = crate::cran::provider::qualification::load_result(&qualification_path)
        .unwrap()
        .unwrap();
    assert_eq!(
        failed.status,
        crate::cran::provider::qualification::Status::Unknown
    );
    assert_eq!(failed.failure_count, 1);
    assert_eq!(
        failed.next_probe_at.as_deref(),
        Some("2026-08-25T02:00:00Z")
    );

    let cooldown_transport = empty_transport();
    let cooldown_requests = cooldown_transport.requests.clone();
    let mut cooldown = CranRefreshSession::new_with_clock(
        Rc::new(cooldown_transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T01:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    cooldown
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(
        cooldown_requests
            .borrow()
            .iter()
            .filter(|request| request.url == ALLPACKAGES_FIXTURE_URL)
            .count(),
        0
    );

    let refresh_transport = allpackages_transport(feed, false);
    let refresh_requests = refresh_transport.requests.clone();
    let mut refresh = CranRefreshSession::new_with_clock(
        Rc::new(refresh_transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL)
            .with_refresh_metadata(),
        Some("2026-08-25T01:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    refresh
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(
        refresh_requests
            .borrow()
            .iter()
            .filter(|request| request.url == ALLPACKAGES_FIXTURE_URL)
            .count(),
        1
    );
    let recovered = crate::cran::provider::qualification::load_result(&qualification_path)
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.status,
        crate::cran::provider::qualification::Status::Positive
    );
    assert_eq!(recovered.failure_count, 0);
    assert_eq!(recovered.next_probe_at, None);
}

#[test]
fn publication_cutoff_disables_allpackages_history_and_uses_archive_index() {
    let (directory, store) = store();
    let entries = matrix_history_entries();
    let transport = allpackages_transport(allpackages_fixture_body(&entries, true, None), true);
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL)
            .without_allpackages_history(),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let result = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(
        result
            .candidates()
            .iter()
            .any(|release| release.version().to_string() == "1.6-5")
    );
    assert!(
        !requests
            .borrow()
            .iter()
            .any(|request| request.url == ALLPACKAGES_FIXTURE_URL)
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|request| request.url
                == "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds")
            .count(),
        1
    );
    drop(directory);
}

#[test]
fn allpackages_missing_historical_occurrence_uses_exclusive_package_local_history() {
    let (directory, store) = store();
    let entries = matrix_history_entries();
    let missing_index = entries
        .iter()
        .position(|entry| entry.version().to_string() == "1.6-5")
        .unwrap();
    let mut transport = allpackages_transport(
        allpackages_fixture_body(&entries, true, Some(missing_index)),
        true,
    );
    transport.responses.insert(
        "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds".into(),
        TransportResponse::new(200, EMPTY_FAST.to_vec()),
    );
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let result = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(
        result
            .candidates()
            .iter()
            .any(|release| release.version().to_string() == "1.7-6")
    );
    assert!(
        !result
            .candidates()
            .iter()
            .any(|release| release.version().to_string() == "1.7-0")
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|request| request.url
                == "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds")
            .count(),
        1
    );
    assert!(
        !session
            .evidence
            .borrow()
            .iter()
            .any(|observation| observation.source.endpoint == ALLPACKAGES_FIXTURE_URL)
    );
    drop(directory);
}

#[test]
fn allpackages_duplicate_occurrence_uses_exclusive_package_local_history() {
    let (directory, store) = store();
    let entries = matrix_history_entries();
    let mut transport = allpackages_transport(allpackages_duplicate_fixture_body(&entries), true);
    transport.responses.insert(
        "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds".into(),
        // The package-local index supplies the complete canonical history;
        // no bulk sibling is mixed with it after the duplicate occurrence.
        TransportResponse::new(200, FAST.to_vec()),
    );
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let result = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(
        result
            .candidates()
            .iter()
            .any(|release| release.version().to_string() == "1.6-5")
    );
    assert!(
        result
            .candidates()
            .iter()
            .any(|release| release.version().to_string() == "1.7-0")
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|request| request.url
                == "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds")
            .count(),
        1
    );
    assert!(
        !session
            .evidence
            .borrow()
            .iter()
            .any(|observation| observation.source.endpoint == ALLPACKAGES_FIXTURE_URL)
    );
    drop(directory);
}

#[test]
fn allpackages_archive_history_rejection_forces_package_local_history() {
    let (directory, store) = store();
    let feed = raw_zstd(
        b"Package: dse\nVersion: 1.0\nLicense: BSD-3-Clause\nSHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nSHA256Original: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nSnapshot: 2026-08-01\nDownloadURL: https://packagemanager.posit.co/cran/2026-08-01/src/contrib/dse_1.0.tar.gz\n\n",
    );
    let mut transport = allpackages_transport(feed, true);
    transport.responses.insert(
        history_url(),
        TransportResponse::new(200, LEGACY_VERSION_HISTORY.to_vec()),
    );
    transport.responses.insert(
        "https://cloud.r-project.org/src/contrib/Archive/dse/PACKAGES.rds".into(),
        TransportResponse::new(200, EMPTY_FAST.to_vec()),
    );
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let result = session
        .refresh_package(&PackageName::new("dse").unwrap())
        .unwrap();
    assert!(result.candidates().is_empty());
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|request| request.url
                == "https://cloud.r-project.org/src/contrib/Archive/dse/PACKAGES.rds")
            .count(),
        1
    );
    assert!(
        !session
            .evidence
            .borrow()
            .iter()
            .any(|observation| observation.source.endpoint == ALLPACKAGES_FIXTURE_URL)
    );
    drop(directory);
}

#[test]
fn allpackages_extra_historical_identity_forces_package_local_history() {
    let (directory, store) = store();
    let entries = matrix_history_entries();
    let mut dcf = String::from_utf8(
        crate::cran::provider::allpackages::decode_zstd(&allpackages_fixture_body(
            &entries, true, None,
        ))
        .unwrap(),
    )
    .unwrap();
    dcf.push_str(
        "Package: Matrix\nVersion: 9.9-9\nLicense: BSD-3-Clause\nSHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nSHA256Original: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nSnapshot: 2026-08-01\nDownloadURL: https://packagemanager.posit.co/cran/2026-08-01/src/contrib/Matrix_9.9-9.tar.gz\n\n",
    );
    let mut transport = allpackages_transport(raw_zstd(dcf.as_bytes()), true);
    transport.responses.insert(
        "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds".into(),
        TransportResponse::new(200, FAST.to_vec()),
    );
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cloud.r-project.org", ALLPACKAGES_FIXTURE_URL),
        Some("2026-08-25T00:00:00Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let result = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(
        result
            .candidates()
            .iter()
            .any(|release| release.version().to_string() == "1.7-0")
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|request| request.url
                == "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds")
            .count(),
        1
    );
    assert!(
        !session
            .evidence
            .borrow()
            .iter()
            .any(|observation| observation.source.endpoint == ALLPACKAGES_FIXTURE_URL)
    );
    drop(directory);
}
use super::*;
use crate::cran::provider::cache_policy::CacheControlHeader;
use crate::cran::provider::raw_cache::RawCacheRepresentation;
