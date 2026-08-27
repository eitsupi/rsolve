#[test]
fn archive_history_fresh_cache_hit_avoids_network() {
    let (_directory, store) = store();
    CranRefreshSession::<FixtureTransport>::reset_archive_projection_build_count();
    crate::cran::provider::raw_cache::projection::reset_visit_package_records_count();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = FixtureTransport {
        responses: [(
            history_url(),
            history_response(TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("max-age=3600".into()),
                ..TransportResponseHeaders::default()
            }),
        )]
        .into_iter()
        .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let first_requests = first_transport.requests.clone();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    assert!(matches!(
        first.ensure_history(),
        Ok(HistorySource::Available { .. })
    ));
    assert_eq!(
        CranRefreshSession::<FixtureTransport>::archive_projection_build_count(),
        1
    );
    assert_eq!(
        crate::cran::provider::raw_cache::projection::visit_package_records_count(),
        0
    );
    assert_eq!(first_requests.borrow().len(), 1);
    assert!(
        !first_requests
            .borrow()
            .iter()
            .any(|request| request.url == legacy_history_url())
    );

    let second_transport = empty_transport();
    let second_requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    assert!(matches!(
        second.ensure_history(),
        Ok(HistorySource::Available { .. })
    ));
    assert_eq!(
        CranRefreshSession::<FixtureTransport>::archive_projection_build_count(),
        1
    );
    assert_eq!(
        crate::cran::provider::raw_cache::projection::visit_package_records_count(),
        0
    );
    assert!(second_requests.borrow().is_empty());
    assert!(
        !second_requests
            .borrow()
            .iter()
            .any(|request| request.url == legacy_history_url())
    );
    let metrics = second.metrics();
    assert_eq!(metrics.http_attempts, 0);
    assert_eq!(metrics.archive_history.requests, 0);
    assert_eq!(metrics.raw_cache_hits, 1);
    assert_eq!(metrics.raw_cache_misses, 0);
    assert_eq!(metrics.raw_cache_corrupt, 0);
    assert_eq!(metrics.projection_reuses, 1);
    assert_eq!(metrics.projection_builds, 0);
}

#[test]
fn archive_projection_storage_failure_does_not_retry_transport() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = FixtureTransport {
        responses: [(history_url(), history_response(Default::default()))]
            .into_iter()
            .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    first.ensure_history().unwrap();
    drop(first);

    let cache = RawCache::open(&store).unwrap();
    let key = cache
        .key(&history_url(), RawCacheRepresentation::ArchiveHistoryRds)
        .unwrap();
    let digest = Sha256::digest(HISTORY);
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let projection =
        cache.projection_path_in_namespace(ProjectionNamespace::ArchiveHistory, &key, &digest);
    std::fs::remove_file(&projection).unwrap();
    std::fs::create_dir(&projection).unwrap();

    let second_transport = empty_transport();
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let error = second
        .ensure_history()
        .err()
        .expect("projection storage failure");
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );
    assert!(requests.borrow().is_empty());
}

#[test]
fn corrupt_archive_projection_rebuilds_from_cached_raw_without_transport() {
    let (_directory, store) = store();
    CranRefreshSession::<FixtureTransport>::reset_archive_projection_build_count();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = FixtureTransport {
        responses: [(history_url(), history_response(Default::default()))]
            .into_iter()
            .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    first.ensure_history().unwrap();
    drop(first);
    let cache = RawCache::open(&store).unwrap();
    let key = cache
        .key(&history_url(), RawCacheRepresentation::ArchiveHistoryRds)
        .unwrap();
    let digest = Sha256::digest(HISTORY);
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let projection =
        cache.projection_path_in_namespace(ProjectionNamespace::ArchiveHistory, &key, &digest);
    std::fs::write(&projection, b"corrupt projection").unwrap();

    let second_transport = empty_transport();
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    assert!(matches!(
        second.ensure_history(),
        Ok(HistorySource::Available { .. })
    ));
    assert!(requests.borrow().is_empty());
    assert_eq!(
        CranRefreshSession::<FixtureTransport>::archive_projection_build_count(),
        2
    );
}

#[test]
fn semantically_corrupt_archive_summary_rebuilds_from_cached_raw_without_transport() {
    let (_directory, store) = store();
    CranRefreshSession::<FixtureTransport>::reset_archive_projection_build_count();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = FixtureTransport {
        responses: [(history_url(), history_response(Default::default()))]
            .into_iter()
            .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    first.ensure_history().unwrap();
    drop(first);

    let cache = RawCache::open(&store).unwrap();
    let key = cache
        .key(&history_url(), RawCacheRepresentation::ArchiveHistoryRds)
        .unwrap();
    let digest = Sha256::digest(HISTORY);
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let projection =
        cache.projection_path_in_namespace(ProjectionNamespace::ArchiveHistory, &key, &digest);
    crate::cran::provider::raw_cache::projection::overwrite_projection_summary(
        &projection,
        b"invalid summary".to_vec(),
    );

    let second_transport = empty_transport();
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    assert!(matches!(
        second.ensure_history(),
        Ok(HistorySource::Available { .. })
    ));
    assert!(requests.borrow().is_empty());
    assert_eq!(
        CranRefreshSession::<FixtureTransport>::archive_projection_build_count(),
        2
    );
}

#[test]
fn semantically_corrupt_archive_package_rebuilds_on_target_lookup_without_transport() {
    let (_directory, store) = store();
    CranRefreshSession::<FixtureTransport>::reset_archive_projection_build_count();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = FixtureTransport {
        responses: [(history_url(), history_response(Default::default()))]
            .into_iter()
            .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    first.ensure_history().unwrap();
    drop(first);

    let cache = RawCache::open(&store).unwrap();
    let key = cache
        .key(&history_url(), RawCacheRepresentation::ArchiveHistoryRds)
        .unwrap();
    let digest = Sha256::digest(HISTORY);
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let projection =
        cache.projection_path_in_namespace(ProjectionNamespace::ArchiveHistory, &key, &digest);
    crate::cran::provider::raw_cache::projection::overwrite_projection_package(
        &projection,
        "Matrix",
        b"invalid package payload".to_vec(),
    );

    let second_transport = empty_transport();
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let source = second.ensure_history().unwrap();
    let HistorySource::Available { source } = source else {
        panic!("expected available history");
    };
    assert!(source.package(&PackageName::new("Matrix").unwrap()).is_ok());
    assert!(requests.borrow().is_empty());
    assert_eq!(
        CranRefreshSession::<FixtureTransport>::archive_projection_build_count(),
        2
    );
}

#[test]
fn archive_history_stale_cache_revalidates_once_and_reuses_body() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let etag = "\"archive-etag\"";
    let first_transport = FixtureTransport {
        responses: [(
            history_url(),
            history_response(TransportResponseHeaders {
                etag: Some(etag.into()),
                cache_control: CacheControlHeader::Valid("no-cache".into()),
                ..TransportResponseHeaders::default()
            }),
        )]
        .into_iter()
        .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    first.ensure_history().unwrap();

    let second_transport = FixtureTransport {
        responses: [(
            history_url(),
            TransportResponse {
                status: 304,
                body: Vec::new(),
                headers: TransportResponseHeaders {
                    cache_control: CacheControlHeader::Valid("max-age=120".into()),
                    ..TransportResponseHeaders::default()
                },
            },
        )]
        .into_iter()
        .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    second.ensure_history().unwrap();
    assert_eq!(requests.borrow().len(), 1);
    assert_eq!(
        requests.borrow()[0].validators.if_none_match.as_deref(),
        Some(etag)
    );
    let key = RawCache::open(&store)
        .unwrap()
        .key(&history_url(), RawCacheRepresentation::ArchiveHistoryRds)
        .unwrap();
    let RawCacheLookup::Hit(entry) = RawCache::open(&store).unwrap().lookup(&key) else {
        panic!("expected revalidated archive history cache entry")
    };
    assert_eq!(entry.observed_at, t0);
    assert_eq!(entry.etag.as_deref(), Some(etag));
    assert_eq!(entry.validated_at, "2026-08-23T00:00:01Z".parse().unwrap());
}

#[test]
fn archive_history_rejections_survive_fresh_and_304_cache_decode() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = FixtureTransport {
        responses: [(
            history_url(),
            history_response_with_body(
                FOREIGN_NESTED_HISTORY,
                TransportResponseHeaders {
                    etag: Some("\"foreign-etag\"".into()),
                    cache_control: CacheControlHeader::Valid("max-age=3600".into()),
                    ..TransportResponseHeaders::default()
                },
            ),
        )]
        .into_iter()
        .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let first_source = first.ensure_history().expect("fresh history");
    let HistorySource::Available { source } = first_source else {
        panic!("expected available history")
    };
    let package = PackageName::new("calibFit").unwrap();
    let first_payload = source.package(&package).expect("package payload");
    assert_eq!(first_payload.rejections.len(), 1);
    assert_eq!(first.metrics().quarantined_releases, 1);
    assert!(first.diagnostics.iter().any(|diagnostic| matches!(
        diagnostic.status_detail(),
        CranFastPathStatus::Invalid { diagnostic, .. }
            if diagnostic.contains("calibFit/Ancestry/calib_0.1.02.tar.gz")
    )));

    let second_transport = FixtureTransport {
        responses: [(
            history_url(),
            TransportResponse {
                status: 304,
                body: Vec::new(),
                headers: TransportResponseHeaders {
                    cache_control: CacheControlHeader::Valid("max-age=120".into()),
                    ..TransportResponseHeaders::default()
                },
            },
        )]
        .into_iter()
        .collect(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let second_source = second.ensure_history().expect("304 history");
    let HistorySource::Available { source } = second_source else {
        panic!("expected available history")
    };
    let second_payload = source.package(&package).expect("package payload");
    assert_eq!(second_payload.rejections.len(), 1);
    assert_eq!(second.metrics().quarantined_releases, 1);
    assert_eq!(
        second_payload.rejections[0].raw_path(),
        "calibFit/Ancestry/calib_0.1.02.tar.gz"
    );
    assert!(second.diagnostics.iter().any(|diagnostic| matches!(
        diagnostic.status_detail(),
        CranFastPathStatus::Invalid { diagnostic, .. }
            if diagnostic.contains("calibFit/Ancestry/calib_0.1.02.tar.gz")
    )));
}
use super::*;
use crate::cran::provider::cache_policy::CacheControlHeader;
use crate::cran::provider::raw_cache::ProjectionNamespace;
use crate::cran::provider::raw_cache::{RawCache, RawCacheLookup, RawCacheRepresentation};
use sha2::{Digest, Sha256};
