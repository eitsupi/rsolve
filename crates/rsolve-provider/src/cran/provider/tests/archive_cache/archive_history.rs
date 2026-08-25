#[test]
fn archive_history_fresh_cache_hit_avoids_network() {
    let (_directory, store) = store();
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
    assert!(second_requests.borrow().is_empty());
    assert!(
        !second_requests
            .borrow()
            .iter()
            .any(|request| request.url == legacy_history_url())
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
    let HistorySource::Available { rejections, .. } = first_source else {
        panic!("expected available history")
    };
    assert_eq!(rejections.len(), 1);
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
    let HistorySource::Available { rejections, .. } = second_source else {
        panic!("expected available history")
    };
    assert_eq!(rejections.len(), 1);
    assert_eq!(
        rejections[0].raw_path(),
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
use crate::cran::provider::raw_cache::{RawCache, RawCacheLookup, RawCacheRepresentation};
