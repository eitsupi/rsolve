use super::*;
use crate::cran::provider::cache_policy::CacheControlHeader;
use crate::cran::provider::raw_cache::{RawCache, RawCacheLookup, RawCacheRepresentation};

#[test]
fn package_archive_stale_cache_revalidates_once_with_304() {
    let (_directory, store) = store();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let etag = "\"package-archive-etag\"";
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

    let second_transport = FixtureTransport {
        responses: [(
            fast_url(),
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
    second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();

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
        .expect("archive fast-path diagnostic");
    assert_eq!(diagnostic.status(), Some(304));
    assert_eq!(diagnostic.status_detail(), &CranFastPathStatus::Available);
    let key = RawCache::open(&store)
        .unwrap()
        .key(&fast_url(), RawCacheRepresentation::PackageArchiveIndexRds)
        .unwrap();
    let RawCacheLookup::Hit(entry) = RawCache::open(&store).unwrap().lookup(&key) else {
        panic!("expected revalidated package archive cache entry")
    };
    assert_eq!(entry.observed_at, t0);
    assert_eq!(entry.validated_at, "2026-08-23T00:00:01Z".parse().unwrap());
    assert_eq!(entry.etag.as_deref(), Some(etag));
    let evidence = second.evidence.borrow();
    let archive_source = evidence
        .iter()
        .find(|observation| observation.source.kind == "cran-archive-index")
        .expect("archive source evidence");
    assert_eq!(archive_source.source.observed_at, "2026-08-23T00:00:00Z");
    assert_eq!(archive_source.source.etag.as_deref(), Some(etag));
}
