use super::*;
use crate::cran::provider::cache_policy::CacheControlHeader;
use crate::cran::provider::raw_cache::{
    RawCache, RawCacheLookup, RawCacheRepresentation, RawCacheWrite,
};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::io::{Read, Write};

fn store() -> (tempfile::TempDir, SnapshotStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    (directory, store)
}

fn history_response(headers: TransportResponseHeaders) -> TransportResponse {
    TransportResponse {
        status: 200,
        body: HISTORY.to_vec(),
        headers,
    }
}

fn empty_transport() -> FixtureTransport {
    FixtureTransport {
        responses: std::collections::HashMap::new(),
        requests: Rc::new(RefCell::new(Vec::new())),
    }
}

fn mixed_semantic_archive_index() -> Vec<u8> {
    let mut decoded = Vec::new();
    GzDecoder::new(FAST).read_to_end(&mut decoded).unwrap();
    let original = b"R (>= 3.5.0)";
    let replacement = b"libxml (>= )";
    let position = decoded
        .windows(original.len())
        .position(|window| window == original)
        .expect("fixture dependency");
    decoded[position..position + original.len()].copy_from_slice(replacement);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&decoded).unwrap();
    encoder.finish().unwrap()
}

fn all_semantic_invalid_archive_index() -> Vec<u8> {
    let mut decoded = Vec::new();
    GzDecoder::new(FAST).read_to_end(&mut decoded).unwrap();
    let replacement = b"libxml (>= )";
    let mut replaced = 0;
    for original in [b"R (>= 3.5.0)".as_slice(), b"R (>= 4.4.0)".as_slice()] {
        let mut offset = 0;
        while let Some(relative) = decoded[offset..]
            .windows(original.len())
            .position(|window| window == original)
        {
            let position = offset + relative;
            decoded[position..position + original.len()].copy_from_slice(replacement);
            offset = position + replacement.len();
            replaced += 1;
        }
    }
    assert_eq!(replaced, 2);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&decoded).unwrap();
    encoder.finish().unwrap()
}

fn release_signature(releases: &[PackageRelease]) -> Vec<String> {
    releases
        .iter()
        .map(|release| release.version().to_string())
        .collect()
}

fn partial_fast_path_detail(session: &CranRefreshSession<FixtureTransport>) -> (usize, String) {
    let diagnostic = session
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.endpoint() == fast_url())
        .expect("partial fast-path diagnostic");
    match diagnostic.status_detail() {
        CranFastPathStatus::AvailableWithRejections { count, diagnostic } => {
            (*count, diagnostic.to_string())
        }
        other => panic!("expected partial diagnostic, got {other:?}"),
    }
}

const ROOT_DUPLICATE_ARCHIVE: &[u8] = include_bytes!(
    "../../../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-root-duplicate-PACKAGES.rds"
);

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
        "https://cran.invalid",
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    assert!(matches!(
        first.ensure_history(),
        Ok(HistorySource::Available(_))
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
        "https://cran.invalid",
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    assert!(matches!(
        second.ensure_history(),
        Ok(HistorySource::Available(_))
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let releases = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .expect("empty archive fast path");
    assert_eq!(releases.len(), 1);
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let releases = session
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(
        releases
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
        "https://cran.invalid",
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let first_releases = first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let expected_releases = release_signature(&first_releases);
    let expected_detail = partial_fast_path_detail(&first);

    let second_transport = empty_transport();
    let requests = second_transport.requests.clone();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        "https://cran.invalid",
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let second_releases = second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert!(requests.borrow().is_empty());
    assert_eq!(release_signature(&second_releases), expected_releases);
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
        "https://cran.invalid",
        Some(t0),
        Some(RawCache::open(&store).unwrap()),
    );
    let first_releases = first
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    let expected_releases = release_signature(&first_releases);
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
        "https://cran.invalid",
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(RawCache::open(&store).unwrap()),
    );
    let second_releases = second
        .refresh_package(&PackageName::new("Matrix").unwrap())
        .unwrap();
    assert_eq!(release_signature(&second_releases), expected_releases);
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
        "https://cran.invalid",
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
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
        "https://cran.invalid",
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
