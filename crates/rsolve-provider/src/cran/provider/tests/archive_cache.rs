use super::*;
use crate::cran::history::enumerate_archive_rds_for_provider;
use crate::cran::provider::cache_policy::CacheControlHeader;
use crate::cran::provider::raw_cache::{
    RawCache, RawCacheLookup, RawCacheRepresentation, RawCacheWrite,
};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::io::{Read, Write};

const ALLPACKAGES_FIXTURE_URL: &str = "https://feed.invalid/ALLPACKAGES.zst";

fn allpackages_fixture_body(
    entries: &[crate::cran::history::ArchiveEntry],
    include_current: bool,
    omit_entry: Option<usize>,
) -> Vec<u8> {
    let mut dcf = String::new();
    let current_entry = entries.iter().find(|entry| {
        entry.package().as_str() == "Matrix" && entry.version().to_string() == "1.7-6"
    });
    if include_current {
        let (version, filename) = current_entry
            .map(|entry| {
                (
                    entry.version().to_string(),
                    entry
                        .source_archive_relative_path()
                        .rsplit('/')
                        .next()
                        .unwrap()
                        .to_owned(),
                )
            })
            .unwrap_or_else(|| ("1.7-6".into(), "Matrix_1.7-6.tar.gz".into()));
        dcf.push_str(&format!(
            "Package: Matrix\nVersion: {version}\nLicense: BSD-3-Clause\nSHA256: {}\nSHA256Original: {}\nSnapshot: 2026-08-01\nDownloadURL: https://packagemanager.posit.co/cran/2026-08-01/src/contrib/{filename}\n\n",
            "b".repeat(64),
            "a".repeat(64),
        ));
    }
    for (index, entry) in entries.iter().enumerate() {
        if omit_entry == Some(index) {
            continue;
        }
        if include_current
            && entry.package().as_str() == "Matrix"
            && entry.version().to_string() == "1.7-6"
        {
            continue;
        }
        let filename = entry
            .source_archive_relative_path()
            .rsplit('/')
            .next()
            .unwrap();
        dcf.push_str(&format!(
            "Package: {}\nVersion: {}\nLicense: BSD-3-Clause\nSHA256: {}\nSHA256Original: {}\nSnapshot: 2026-08-01\nDownloadURL: https://packagemanager.posit.co/cran/2026-08-01/src/contrib/{filename}\n\n",
            entry.package(),
            entry.version(),
            "b".repeat(64),
            "a".repeat(64),
        ));
    }
    raw_zstd(dcf.as_bytes())
}

fn allpackages_transport(feed_body: Vec<u8>, include_package_archive: bool) -> FixtureTransport {
    let mut responses = std::collections::HashMap::new();
    responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES.rds".into(),
        TransportResponse::new(200, NATIVE_UTF8_CURRENT.to_vec()),
    );
    responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES.gz".into(),
        TransportResponse::new(404, Vec::new()),
    );
    responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES".into(),
        TransportResponse::new(404, Vec::new()),
    );
    responses.insert(
        "https://cloud.r-project.org/src/contrib/Meta/archive.rds".into(),
        TransportResponse::new(200, HISTORY.to_vec()),
    );
    responses.insert(
        ALLPACKAGES_FIXTURE_URL.into(),
        TransportResponse::new(200, feed_body),
    );
    if include_package_archive {
        responses.insert(
            "https://cloud.r-project.org/src/contrib/Archive/Matrix/PACKAGES.rds".into(),
            TransportResponse::new(200, FAST.to_vec()),
        );
    }
    FixtureTransport {
        responses,
        requests: Rc::new(RefCell::new(Vec::new())),
    }
}

fn custom_mirror_transport(
    feed_body: Vec<u8>,
    target_history: &[u8],
    include_package_archive: bool,
) -> FixtureTransport {
    let mut transport = allpackages_transport(feed_body, include_package_archive);
    transport.responses.insert(
        "https://mirror.invalid/src/contrib/PACKAGES.rds".into(),
        TransportResponse::new(200, NATIVE_UTF8_CURRENT.to_vec()),
    );
    transport.responses.insert(
        "https://mirror.invalid/src/contrib/Meta/archive.rds".into(),
        TransportResponse::new(200, target_history.to_vec()),
    );
    if include_package_archive {
        transport.responses.insert(
            "https://mirror.invalid/src/contrib/Archive/Matrix/PACKAGES.rds".into(),
            TransportResponse::new(200, FAST.to_vec()),
        );
    }
    transport
}

fn allpackages_duplicate_fixture_body(entries: &[crate::cran::history::ArchiveEntry]) -> Vec<u8> {
    let mut dcf = String::from_utf8(
        crate::cran::provider::allpackages::decode_zstd(&allpackages_fixture_body(
            entries, true, None,
        ))
        .unwrap(),
    )
    .unwrap();
    dcf.push_str(
        "Package: Matrix\nVersion: 1.7-0\nLicense: BSD-3-Clause\nSHA256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\nSHA256Original: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\nSnapshot: 2024-10-20\nDownloadURL: https://p3m.dev/cran/2024-10-20/src/contrib/Matrix_1.7-0.tar.gz\n\n",
    );
    raw_zstd(dcf.as_bytes())
}

fn matrix_history_entries() -> Vec<crate::cran::history::ArchiveEntry> {
    enumerate_archive_rds_for_provider(HISTORY)
        .unwrap()
        .entries
        .into_iter()
        .filter(|entry| entry.package().as_str() == "Matrix")
        .collect()
}

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
    let second_transport = allpackages_transport(feed, false);
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
    history_response_with_body(HISTORY, headers)
}

fn history_response_with_body(body: &[u8], headers: TransportResponseHeaders) -> TransportResponse {
    TransportResponse {
        status: 200,
        body: body.to_vec(),
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
    let mut offset = 0;
    let mut replaced = 0;
    while let Some(relative) = decoded[offset..]
        .windows(original.len())
        .position(|window| window == original)
    {
        let position = offset + relative;
        decoded[position..position + original.len()].copy_from_slice(replacement);
        offset = position + replacement.len();
        replaced += 1;
    }
    assert!(replaced > 0);
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
