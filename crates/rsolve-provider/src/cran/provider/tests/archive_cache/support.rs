use super::*;
use crate::cran::history::enumerate_archive_rds_for_provider;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::io::{Read, Write};

const ALLPACKAGES_FIXTURE_URL: &str = "https://feed.invalid/ALLPACKAGES.zst";

pub(in crate::cran::provider::tests) fn allpackages_fixture_body(
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

pub(in crate::cran::provider::tests) fn allpackages_transport(
    feed_body: Vec<u8>,
    include_package_archive: bool,
) -> FixtureTransport {
    let mut responses = std::collections::HashMap::new();
    responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES.rds".into(),
        TransportResponse::new(200, NATIVE_UTF8_CURRENT.to_vec()),
    );
    responses.insert(
        "https://cloud.r-project.org/src/contrib/PACKAGES.gz".into(),
        TransportResponse::new(200, current_gzip_body()),
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

pub(in crate::cran::provider::tests) fn custom_mirror_transport(
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
        "https://mirror.invalid/src/contrib/PACKAGES.gz".into(),
        TransportResponse::new(200, current_gzip_body()),
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

pub(in crate::cran::provider::tests) fn allpackages_duplicate_fixture_body(
    entries: &[crate::cran::history::ArchiveEntry],
) -> Vec<u8> {
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

pub(in crate::cran::provider::tests) fn matrix_history_entries()
-> Vec<crate::cran::history::ArchiveEntry> {
    enumerate_archive_rds_for_provider(HISTORY)
        .unwrap()
        .entries
        .into_iter()
        .filter(|entry| entry.package().as_str() == "Matrix")
        .collect()
}

pub(in crate::cran::provider::tests) fn store() -> (tempfile::TempDir, SnapshotStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    (directory, store)
}

pub(in crate::cran::provider::tests) fn history_response(
    headers: TransportResponseHeaders,
) -> TransportResponse {
    history_response_with_body(HISTORY, headers)
}

pub(in crate::cran::provider::tests) fn history_response_with_body(
    body: &[u8],
    headers: TransportResponseHeaders,
) -> TransportResponse {
    TransportResponse {
        status: 200,
        body: body.to_vec(),
        headers,
    }
}

pub(in crate::cran::provider::tests) fn empty_transport() -> FixtureTransport {
    FixtureTransport {
        responses: std::collections::HashMap::new(),
        requests: Rc::new(RefCell::new(Vec::new())),
    }
}

pub(in crate::cran::provider::tests) fn mixed_semantic_archive_index() -> Vec<u8> {
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

pub(in crate::cran::provider::tests) fn all_semantic_invalid_archive_index() -> Vec<u8> {
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

pub(in crate::cran::provider::tests) fn release_signature<R>(releases: R) -> Vec<String>
where
    R: AsRef<[PackageRelease]>,
{
    releases
        .as_ref()
        .iter()
        .map(|release| release.version().to_string())
        .collect()
}

pub(in crate::cran::provider::tests) fn partial_fast_path_detail(
    session: &CranRefreshSession<FixtureTransport>,
) -> (usize, String) {
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

pub(in crate::cran::provider::tests) const ROOT_DUPLICATE_ARCHIVE: &[u8] = include_bytes!(
    "../../../../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-root-duplicate-PACKAGES.rds"
);
