use super::*;
use rsolve_core::{CandidateLoadErrorCategory, PackageName, SolverKey};
use std::collections::HashMap;
use std::io::Write;
use std::rc::Rc;

const FAST: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-PACKAGES.rds");
const SEMANTIC_INVALID_FAST: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-archive-PACKAGES.rds");
const WRONG_ROOT: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-wrong-root.rds"
);
const MISSING_VERSION: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-missing-version.rds"
);
const HISTORY: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-archive.rds");
const INVALID_HISTORY_PATHS: &[&[u8]] = &[
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-traversal.rds"),
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-query.rds"),
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-fragment.rds"),
    include_bytes!(
        "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-percent-traversal.rds"
    ),
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-backslash.rds"),
    include_bytes!(
        "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-package-mismatch.rds"
    ),
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-version.rds"),
];
const OLD_TAR: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-Matrix_1.6-5.tar.gz");
const NEW_TAR: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-Matrix_1.7-0.tar.gz");

#[derive(Clone)]
struct FixtureTransport {
    responses: HashMap<String, TransportResponse>,
    requests: Rc<RefCell<Vec<String>>>,
}

impl FixtureTransport {
    fn fallback(fast: Vec<u8>, status: u16) -> Self {
        let mut responses = HashMap::new();
        responses.insert(fast_url(), TransportResponse { status, body: fast });
        responses.insert(
            history_url(),
            TransportResponse {
                status: 200,
                body: HISTORY.to_vec(),
            },
        );
        responses.insert(
            old_url(),
            TransportResponse {
                status: 200,
                body: OLD_TAR.to_vec(),
            },
        );
        responses.insert(
            new_url(),
            TransportResponse {
                status: 200,
                body: NEW_TAR.to_vec(),
            },
        );
        Self {
            responses,
            requests: Rc::new(RefCell::new(Vec::new())),
        }
    }
}

impl Transport for FixtureTransport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        self.requests.borrow_mut().push(url.to_owned());
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| TransportError::new(format!("fixture has no response for {url}")))
    }
}

fn fast_url() -> String {
    "https://cran.invalid/src/contrib/Archive/Matrix/PACKAGES.rds".to_owned()
}

fn history_url() -> String {
    "https://cran.invalid/Meta/archive.rds".to_owned()
}

fn old_url() -> String {
    "https://cran.invalid/src/contrib/Archive/Matrix/Matrix_1.6-5.tar.gz".to_owned()
}

fn new_url() -> String {
    "https://cran.invalid/src/contrib/Archive/Matrix/Matrix_1.7-0.tar.gz".to_owned()
}

fn invalid_description_tar() -> Vec<u8> {
    let description = b"Package: Matrix\nVersion: not-a-version\n";
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("Matrix/DESCRIPTION").unwrap();
    header.set_size(description.len() as u64);
    header.set_cksum();
    archive.append(&header, description.as_slice()).unwrap();
    let archive = archive.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&archive).unwrap();
    encoder.finish().unwrap()
}

fn current_rds_url() -> String {
    "https://cran.invalid/src/contrib/PACKAGES.rds".to_owned()
}

fn current_gzip_url() -> String {
    "https://cran.invalid/src/contrib/PACKAGES.gz".to_owned()
}

fn current_plain_url() -> String {
    "https://cran.invalid/src/contrib/PACKAGES".to_owned()
}

fn fast_url_for(package: &str) -> String {
    format!("https://cran.invalid/src/contrib/Archive/{package}/PACKAGES.rds")
}

fn provider(transport: FixtureTransport) -> CranProvider<FixtureTransport> {
    CranProvider::refresh(
        transport,
        "https://cran.invalid",
        PackageName::new("Matrix").unwrap(),
    )
    .unwrap()
}

fn runtime_loader(transport: FixtureTransport) -> CranRuntimeLoader<FixtureTransport> {
    CranRuntimeLoader::new(transport, "https://cran.invalid")
}

fn session_transport(
    current_rds: TransportResponse,
    current_gzip: TransportResponse,
    current_plain: TransportResponse,
) -> FixtureTransport {
    let mut responses = HashMap::new();
    responses.insert(current_rds_url(), current_rds);
    responses.insert(current_gzip_url(), current_gzip);
    responses.insert(current_plain_url(), current_plain);
    responses.insert(
        fast_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
    );
    for package in ["methods", "rsolvefixture.plain"] {
        responses.insert(
            fast_url_for(package),
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
        );
    }
    responses.insert(
        history_url(),
        TransportResponse {
            status: 200,
            body: HISTORY.to_vec(),
        },
    );
    responses.insert(
        old_url(),
        TransportResponse {
            status: 200,
            body: OLD_TAR.to_vec(),
        },
    );
    responses.insert(
        new_url(),
        TransportResponse {
            status: 200,
            body: NEW_TAR.to_vec(),
        },
    );
    FixtureTransport {
        responses,
        requests: Rc::new(RefCell::new(Vec::new())),
    }
}

#[test]
fn concrete_loader_validates_and_canonicalizes_base_without_requests() {
    assert_eq!(
        canonical_base_url(" https://cran.invalid/mirror/// ").unwrap(),
        "https://cran.invalid/mirror".into()
    );
    assert!(CranSnapshotRefresher::new("https://cran.invalid/mirror///").is_ok());
    for input in [
        "",
        "ftp://cran.invalid",
        "https://",
        "https://cran.invalid?mirror=1",
        "https://cran.invalid/#mirror",
    ] {
        assert!(matches!(
            CranSnapshotRefresher::new(input),
            Err(CranSnapshotRefresherError::InvalidBaseUrl { .. })
        ));
    }
}

fn logical_signature(provider: &CranProvider<FixtureTransport>) -> Vec<String> {
    provider
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap(),
            ))
            .unwrap()
            .into_iter()
            .map(|release| {
                let dependencies = release
                    .dependencies()
                    .iter()
                    .map(|dependency| {
                        (
                            dependency.kind,
                            dependency.name.as_str(),
                            &dependency.source,
                            &dependency.constraint.clauses,
                        )
                    })
                    .collect::<Vec<_>>();
                let common_metadata = ["License", "NeedsCompilation"]
                    .into_iter()
                    .filter_map(|field| {
                        release
                            .metadata()
                            .fields()
                            .get(field)
                            .map(|value| (field, value))
                    })
                    .collect::<Vec<_>>();
                // MD5sum belongs to the index/artifact acquisition layer, not
                // DESCRIPTION or solver-facing release metadata.  It is
                // intentionally excluded so real CRAN fallback remains exact.
                format!(
                    "identity={:?};version={};dependencies={dependencies:?};metadata={common_metadata:?};distributions={:?}",
                    release.identity(),
                    release.version(),
                    release.distributions(),
                )
            })
            .collect()
}

#[test]
fn absent_fast_path_falls_back_lazily_without_reprobe() {
    let transport = FixtureTransport::fallback(Vec::new(), 404);
    let requests = Rc::clone(&transport.requests);
    let provider = provider(transport);
    assert!(matches!(
        provider.diagnostics()[0].status_detail(),
        CranFastPathStatus::Absent { status: 404 }
    ));
    assert_eq!(requests.borrow().len(), 2);
    assert_eq!(requests.borrow()[0], fast_url());
    assert_eq!(requests.borrow()[1], history_url());
    assert_eq!(logical_signature(&provider).len(), 2);
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &fast_url())
            .count(),
        1
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &history_url())
            .count(),
        1
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &old_url())
            .count(),
        1
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &new_url())
            .count(),
        1
    );
    assert_eq!(logical_signature(&provider).len(), 2);
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &old_url())
            .count(),
        1
    );
}

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
fn invalid_fast_path_shapes_match_fast_catalog() {
    let fast = provider(FixtureTransport::fallback(FAST.to_vec(), 200));
    let expected = logical_signature(&fast);
    for invalid in [
        b"truncated RDS".as_slice(),
        WRONG_ROOT,
        MISSING_VERSION,
        SEMANTIC_INVALID_FAST,
    ] {
        let fallback = provider(FixtureTransport::fallback(invalid.to_vec(), 200));
        assert_eq!(logical_signature(&fallback), expected);
        assert!(matches!(
            fallback.diagnostics()[0].status_detail(),
            CranFastPathStatus::Invalid { status: 200, .. }
        ));
    }
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
fn snapshot_distinguishes_unrefreshed_from_refreshed_empty_packages() {
    let empty = PackageName::new("rsolvefixture.empty").unwrap();
    let unknown = PackageName::new("rsolvefixture.unknown").unwrap();
    let snapshot = CranCandidateSnapshot::from_candidates([(empty.clone(), Vec::new())]);
    assert!(snapshot.contains_package(&empty));
    assert!(!snapshot.needs_refresh(&SolverKey::InstalledName(empty.clone())));
    assert!(
        snapshot
            .releases(&SolverKey::InstalledName(empty))
            .unwrap()
            .is_empty()
    );
    assert!(snapshot.needs_refresh(&SolverKey::InstalledName(unknown.clone())));
    assert_eq!(
        snapshot
            .releases(&SolverKey::InstalledName(unknown))
            .unwrap_err()
            .category(),
        CandidateLoadErrorCategory::NotFound
    );
}

#[test]
fn invalid_gzip_current_index_falls_back_to_plain_once() {
    let current = b"Package: rsolvefixture.plain\nVersion: 3.0.0\n";
    let transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
        TransportResponse {
            status: 200,
            body: b"not gzip".to_vec(),
        },
        TransportResponse {
            status: 200,
            body: current.to_vec(),
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let snapshot = session
        .refresh_packages(&[PackageName::new("rsolvefixture.plain").unwrap()])
        .unwrap();
    assert_eq!(
        snapshot
            .releases(&SolverKey::InstalledName(
                PackageName::new("rsolvefixture.plain").unwrap()
            ))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(requests.borrow()[0], current_rds_url());
    assert_eq!(requests.borrow()[1], current_gzip_url());
    assert_eq!(requests.borrow()[2], current_plain_url());
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Gzip)
            && matches!(
                diagnostic.status_detail(),
                CranFastPathStatus::Invalid { .. }
            )
    }));
}

#[test]
fn current_and_archive_same_identity_merge_or_fail_on_metadata_conflict() {
    let consistent = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: RSOLVE Fictional Terms Matrix\nNeedsCompilation: yes\n";
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
            body: consistent.to_vec(),
        },
    );
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    assert_eq!(
        snapshot
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap()
            ))
            .unwrap()
            .len(),
        2
    );

    let conflicting = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: conflicting\nNeedsCompilation: yes\n";
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
            body: conflicting.to_vec(),
        },
    );
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let error = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
    assert!(
        error
            .diagnostic()
            .contains("conflicting CRAN release metadata")
    );
}

#[test]
fn unsupported_rds_current_index_falls_back_to_gzip() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(b"Package: rsolvefixture.plain\nVersion: 3.0.0\n")
        .unwrap();
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: vec![0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
        },
        TransportResponse {
            status: 200,
            body: encoder.finish().unwrap(),
        },
        TransportResponse {
            status: 500,
            body: Vec::new(),
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    session
        .refresh_packages(&[PackageName::new("rsolvefixture.plain").unwrap()])
        .unwrap();
    assert_eq!(requests.borrow()[0], current_rds_url());
    assert_eq!(requests.borrow()[1], current_gzip_url());
    assert_eq!(requests.borrow()[2], fast_url_for("rsolvefixture.plain"));
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Gzip)
            && matches!(diagnostic.status_detail(), CranFastPathStatus::Available)
    }));
}

#[test]
fn semantic_invalid_current_index_falls_back_to_gzip() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(b"Package: rsolvefixture.plain\nVersion: 3.0.0\n")
        .unwrap();
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: SEMANTIC_INVALID_FAST.to_vec(),
        },
        TransportResponse {
            status: 200,
            body: encoder.finish().unwrap(),
        },
        TransportResponse {
            status: 500,
            body: Vec::new(),
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    session
        .refresh_packages(&[PackageName::new("rsolvefixture.plain").unwrap()])
        .unwrap();
    assert_eq!(requests.borrow()[0], current_rds_url());
    assert_eq!(requests.borrow()[1], current_gzip_url());
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Rds)
            && matches!(
                diagnostic.status_detail(),
                CranFastPathStatus::Invalid { .. }
            )
    }));
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
                },
            ),
            (
                current_gzip_url(),
                TransportResponse {
                    status: 410,
                    body: Vec::new(),
                },
            ),
            (
                current_plain_url(),
                TransportResponse {
                    status: 503,
                    body: Vec::new(),
                },
            ),
        ]),
    ] {
        let transport = FixtureTransport {
            responses,
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
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
        },
    );
    responses.insert(
        current_gzip_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
    );
    responses.insert(
        current_plain_url(),
        TransportResponse {
            status: 503,
            body: Vec::new(),
        },
    );
    let transport = FixtureTransport {
        responses,
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let error = session.ensure_current().unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
}

#[test]
fn gone_fast_path_is_absent_and_shared_history_is_fetched_once() {
    let current = b"Package: Matrix\nVersion: 1.8-0\n";
    let mut transport = session_transport(
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
    transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 410,
            body: Vec::new(),
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    assert_eq!(
        session
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.endpoint() == fast_url())
            .unwrap()
            .status_detail(),
        &CranFastPathStatus::Absent { status: 410 }
    );
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &history_url())
            .count(),
        1
    );
}

#[test]
fn absent_fast_path_and_absent_history_use_current_candidates_only() {
    let current = b"Package: Matrix\nVersion: 1.8-0\n";
    for (fast_status, history_status) in [(404, 404), (404, 410), (410, 404), (410, 410)] {
        let mut transport = session_transport(
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
        transport.responses.insert(
            fast_url(),
            TransportResponse {
                status: fast_status,
                body: Vec::new(),
            },
        );
        transport.responses.insert(
            history_url(),
            TransportResponse {
                status: history_status,
                body: Vec::new(),
            },
        );
        let requests = Rc::clone(&transport.requests);
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        let snapshot = session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .expect("current-only refresh");
        assert_eq!(
            snapshot
                .releases(&SolverKey::InstalledName(
                    PackageName::new("Matrix").unwrap()
                ))
                .unwrap()
                .len(),
            1
        );
        assert!(!requests.borrow().iter().any(|url| url == &old_url()));
        assert!(session.diagnostics.iter().any(|diagnostic| {
            diagnostic.source() == CranRefreshSource::ArchiveHistory
                && diagnostic.status_detail()
                    == &CranFastPathStatus::Absent {
                        status: history_status,
                    }
        }));
        let fast_index = session
            .diagnostics
            .iter()
            .position(|diagnostic| diagnostic.source() == CranRefreshSource::ArchiveFastPath)
            .unwrap();
        let history_index = session
            .diagnostics
            .iter()
            .position(|diagnostic| diagnostic.source() == CranRefreshSource::ArchiveHistory)
            .unwrap();
        assert!(fast_index < history_index);
    }
}

#[test]
fn current_absence_with_absent_archive_sources_is_empty() {
    let mut transport = session_transport(
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
            body: b"Package: other\nVersion: 1.0.0\n".to_vec(),
        },
    );
    transport.responses.insert(
        history_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
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

#[test]
fn archive_candidates_are_retained_when_current_index_lacks_package() {
    let mut transport = session_transport(
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
            body: b"Package: other\nVersion: 1.0.0\n".to_vec(),
        },
    );
    transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 200,
            body: FAST.to_vec(),
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .expect("archive-only candidates");
    assert_eq!(
        snapshot
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap()
            ))
            .unwrap()
            .len(),
        2
    );
    assert!(requests.borrow().iter().any(|url| url == &fast_url()));
    assert!(!requests.borrow().iter().any(|url| url == &history_url()));
}

#[test]
fn fast_path_failure_is_not_hidden_by_absent_history() {
    for fast_response in [
        TransportResponse {
            status: 500,
            body: Vec::new(),
        },
        TransportResponse {
            status: 200,
            body: WRONG_ROOT.to_vec(),
        },
    ] {
        let mut transport = session_transport(
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
                body: b"Package: Matrix\nVersion: 1.8-0\n".to_vec(),
            },
        );
        transport
            .responses
            .insert(fast_url(), fast_response.clone());
        transport.responses.insert(
            history_url(),
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
        );
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        let error = session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .unwrap_err();
        assert_eq!(
            error.category(),
            if fast_response.status == 200 {
                CandidateLoadErrorCategory::MetadataInvalid
            } else {
                CandidateLoadErrorCategory::TransportFailure
            }
        );
        assert!(session.diagnostics.iter().any(|diagnostic| {
            diagnostic.source() == CranRefreshSource::ArchiveHistory
                && matches!(
                    diagnostic.status_detail(),
                    CranFastPathStatus::Absent { status: 404 }
                )
        }));
    }
}

#[test]
fn history_transport_and_metadata_failures_remain_hard_failures() {
    let cases = [
        (
            500,
            Vec::new(),
            CandidateLoadErrorCategory::TransportFailure,
        ),
        (
            200,
            b"invalid history".to_vec(),
            CandidateLoadErrorCategory::MetadataInvalid,
        ),
    ];
    for (history_status, history_body, expected_category) in cases {
        let mut transport = session_transport(
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
                body: b"Package: Matrix\nVersion: 1.8-0\n".to_vec(),
            },
        );
        transport.responses.insert(
            history_url(),
            TransportResponse {
                status: history_status,
                body: history_body,
            },
        );
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        let error = session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .unwrap_err();
        assert_eq!(error.category(), expected_category);
        assert!(session.diagnostics.iter().any(|diagnostic| {
            diagnostic.source() == CranRefreshSource::ArchiveHistory
                && diagnostic.status() == Some(history_status)
        }));
    }
}

#[test]
fn history_transport_error_is_hard_failure_after_absent_fast_path() {
    let mut transport = session_transport(
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
            body: b"Package: Matrix\nVersion: 1.8-0\n".to_vec(),
        },
    );
    transport.responses.remove(&history_url());
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    let error = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::TransportFailure
    );
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::ArchiveHistory
            && diagnostic.status().is_none()
            && matches!(
                diagnostic.status_detail(),
                CranFastPathStatus::Invalid { status: 0, .. }
            )
    }));
}

#[test]
fn fast_path_transport_error_is_diagnostic_and_falls_back() {
    let current = b"Package: Matrix\nVersion: 1.8-0\n";
    let mut transport = session_transport(
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
    transport.responses.remove(&fast_url());
    let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
    session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    let diagnostic = session
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.endpoint() == fast_url())
        .unwrap();
    assert_eq!(diagnostic.status(), None);
    assert!(matches!(
        diagnostic.status_detail(),
        CranFastPathStatus::Invalid { status: 0, .. }
    ));
}

#[test]
fn history_only_enumerates_file_info_facts() {
    let entries = enumerate_archive_rds(HISTORY).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].package().as_str(), "Matrix");
    assert_eq!(
        entries[0].source_archive_relative_path(),
        "Matrix/Matrix_1.6-5.tar.gz"
    );
    assert_eq!(entries[0].version().as_str(), "1.6-5");
    assert_eq!(entries[0].size(), OLD_TAR.len() as u64);
    assert_eq!(entries[0].mtime(), 1_790_000_000);
}

#[test]
fn history_rejects_non_canonical_archive_paths() {
    for fixture in INVALID_HISTORY_PATHS {
        assert!(matches!(
            enumerate_archive_rds(fixture),
            Err(CranHistoryError::InvalidArchivePath { .. })
        ));
    }
}

#[test]
fn size_mismatch_is_a_hard_acquisition_error() {
    let mut size_transport = FixtureTransport::fallback(Vec::new(), 404);
    size_transport
        .responses
        .get_mut(&old_url())
        .unwrap()
        .body
        .pop();
    let size_provider = provider(size_transport);
    let error = size_provider
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

#[test]
fn semantically_invalid_description_is_metadata_invalid() {
    let mut transport = FixtureTransport::fallback(Vec::new(), 404);
    let mut invalid = invalid_description_tar();
    invalid.resize(OLD_TAR.len(), 0);
    transport.responses.insert(
        old_url(),
        TransportResponse {
            status: 200,
            body: invalid.clone(),
        },
    );
    invalid.resize(NEW_TAR.len(), 0);
    transport.responses.insert(
        new_url(),
        TransportResponse {
            status: 200,
            body: invalid,
        },
    );
    let provider = provider(transport);
    let error = provider
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
    assert!(error.diagnostic().contains("invalid DESCRIPTION"));
    assert!(
        error
            .diagnostic()
            .contains("R version component 0 is not numeric")
    );
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
