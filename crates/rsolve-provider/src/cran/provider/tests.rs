use super::*;
use crate::cran::enumerate_archive_rds;
use rsolve_core::{CandidateLoadErrorCategory, PackageName, SolverKey};
use std::collections::HashMap;
use std::io::Write;
use std::rc::Rc;

const FAST: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-PACKAGES.rds");
const EMPTY_FAST: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-empty-matrix-archive-PACKAGES.rds"
);
const SEMANTIC_INVALID_FAST: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-archive-PACKAGES.rds");
const WRONG_ROOT: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-wrong-root.rds"
);
const MISSING_VERSION: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-missing-version.rds"
);
const NATIVE_UTF8_CURRENT: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-native-utf8-archive-PACKAGES.rds"
);
const INVALID_UTF8_CURRENT: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-invalid-utf8-archive-PACKAGES.rds"
);
const HISTORY: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-archive.rds");
const NESTED_HISTORY: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-nested-archive.rds");
const FOREIGN_NESTED_HISTORY: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-foreign-nested-archive.rds"
);
const ROOT_NESTED_MIXED_HISTORY: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-root-nested-mixed.rds");
const ROOT_UNSAFE_PERCENT_HISTORY: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-root-unsafe-percent.rds"
);
const NLME_ARCHIVE: &[u8] =
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-nlme-archive-PACKAGES.rds");
const LEGACY_VERSION_HISTORY: &[u8] = include_bytes!(
    "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-legacy-version.rds"
);
const INVALID_HISTORY_PATHS: &[&[u8]] = &[
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-traversal.rds"),
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-query.rds"),
    include_bytes!("../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-fragment.rds"),
    include_bytes!(
        "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-percent-traversal.rds"
    ),
    include_bytes!(
        "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-percent-slash.rds"
    ),
    include_bytes!(
        "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-percent-backslash.rds"
    ),
    include_bytes!(
        "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-percent-dot.rds"
    ),
    include_bytes!(
        "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-percent-query.rds"
    ),
    include_bytes!(
        "../../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-percent-fragment.rds"
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
    requests: Rc<RefCell<Vec<FixtureRequest>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixtureRequest {
    url: String,
    validators: TransportValidators,
}

impl PartialEq<String> for FixtureRequest {
    fn eq(&self, other: &String) -> bool {
        self.url == *other
    }
}

impl PartialEq<FixtureRequest> for String {
    fn eq(&self, other: &FixtureRequest) -> bool {
        *self == other.url
    }
}

impl FixtureTransport {
    fn fallback(fast: Vec<u8>, status: u16) -> Self {
        let mut responses = HashMap::new();
        responses.insert(fast_url(), TransportResponse::new(status, fast));
        responses.insert(
            history_url(),
            TransportResponse {
                status: 200,
                body: HISTORY.to_vec(),
                ..TransportResponse::default()
            },
        );
        responses.insert(
            old_url(),
            TransportResponse {
                status: 200,
                body: OLD_TAR.to_vec(),
                ..TransportResponse::default()
            },
        );
        responses.insert(
            new_url(),
            TransportResponse {
                status: 200,
                body: NEW_TAR.to_vec(),
                ..TransportResponse::default()
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
        self.get_with_validators(url, &TransportValidators::default())
    }

    fn get_with_validators(
        &self,
        url: &str,
        validators: &TransportValidators,
    ) -> Result<TransportResponse, TransportError> {
        self.requests.borrow_mut().push(FixtureRequest {
            url: url.to_owned(),
            validators: validators.clone(),
        });
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| TransportError::new(format!("fixture has no response for {url}")))
    }
}

#[test]
fn fixture_transport_observes_conditional_validators() {
    let transport = FixtureTransport::fallback(FAST.to_vec(), 200);
    let validators = TransportValidators::from_values(
        Some("\"fixture-etag\""),
        Some("Wed, 21 Oct 2015 07:28:00 GMT"),
    );
    let response = transport
        .get_with_validators(&fast_url(), &validators)
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(transport.requests.borrow().len(), 1);
    assert_eq!(transport.requests.borrow()[0].url, fast_url());
    assert_eq!(transport.requests.borrow()[0].validators, validators);
}

fn fast_url() -> String {
    "https://cran.invalid/src/contrib/Archive/Matrix/PACKAGES.rds".to_owned()
}

fn history_url() -> String {
    "https://cran.invalid/src/contrib/Meta/archive.rds".to_owned()
}

fn legacy_history_url() -> String {
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
            ..TransportResponse::default()
        },
    );
    for package in ["methods", "rsolvefixture.plain"] {
        responses.insert(
            fast_url_for(package),
            TransportResponse {
                status: 404,
                body: Vec::new(),
                ..TransportResponse::default()
            },
        );
    }
    responses.insert(
        history_url(),
        TransportResponse {
            status: 200,
            body: HISTORY.to_vec(),
            ..TransportResponse::default()
        },
    );
    responses.insert(
        old_url(),
        TransportResponse {
            status: 200,
            body: OLD_TAR.to_vec(),
            ..TransportResponse::default()
        },
    );
    responses.insert(
        new_url(),
        TransportResponse {
            status: 200,
            body: NEW_TAR.to_vec(),
            ..TransportResponse::default()
        },
    );
    FixtureTransport {
        responses,
        requests: Rc::new(RefCell::new(Vec::new())),
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

mod archive_cache;
mod current;
mod diagnostics;
mod fallback;
mod runtime;
