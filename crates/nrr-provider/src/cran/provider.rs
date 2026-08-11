//! CRAN archive refresh and lazy DESCRIPTION fallback.
// The provider remains private until concrete runtime transport wiring is
// added; its unit tests exercise the refresh seam without exposing transport
// types through the public CRAN adapter API.
#![allow(dead_code)]

use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::path::Component;

use super::catalog::CranCatalog;
use super::history::{ArchiveEntry, CranHistoryError, enumerate_archive_rds};
use flate2::read::GzDecoder;
use nrr_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, PackageName, PackageRelease,
    SolverKey,
};

/// A provider-local response used by both real and fixture transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// A provider-local transport failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportError {
    pub diagnostic: Box<str>,
}

impl TransportError {
    fn new(diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            diagnostic: diagnostic.into(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.diagnostic)
    }
}

impl Error for TransportError {}

/// The small synchronous seam used by the CRAN provider.
pub(crate) trait Transport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError>;
}

/// Observable result of probing the per-package archive fast path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FastPathStatus {
    Available,
    Absent { status: u16 },
    Invalid { status: u16, diagnostic: Box<str> },
}

/// A refresh diagnostic.  A 404 remains an endpoint observation rather than a
/// portable "history none" result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CranRefreshDiagnostic {
    pub(crate) endpoint: Box<str>,
    pub(crate) status: Option<u16>,
    pub status_detail: FastPathStatus,
}

/// A failure before a provider snapshot can be constructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CranProviderError {
    Transport {
        endpoint: Box<str>,
        source: TransportError,
    },
    History(CranHistoryError),
}

impl fmt::Display for CranProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { endpoint, source } => {
                write!(f, "transport failure for {endpoint}: {source}")
            }
            Self::History(error) => error.fmt(f),
        }
    }
}

impl Error for CranProviderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport { source, .. } => Some(source),
            Self::History(source) => Some(source),
        }
    }
}

enum CandidateSource {
    Fast(CranCatalog),
    Fallback(Vec<ArchiveEntry>),
}

/// A refreshed CRAN candidate source.
pub(crate) struct CranProvider<T> {
    package: PackageName,
    transport: RefCell<T>,
    base_url: Box<str>,
    source: CandidateSource,
    diagnostics: Vec<CranRefreshDiagnostic>,
    loaded: RefCell<Option<Result<Vec<PackageRelease>, CandidateLoadError>>>,
}

impl<T: Transport> CranProvider<T> {
    /// Refresh one package's archive source.  The fast-path endpoint is
    /// requested exactly once per provider instance.
    pub(crate) fn refresh(
        transport: T,
        base_url: impl AsRef<str>,
        package: PackageName,
    ) -> Result<Self, CranProviderError> {
        let base_url = base_url.as_ref().trim_end_matches('/').to_owned();
        let endpoint = format!(
            "{base_url}/src/contrib/Archive/{}/PACKAGES.rds",
            package.as_str()
        );
        let response = transport
            .get(&endpoint)
            .map_err(|source| CranProviderError::Transport {
                endpoint: endpoint.clone().into_boxed_str(),
                source,
            })?;
        let mut diagnostics = Vec::new();
        let source = if response.status == 200 {
            match CranCatalog::from_archive_index_rds(&response.body) {
                Ok(catalog) => {
                    diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.clone().into_boxed_str(),
                        status: Some(response.status),
                        status_detail: FastPathStatus::Available,
                    });
                    CandidateSource::Fast(catalog)
                }
                Err(error) => {
                    diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.clone().into_boxed_str(),
                        status: Some(response.status),
                        status_detail: FastPathStatus::Invalid {
                            status: response.status,
                            diagnostic: error.to_string().into_boxed_str(),
                        },
                    });
                    Self::fallback_source(&transport, &base_url)?
                }
            }
        } else if response.status == 404 {
            diagnostics.push(CranRefreshDiagnostic {
                endpoint: endpoint.clone().into_boxed_str(),
                status: Some(response.status),
                status_detail: FastPathStatus::Absent {
                    status: response.status,
                },
            });
            Self::fallback_source(&transport, &base_url)?
        } else {
            diagnostics.push(CranRefreshDiagnostic {
                endpoint: endpoint.clone().into_boxed_str(),
                status: Some(response.status),
                status_detail: FastPathStatus::Invalid {
                    status: response.status,
                    diagnostic: "unexpected fast-path status".into(),
                },
            });
            Self::fallback_source(&transport, &base_url)?
        };

        Ok(Self {
            package,
            transport: RefCell::new(transport),
            base_url: base_url.into_boxed_str(),
            source,
            diagnostics,
            loaded: RefCell::new(None),
        })
    }

    pub(crate) fn diagnostics(&self) -> &[CranRefreshDiagnostic] {
        &self.diagnostics
    }

    fn fallback_source(
        transport: &T,
        base_url: &str,
    ) -> Result<CandidateSource, CranProviderError> {
        let endpoint = format!("{base_url}/Meta/archive.rds");
        let response = transport
            .get(&endpoint)
            .map_err(|source| CranProviderError::Transport {
                endpoint: endpoint.clone().into_boxed_str(),
                source,
            })?;
        if response.status != 200 {
            return Err(CranProviderError::Transport {
                endpoint: endpoint.into_boxed_str(),
                source: TransportError::new(format!(
                    "history enumeration returned HTTP {}",
                    response.status
                )),
            });
        }
        let entries = enumerate_archive_rds(&response.body).map_err(CranProviderError::History)?;
        Ok(CandidateSource::Fallback(entries))
    }

    fn load_fallback(
        &self,
        entries: &[ArchiveEntry],
    ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let mut releases = Vec::new();
        for entry in entries.iter().filter(|entry| entry.package == self.package) {
            let url = if entry.path.starts_with('/') {
                format!("{}{}", self.base_url, entry.path)
            } else {
                format!("{}/{}", self.base_url, entry.path)
            };
            let transport = self.transport.borrow();
            let response = transport.get(&url).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!("failed to fetch {}: {error}", entry.path),
                )
            })?;
            if response.status != 200 {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!("failed to fetch {}: HTTP {}", entry.path, response.status),
                ));
            }
            if response.body.len() as u64 != entry.size {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!("size mismatch for {}", entry.path),
                ));
            }
            let description = extract_description(&response.body).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("invalid DESCRIPTION in {}: {error}", entry.path),
                )
            })?;
            let catalog = CranCatalog::from_packages(&description).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("invalid DESCRIPTION in {}: {error}", entry.path),
                )
            })?;
            releases.extend(catalog.candidates(&entry.package).iter().cloned());
        }
        Ok(releases)
    }
}

impl<T: Transport> CandidateLoader for CranProvider<T> {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN provider has no candidates for {package:?}"),
            ));
        };
        if name != &self.package {
            return Ok(Vec::new());
        }
        if let Some(result) = self.loaded.borrow().as_ref() {
            return result.clone();
        }
        let result = match &self.source {
            CandidateSource::Fast(catalog) => Ok(catalog.candidates(&self.package).to_vec()),
            CandidateSource::Fallback(entries) => self.load_fallback(entries),
        };
        *self.loaded.borrow_mut() = Some(result.clone());
        result
    }
}

fn extract_description(input: &[u8]) -> Result<Vec<u8>, String> {
    let decoder = GzDecoder::new(input);
    let mut archive = tar::Archive::new(decoder);
    let mut description = None;
    for item in archive.entries().map_err(|error| error.to_string())? {
        let entry = item.map_err(|error| error.to_string())?;
        let path = entry
            .path()
            .map_err(|error| error.to_string())?
            .into_owned();
        let components = path.components().collect::<Vec<_>>();
        if components.iter().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err("archive contains an unsafe path".to_owned());
        }
        if !entry.header().entry_type().is_file() {
            continue;
        }
        if components.len() == 2
            && components[1].as_os_str() == "DESCRIPTION"
            && matches!(components[0], Component::Normal(_))
        {
            if description.is_some() {
                return Err("archive contains multiple root DESCRIPTION files".to_owned());
            }
            let size = entry.header().size().map_err(|error| error.to_string())?;
            if size > 4 * 1024 * 1024 {
                return Err("DESCRIPTION exceeds size limit".to_owned());
            }
            let mut bytes = Vec::new();
            entry
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err("DESCRIPTION exceeds size limit".to_owned());
            }
            description = Some(bytes);
        }
    }
    description.ok_or_else(|| "archive root has no DESCRIPTION file".to_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    use nrr_core::{CandidateLoadErrorCategory, PackageName, SolverKey};
    use std::collections::HashMap;
    use std::rc::Rc;

    const FAST: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-PACKAGES.rds"
    );
    const WRONG_ROOT: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-wrong-root.rds"
    );
    const MISSING_VERSION: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-missing-version.rds"
    );
    const HISTORY: &[u8] =
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-meta-archive.rds");
    const OLD_TAR: &[u8] =
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-Matrix_1.6-5.tar.gz");
    const NEW_TAR: &[u8] =
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-Matrix_1.7-0.tar.gz");

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

    fn provider(transport: FixtureTransport) -> CranProvider<FixtureTransport> {
        CranProvider::refresh(
            transport,
            "https://cran.invalid",
            PackageName::new("Matrix").unwrap(),
        )
        .unwrap()
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
            provider.diagnostics()[0].status_detail,
            FastPathStatus::Absent { status: 404 }
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
    fn invalid_fast_path_shapes_match_fast_catalog() {
        let fast = provider(FixtureTransport::fallback(FAST.to_vec(), 200));
        let expected = logical_signature(&fast);
        for invalid in [b"truncated RDS".as_slice(), WRONG_ROOT, MISSING_VERSION] {
            let fallback = provider(FixtureTransport::fallback(invalid.to_vec(), 200));
            assert_eq!(logical_signature(&fallback), expected);
            assert!(matches!(
                fallback.diagnostics()[0].status_detail,
                FastPathStatus::Invalid { status: 200, .. }
            ));
        }
    }

    #[test]
    fn history_only_enumerates_file_info_facts() {
        let entries = enumerate_archive_rds(HISTORY).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].package.as_str(), "Matrix");
        assert_eq!(
            &*entries[0].path,
            "src/contrib/Archive/Matrix/Matrix_1.6-5.tar.gz"
        );
        assert_eq!(entries[0].size, OLD_TAR.len() as u64);
        assert_eq!(entries[0].mtime, 1_790_000_000);
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
}
