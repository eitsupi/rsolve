use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::path::Component;
use std::rc::Rc;

use flate2::read::GzDecoder;
use rsolve_core::{CandidateLoadError, PackageName};

use super::super::publish::{CranSnapshotPublishError, default_context, publish_snapshot};
use super::transport::UreqTransport;
use super::{CranCandidateSnapshot, CranRefreshDiagnostic, CranRefreshSession};
use crate::snapshot::{ReadOnlySnapshotCandidateLoader, SnapshotStore};

/// A transport-neutral failure constructing the CRAN snapshot refresher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranSnapshotRefresherError {
    InvalidBaseUrl { diagnostic: Box<str> },
}

impl fmt::Display for CranSnapshotRefresherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl { diagnostic } => formatter.write_str(diagnostic),
        }
    }
}

impl Error for CranSnapshotRefresherError {}

/// A synchronous CRAN refresh owner backed by one reusable ureq agent.
///
/// Refreshing this owner blocks while performing network I/O. Async callers
/// should invoke refresh methods through a blocking worker boundary; the
/// returned snapshot itself performs no I/O.
pub struct CranSnapshotRefresher {
    session: RefCell<CranRefreshSession<UreqTransport>>,
}

impl CranSnapshotRefresher {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, CranSnapshotRefresherError> {
        let base_url = canonical_base_url(base_url.as_ref())?;
        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(tls_config)
            .build();
        Ok(Self {
            session: RefCell::new(CranRefreshSession::new(
                Rc::new(UreqTransport {
                    agent: config.new_agent(),
                }),
                base_url,
            )),
        })
    }

    pub fn diagnostics(&self) -> Vec<CranRefreshDiagnostic> {
        let mut diagnostics = self.session.borrow().diagnostics.clone();
        diagnostics.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
        diagnostics
    }

    /// Refreshes exactly these package names, then returns a transport-free
    /// snapshot containing all package results cached by this refresher.
    pub fn refresh_packages(
        &self,
        roots: &[PackageName],
    ) -> Result<CranCandidateSnapshot, CandidateLoadError> {
        self.session.borrow_mut().refresh_packages(roots)
    }

    /// Refreshes the requested CRAN packages and atomically publishes their
    /// validated source observations into the persistent snapshot store.
    /// The returned loader is transport-free and pins the committed generation.
    pub fn refresh_and_publish_snapshot(
        &self,
        store: &SnapshotStore,
        roots: &[PackageName],
    ) -> Result<ReadOnlySnapshotCandidateLoader, CranSnapshotPublishError> {
        let observations = self
            .session
            .borrow_mut()
            .refresh_snapshot_observations(roots)
            .map_err(CranSnapshotPublishError::Acquisition)?;
        publish_snapshot(
            store,
            default_context(store.registry_id().clone()),
            observations,
        )
    }
}

pub(super) fn canonical_base_url(input: &str) -> Result<Box<str>, CranSnapshotRefresherError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must not be empty".into(),
        });
    }
    let mut url =
        url::Url::parse(input).map_err(|error| CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: format!("invalid CRAN base URL: {error}").into(),
        })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must use HTTP or HTTPS".into(),
        });
    }
    if url.host_str().is_none() || url.cannot_be_a_base() {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must be hierarchical and include a host".into(),
        });
    }
    if url.query().is_some() {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must not include a query".into(),
        });
    }
    if url.fragment().is_some() {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must not include a fragment".into(),
        });
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.to_string().trim_end_matches('/').into())
}

pub(super) fn decode_gzip(input: &[u8]) -> Result<Vec<u8>, String> {
    let decoder = GzDecoder::new(input);
    let mut output = Vec::new();
    decoder
        .take(super::MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|error| format!("invalid gzip current index: {error}"))?;
    if output.len() as u64 > super::MAX_RESPONSE_BYTES {
        return Err(format!(
            "gzip current index exceeds {}-byte limit",
            super::MAX_RESPONSE_BYTES
        ));
    }
    Ok(output)
}

pub(super) fn extract_description(input: &[u8]) -> Result<Vec<u8>, String> {
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
