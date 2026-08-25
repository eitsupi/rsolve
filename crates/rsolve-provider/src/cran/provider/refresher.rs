use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::path::Component;
use std::rc::Rc;

use flate2::read::GzDecoder;
use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory, PackageName};

use super::super::publish::{
    CranSnapshotPublishError, default_context, publish_snapshot_with_endpoint,
};
use super::transport::UreqTransport;
use super::{CranCandidateSnapshot, CranMetadataConfig, CranRefreshDiagnostic, CranRefreshSession};
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
    pub fn new(metadata: CranMetadataConfig) -> Result<Self, CranSnapshotRefresherError> {
        let base_url = canonical_base_url(&metadata.repository_endpoint)?;
        let allpackages_feed_endpoint = canonical_base_url(&metadata.allpackages_feed_endpoint)?;
        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let agent_config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(tls_config)
            .build();
        Ok(Self {
            session: RefCell::new(CranRefreshSession::new(
                Rc::new(UreqTransport {
                    agent: agent_config.new_agent(),
                }),
                CranMetadataConfig {
                    repository_endpoint: base_url,
                    allpackages_feed_endpoint,
                    refresh_metadata: metadata.refresh_metadata,
                    allow_allpackages_history: metadata.allow_allpackages_history,
                },
            )),
        })
    }

    pub fn diagnostics(&self) -> Vec<CranRefreshDiagnostic> {
        let mut diagnostics = self.session.borrow().diagnostics.clone();
        diagnostics.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
        diagnostics
    }

    pub fn canonical_endpoint(&self) -> Box<str> {
        self.session.borrow().base_url.clone()
    }

    pub fn allpackages_feed_endpoint(&self) -> Box<str> {
        self.session.borrow().allpackages_feed_endpoint.clone()
    }

    #[cfg(test)]
    pub(crate) fn refresh_metadata_enabled(&self) -> bool {
        self.session.borrow().refresh_metadata
    }

    #[cfg(test)]
    pub(crate) fn allpackages_history_enabled(&self) -> bool {
        self.session.borrow().allow_allpackages_history
    }

    /// Refreshes exactly these package names, then returns a transport-free
    /// snapshot containing all package results cached by this refresher.
    pub fn refresh_packages(
        &self,
        roots: &[PackageName],
    ) -> Result<CranCandidateSnapshot, CandidateLoadError> {
        self.session.borrow_mut().refresh_packages(roots)
    }

    /// Binds a persistent store to this refresher before any package refresh
    /// begins. Callers that first discover a dependency closure with
    /// [`refresh_packages`] and publish it later must use this seam so the
    /// metadata responses acquired during discovery are also persisted.
    pub fn prepare_persistent_refresh(
        &self,
        store: &SnapshotStore,
    ) -> Result<(), CranSnapshotPublishError> {
        let raw_cache = super::raw_cache::RawCache::open(store).map_err(|error| {
            CranSnapshotPublishError::Acquisition(CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                format!("unable to open CRAN current raw cache: {error}"),
            ))
        })?;
        self.session.borrow_mut().attach_raw_cache(raw_cache);
        Ok(())
    }

    /// Refreshes the requested CRAN packages and atomically publishes their
    /// validated source observations into the persistent snapshot store.
    /// The returned loader is transport-free and pins the committed generation.
    pub fn refresh_and_publish_snapshot(
        &self,
        store: &SnapshotStore,
        roots: &[PackageName],
    ) -> Result<ReadOnlySnapshotCandidateLoader, CranSnapshotPublishError> {
        self.prepare_persistent_refresh(store)?;
        let mut session = self.session.borrow_mut();
        let observations = session
            .refresh_snapshot_observations(roots)
            .map_err(CranSnapshotPublishError::Acquisition)?;
        drop(session);
        publish_snapshot_with_endpoint(
            store,
            default_context(store.registry_id().clone()),
            observations,
            &self.session.borrow().base_url,
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
