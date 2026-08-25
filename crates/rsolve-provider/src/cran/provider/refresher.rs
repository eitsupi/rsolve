use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::path::Component;
use std::rc::Rc;

use flate2::read::GzDecoder;
use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory, PackageName};

use super::super::publish::{
    CranSnapshotPublishError, default_context, publish_snapshot_with_endpoint_and_refresh_guard,
};
use super::transport::UreqTransport;
use super::{CranCandidateSnapshot, CranMetadataConfig, CranRefreshDiagnostic, CranRefreshSession};
use crate::snapshot::{ReadOnlySnapshotCandidateLoader, SnapshotRefreshGuard, SnapshotStore};

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

/// Provider-owned transaction spanning cache recheck, CRAN metadata
/// acquisition, composition and publication. The generic snapshot lock is
/// deliberately kept behind this boundary.
pub struct CranPersistentRefresh<'a> {
    refresher: &'a CranSnapshotRefresher,
    store: &'a SnapshotStore,
    guard: SnapshotRefreshGuard<'a>,
    previous_projection: Option<std::path::PathBuf>,
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

    pub fn begin_persistent_refresh<'a>(
        &'a self,
        store: &'a SnapshotStore,
    ) -> Result<CranPersistentRefresh<'a>, CranSnapshotPublishError> {
        let guard = store.begin_refresh().map_err(|error| {
            CranSnapshotPublishError::Acquisition(CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                format!("unable to acquire CRAN snapshot refresh lock: {error}"),
            ))
        })?;
        // Bind the raw cache and capture the last-known-good projection while
        // the transaction is still at its initial, locked snapshot. Closure
        // discovery may replace the qualification record, so doing this
        // later would lose the safe previous projection.
        self.attach_persistent_cache(store)?;
        let previous_projection = self.session.borrow().previous_allpackages_projection_path();
        Ok(CranPersistentRefresh {
            refresher: self,
            store,
            guard,
            previous_projection,
        })
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

    fn attach_persistent_cache(
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
        let guard = store.begin_refresh().map_err(|error| {
            CranSnapshotPublishError::Acquisition(CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                format!("unable to acquire CRAN snapshot refresh lock: {error}"),
            ))
        })?;
        self.attach_persistent_cache(store)?;
        let previous_projection = self.session.borrow().previous_allpackages_projection_path();
        self.refresh_and_publish_snapshot_with_refresh_guard(
            &guard,
            store,
            roots,
            previous_projection.as_deref(),
        )
    }

    pub(crate) fn refresh_and_publish_snapshot_with_refresh_guard(
        &self,
        guard: &SnapshotRefreshGuard<'_>,
        store: &SnapshotStore,
        roots: &[PackageName],
        previous_projection: Option<&std::path::Path>,
    ) -> Result<ReadOnlySnapshotCandidateLoader, CranSnapshotPublishError> {
        let mut session = self.session.borrow_mut();
        let observations = session
            .refresh_snapshot_observations(roots)
            .map_err(CranSnapshotPublishError::Acquisition)?;
        drop(session);
        let loader = publish_snapshot_with_endpoint_and_refresh_guard(
            guard,
            default_context(store.registry_id().clone()),
            observations,
            &self.session.borrow().base_url,
        )?;
        if let Ok(raw_cache) = super::raw_cache::RawCache::open(store)
            && let Some(active_projection) =
                self.session.borrow().active_allpackages_projection_path()
        {
            let _ = raw_cache.retain_projections(&active_projection, previous_projection);
        }
        Ok(loader)
    }
}

impl CranPersistentRefresh<'_> {
    pub fn inspect_cache(
        &self,
        policy: &super::super::CranSnapshotCachePolicy,
    ) -> super::super::CranSnapshotCacheResult {
        super::super::provider::inspect_cran_snapshot_cache_with_refresh_guard(&self.guard, policy)
    }

    pub fn refresh_packages(
        &self,
        roots: &[PackageName],
    ) -> Result<CranCandidateSnapshot, CandidateLoadError> {
        self.refresher.session.borrow_mut().refresh_packages(roots)
    }

    pub fn refresh_and_publish_snapshot(
        &self,
        roots: &[PackageName],
    ) -> Result<ReadOnlySnapshotCandidateLoader, CranSnapshotPublishError> {
        self.refresher
            .refresh_and_publish_snapshot_with_refresh_guard(
                &self.guard,
                self.store,
                roots,
                self.previous_projection.as_deref(),
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
