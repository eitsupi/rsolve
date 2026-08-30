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
use super::{
    CranCandidateSnapshot, CranMetadataConfig, CranRefreshDiagnostic, CranRefreshProgress,
    CranRefreshProgressCallback, CranRefreshSession, CranSnapshotCachePolicy,
    CranSnapshotCacheResult,
};
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
    pre_wait: PersistentRefreshProbe,
}

/// Provider-owned state captured before a refresh caller waits for the
/// persistent transaction. The cache result is only for the warm fast path;
/// the opaque validation observation is consumed by the transaction.
pub struct CranPersistentRefreshPreflight<'a> {
    store: &'a SnapshotStore,
    probe: PersistentRefreshProbe,
    initial_cache: Option<CranSnapshotCacheResult>,
}

impl CranPersistentRefreshPreflight<'_> {
    pub fn cache_result(&self) -> Option<&CranSnapshotCacheResult> {
        self.initial_cache.as_ref()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PersistentRefreshProbe {
    revision: Option<Box<str>>,
    observation_valid: bool,
}

pub(crate) fn observe_persistent_refresh_probe(
    store: &SnapshotStore,
    policy: &CranSnapshotCachePolicy,
) -> PersistentRefreshProbe {
    let revision = match policy.expected_endpoint.as_deref() {
        Some(endpoint) => store.read_view_validation_revision_for_endpoint_unlocked(endpoint),
        None => store.read_latest_view_validation_revision_unlocked(),
    };
    match revision {
        Ok(revision) => PersistentRefreshProbe {
            revision,
            observation_valid: true,
        },
        Err(_) => PersistentRefreshProbe::default(),
    }
}

pub(crate) fn refresh_completed_after_wait(
    probe: &PersistentRefreshProbe,
    locked_revision: Option<&str>,
) -> bool {
    probe.observation_valid
        && locked_revision.is_some()
        && probe.revision.as_deref() != locked_revision
}

impl CranSnapshotRefresher {
    pub fn new(metadata: CranMetadataConfig) -> Result<Self, CranSnapshotRefresherError> {
        Self::new_with_progress(metadata, None)
    }

    pub fn new_with_progress(
        metadata: CranMetadataConfig,
        progress: Option<CranRefreshProgressCallback>,
    ) -> Result<Self, CranSnapshotRefresherError> {
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
            session: RefCell::new(CranRefreshSession::new_with_progress(
                Rc::new(UreqTransport {
                    agent: agent_config.new_agent(),
                }),
                CranMetadataConfig {
                    repository_endpoint: base_url,
                    allpackages_feed_endpoint,
                    refresh_metadata: metadata.refresh_metadata,
                    allow_allpackages_history: metadata.allow_allpackages_history,
                },
                None,
                None,
                progress,
            )),
        })
    }

    pub fn diagnostics(&self) -> Vec<CranRefreshDiagnostic> {
        let mut diagnostics = self.session.borrow().diagnostics.clone();
        diagnostics.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
        diagnostics
    }

    /// Return the cumulative acquisition counters for this refresher.
    /// Counters are cloned while the session is borrowed, so the returned
    /// value is an immutable point-in-time snapshot.
    pub fn metrics(&self) -> super::CranRefreshMetrics {
        self.session.borrow().metrics()
    }

    pub fn preflight_refresh<'a>(
        &self,
        store: &'a SnapshotStore,
        policy: &CranSnapshotCachePolicy,
    ) -> CranPersistentRefreshPreflight<'a> {
        self.preflight_refresh_with_after_observation(store, policy, || {})
    }

    fn preflight_refresh_with_after_observation<'a, F>(
        &self,
        store: &'a SnapshotStore,
        policy: &CranSnapshotCachePolicy,
        after_observation: F,
    ) -> CranPersistentRefreshPreflight<'a>
    where
        F: FnOnce(),
    {
        // Capture the lock-free observation before attempting even the warm
        // probe. This ordering is the forced-waiter coalescing boundary.
        let probe = observe_persistent_refresh_probe(store, policy);
        after_observation();
        let initial_cache = super::inspect_cran_snapshot_cache_without_wait(store, policy);
        CranPersistentRefreshPreflight {
            store,
            probe,
            initial_cache,
        }
    }

    pub fn begin_persistent_refresh<'a>(
        &'a self,
        preflight: CranPersistentRefreshPreflight<'a>,
    ) -> Result<CranPersistentRefresh<'a>, CranSnapshotPublishError> {
        self.begin_persistent_refresh_with_probe(preflight.store, preflight.probe)
    }

    fn begin_persistent_refresh_with_probe<'a>(
        &'a self,
        store: &'a SnapshotStore,
        pre_wait: PersistentRefreshProbe,
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
            pre_wait,
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
        self.session
            .borrow()
            .emit_progress(CranRefreshProgress::SnapshotPublishStarted {
                packages: roots.len(),
            });
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
        self.session
            .borrow()
            .emit_progress(CranRefreshProgress::SnapshotPublishCompleted);
        Ok(loader)
    }
}

impl CranPersistentRefresh<'_> {
    /// Reports whether a successful publication advanced the validation
    /// revision while this transaction waited for the refresh lock.
    pub fn refresh_completed_while_waiting(&self, locked_revision: Option<&str>) -> bool {
        refresh_completed_after_wait(&self.pre_wait, locked_revision)
    }

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
    reject_raw_root_escape(input)?;
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
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must not include credentials".into(),
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
    if url.port() == Some(0) {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must not use port zero".into(),
        });
    }
    if (url.scheme() == "http" && url.port() == Some(80))
        || (url.scheme() == "https" && url.port() == Some(443))
    {
        url.set_port(None)
            .map_err(|_| CranSnapshotRefresherError::InvalidBaseUrl {
                diagnostic: "CRAN base URL has an invalid default port".into(),
            })?;
    }
    // Keep trailing and repeated slashes: they are part of the configured
    // endpoint identity and affect the request URL contract.
    let path = url.path().to_owned();
    url.set_path(&path);
    Ok(url.to_string().into())
}

fn reject_raw_root_escape(input: &str) -> Result<(), CranSnapshotRefresherError> {
    let Some((_, authority_and_path)) = input.split_once("://") else {
        return Ok(());
    };
    let authority_and_path = authority_and_path.split(['?', '#']).next().unwrap_or("");
    if authority_and_path.contains('\\') {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must not contain backslashes in authority or path".into(),
        });
    }
    let Some(index) = authority_and_path.find('/') else {
        return Ok(());
    };
    let path = &authority_and_path[index..];
    let mut segments = Vec::new();
    for segment in path.split('/') {
        if is_current_segment(segment) {
            continue;
        }
        if is_parent_segment(segment) {
            if segments.len() <= 1 {
                return Err(CranSnapshotRefresherError::InvalidBaseUrl {
                    diagnostic: "CRAN base URL path escapes the URL root".into(),
                });
            }
            segments.pop();
        } else {
            segments.push(segment);
        }
    }
    Ok(())
}

fn is_current_segment(segment: &str) -> bool {
    segment == "." || segment.eq_ignore_ascii_case("%2e")
}

fn is_parent_segment(segment: &str) -> bool {
    segment == ".."
        || segment.eq_ignore_ascii_case("%2e%2e")
        || segment.eq_ignore_ascii_case(".%2e")
        || segment.eq_ignore_ascii_case("%2e.")
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

#[cfg(test)]
mod tests {
    use super::{
        CranSnapshotCachePolicy, CranSnapshotCacheResult, CranSnapshotRefresher,
        observe_persistent_refresh_probe, refresh_completed_after_wait,
    };
    use crate::snapshot::SnapshotStore;
    use rsolve_core::RegistryId;

    fn view_path(store: &SnapshotStore) -> std::path::PathBuf {
        std::fs::read_dir(store.root().join("views"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|extension| extension.to_str()) == Some("json"))
            .expect("published view head")
    }

    #[test]
    fn pre_wait_validation_revision_is_stable_and_scoped_misses_are_detectable() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        store
            .build_and_publish_with_endpoint(
                crate::snapshot::test_present_input(),
                "https://cloud.r-project.org",
            )
            .unwrap();
        let path = view_path(&store);
        let policy = CranSnapshotCachePolicy::at("2026-08-25T00:00:00Z".parse().unwrap())
            .with_expected_endpoint("https://cloud.r-project.org");
        let first = observe_persistent_refresh_probe(&store, &policy);
        let mut changed = std::fs::read_to_string(&path).unwrap();
        changed = changed.replace("\"refresh_sequence\":1", "\"refresh_sequence\":2");
        std::fs::write(&path, changed).unwrap();
        let second = observe_persistent_refresh_probe(&store, &policy);
        assert!(first.observation_valid && second.observation_valid);
        assert_ne!(first.revision, second.revision);
        assert!(refresh_completed_after_wait(
            &first,
            second.revision.as_deref()
        ));

        let identical = observe_persistent_refresh_probe(&store, &policy);
        assert_eq!(second.revision, identical.revision);
        assert!(!refresh_completed_after_wait(
            &second,
            identical.revision.as_deref()
        ));

        std::fs::write(&path, b"invalid").unwrap();
        let invalid = observe_persistent_refresh_probe(&store, &policy);
        assert!(invalid.observation_valid);
        assert!(invalid.revision.is_none());
        assert!(!refresh_completed_after_wait(&invalid, None));
        let global_invalid = observe_persistent_refresh_probe(
            &store,
            &CranSnapshotCachePolicy::at("2026-08-25T00:00:00Z".parse().unwrap()),
        );
        assert!(!global_invalid.observation_valid);

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let unreadable = observe_persistent_refresh_probe(&store, &policy);
        assert!(unreadable.observation_valid);
        assert!(unreadable.revision.is_none());
        assert!(!refresh_completed_after_wait(&unreadable, None));
    }

    #[test]
    fn endpoint_scoped_probe_ignores_another_endpoint_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let input = crate::snapshot::test_present_input();
        let policy_a = CranSnapshotCachePolicy::at("2026-08-25T00:00:00Z".parse().unwrap())
            .with_expected_endpoint("https://mirror-a.example");
        let policy_b = CranSnapshotCachePolicy::at("2026-08-25T00:00:00Z".parse().unwrap())
            .with_expected_endpoint("https://mirror-b.example");
        store
            .build_and_publish_with_endpoint(input.clone(), "https://mirror-a.example")
            .unwrap();
        let probe_a = observe_persistent_refresh_probe(&store, &policy_a);
        store
            .build_and_publish_with_endpoint(input, "https://mirror-b.example")
            .unwrap();
        let after_a = observe_persistent_refresh_probe(&store, &policy_a);
        let after_b = observe_persistent_refresh_probe(&store, &policy_b);
        assert_eq!(probe_a.revision, after_a.revision);
        assert_ne!(probe_a.revision, after_b.revision);
        assert!(!refresh_completed_after_wait(
            &probe_a,
            after_a.revision.as_deref()
        ));
    }

    #[test]
    fn preflight_carries_the_old_revision_past_a_cache_probe() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("cran").unwrap()).unwrap();
        let input = crate::snapshot::test_present_input();
        store
            .build_and_publish_with_endpoint(input, "https://cloud.r-project.org")
            .unwrap();
        let validation_path = view_path(&store);
        let refresher = CranSnapshotRefresher::new(crate::cran::CranMetadataConfig::new(
            "https://cloud.r-project.org",
            "https://cloud.r-project.org/src/contrib/ALLPACKAGES.rds",
        ))
        .unwrap();
        let policy = CranSnapshotCachePolicy::at("2026-08-25T00:00:00Z".parse().unwrap())
            .with_expected_endpoint("https://cloud.r-project.org")
            .with_allowed_auxiliary_endpoint(
                "https://cloud.r-project.org/src/contrib/ALLPACKAGES.rds",
            );

        // `preflight_refresh` captures sequence 1 before its nonblocking
        // cache probe. Simulate an owner publishing sequence 2 immediately
        // after observation and before that probe.
        let preflight = refresher.preflight_refresh_with_after_observation(&store, &policy, || {
            let mut next = std::fs::read_to_string(&validation_path).unwrap();
            next = next.replace("\"refresh_sequence\":1", "\"refresh_sequence\":2");
            std::fs::write(&validation_path, next).unwrap();
        });
        let locked_revision = store.read_latest_view_validation_revision().unwrap();
        let probed_revision = match preflight.cache_result().unwrap() {
            CranSnapshotCacheResult::Compatible { diagnostic, .. }
            | CranSnapshotCacheResult::Rejected(diagnostic) => {
                diagnostic.revision_token().map(str::to_owned)
            }
        };
        assert_eq!(probed_revision.as_deref(), locked_revision.as_deref());
        let transaction = refresher.begin_persistent_refresh(preflight).unwrap();
        assert!(transaction.refresh_completed_while_waiting(locked_revision.as_deref()));
    }
}
