//! CRAN archive refresh and lazy DESCRIPTION fallback.

use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(test)]
use std::error::Error;
#[cfg(test)]
use std::fmt;
use std::rc::Rc;
use std::time::Duration;

use super::archive_index::provider_rds_read_options;
use super::catalog::CranCatalog;
use super::evidence::CranEvidenceObservation;
#[cfg(test)]
use super::history::CranHistoryError;
use super::history::{ArchiveEntry, enumerate_archive_rds_for_provider};
use crate::SnapshotStore;
use crate::snapshot::FreshnessStateV1;
use crate::snapshot::ReadOnlySnapshotCandidateLoader;
use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, PackageName, PackageRelease,
    ReleaseAggregation, SolverKey,
};

mod negative;
mod refresher;
mod snapshot;
mod transport;

use negative::FastPathFailure;
#[cfg(test)]
use refresher::canonical_base_url;
pub use refresher::{CranSnapshotRefresher, CranSnapshotRefresherError};
use refresher::{decode_gzip, extract_description};
#[cfg(test)]
pub(crate) use snapshot::refresh_and_publish_with_transport;
use snapshot::{
    current_records, index_record_to_evidence, source_input, tarball_record_to_evidence,
};
pub(crate) use transport::Transport;
#[cfg(test)]
pub(crate) use transport::{TransportError, TransportResponse};

// This is a CRAN transport defense limit, not a generic artifact-size contract.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

/// A failure before a provider snapshot can be constructed.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CranProviderError {
    Transport {
        endpoint: Box<str>,
        source: TransportError,
    },
    History(CranHistoryError),
}

#[cfg(test)]
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

#[cfg(test)]
impl Error for CranProviderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport { source, .. } => Some(source),
            Self::History(source) => Some(source),
        }
    }
}

/// The observed result of probing one package's CRAN archive fast path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranFastPathStatus {
    Available,
    /// The archive index capability is not exposed by this repository.
    Unsupported {
        status: u16,
    },
    Absent {
        status: u16,
    },
    Invalid {
        status: u16,
        diagnostic: Box<str>,
    },
}

/// The representation attempted for the shared current CRAN index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CranCurrentIndexRepresentation {
    Rds,
    Gzip,
    PlainDcf,
}

/// The transport-neutral source of a refresh diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CranRefreshSource {
    ArchiveFastPath,
    ArchiveHistory,
    CurrentIndex(CranCurrentIndexRepresentation),
}

/// The default period for which a compatible CRAN generation can be reused
/// online when the server has not supplied a stronger freshness policy.
pub const CRAN_COMPATIBILITY_PROFILE: u32 = 1;
pub const CRAN_PARSER_SCHEMA: u32 = 1;
pub const CRAN_NORMALIZATION_POLICY: u32 = 1;
pub const DEFAULT_COMPATIBLE_GENERATION_TTL: Duration = Duration::from_secs(60 * 60);

/// Clock and compatibility policy used by the CRAN snapshot reuse boundary.
/// Supplying an explicit timestamp keeps this decision deterministic in tests
/// and leaves room for HTTP cache policy to take precedence later.
#[derive(Clone, Debug)]
pub struct CranSnapshotCachePolicy {
    pub now: jiff::Timestamp,
    pub fallback_ttl: Duration,
    pub compatibility_profile: u32,
    pub parser_schema: u32,
    pub normalization_policy: u32,
}

impl CranSnapshotCachePolicy {
    pub fn at(now: jiff::Timestamp) -> Self {
        Self {
            now,
            fallback_ttl: DEFAULT_COMPATIBLE_GENERATION_TTL,
            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
            parser_schema: CRAN_PARSER_SCHEMA,
            normalization_policy: CRAN_NORMALIZATION_POLICY,
        }
    }
}

impl Default for CranSnapshotCachePolicy {
    fn default() -> Self {
        Self::at(jiff::Timestamp::now())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CranSnapshotCacheStatus {
    Fresh,
    Stale,
    Missing,
    RevisionIncompatible,
    Corrupt,
    Incomplete,
}

/// A typed explanation for reusing or rejecting the provider-owned current
/// generation. Local generation names and paths are intentionally omitted.
#[derive(Clone, Debug)]
pub struct CranSnapshotCacheDiagnostic {
    status: CranSnapshotCacheStatus,
    age_seconds: Option<u64>,
    endpoints: Vec<Box<str>>,
    diagnostic: Box<str>,
}

impl std::fmt::Display for CranSnapshotCacheDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.status, self.diagnostic)
    }
}

impl std::error::Error for CranSnapshotCacheDiagnostic {}

impl CranSnapshotCacheDiagnostic {
    pub fn new(
        status: CranSnapshotCacheStatus,
        age_seconds: Option<u64>,
        endpoints: impl IntoIterator<Item = impl Into<Box<str>>>,
        diagnostic: impl Into<Box<str>>,
    ) -> Self {
        let mut endpoints = endpoints.into_iter().map(Into::into).collect::<Vec<_>>();
        endpoints.sort();
        endpoints.dedup();
        Self {
            status,
            age_seconds,
            endpoints,
            diagnostic: diagnostic.into(),
        }
    }
    pub fn status(&self) -> CranSnapshotCacheStatus {
        self.status
    }
    pub fn age_seconds(&self) -> Option<u64> {
        self.age_seconds
    }
    pub fn endpoints(&self) -> impl Iterator<Item = &str> {
        self.endpoints.iter().map(Box::as_ref)
    }
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }

    pub fn is_routine_online_fallback(&self) -> bool {
        matches!(self.status, CranSnapshotCacheStatus::Missing)
    }

    pub fn closure_incomplete(error: &rsolve_core::CandidateLoadError) -> Self {
        let status = match error.category() {
            rsolve_core::CandidateLoadErrorCategory::SnapshotInvalid => {
                CranSnapshotCacheStatus::Corrupt
            }
            _ => CranSnapshotCacheStatus::Incomplete,
        };
        Self {
            status,
            age_seconds: None,
            endpoints: Vec::new(),
            diagnostic: format!(
                "cached CRAN generation cannot be used for the requested dependency closure: {error}"
            )
            .into(),
        }
    }
}

pub enum CranSnapshotCacheResult {
    Compatible {
        loader: Box<ReadOnlySnapshotCandidateLoader>,
        diagnostic: CranSnapshotCacheDiagnostic,
    },
    Rejected(CranSnapshotCacheDiagnostic),
}

/// Inspect the current immutable generation without transport. This is the
/// sole CRAN freshness boundary; resolver traversal remains loader-only.
pub fn inspect_cran_snapshot_cache(
    store: &SnapshotStore,
    policy: &CranSnapshotCachePolicy,
) -> CranSnapshotCacheResult {
    let loader = match store.read_current_optional() {
        Ok(Some(loader)) => loader,
        Ok(None) => {
            return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
                status: CranSnapshotCacheStatus::Missing,
                age_seconds: None,
                endpoints: Vec::new(),
                diagnostic: "current CRAN snapshot pointer is missing".into(),
            });
        }
        Err(error) => {
            return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
                status: CranSnapshotCacheStatus::Corrupt,
                age_seconds: None,
                endpoints: Vec::new(),
                diagnostic: error.diagnostic().into(),
            });
        }
    };
    let header = loader.header();
    if header.compatibility_profile != policy.compatibility_profile
        || header.parser_schema != policy.parser_schema
        || header.normalization_policy != policy.normalization_policy
    {
        return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
            status: CranSnapshotCacheStatus::RevisionIncompatible,
            age_seconds: None,
            endpoints: canonical_endpoints(header),
            diagnostic: format!(
                "CRAN snapshot compatibility revisions are incompatible (profile {}, parser {}, normalization {})",
                header.compatibility_profile, header.parser_schema, header.normalization_policy
            ).into(),
        });
    }
    let mut oldest_source_age = 0_i64;
    let mut future_source = false;
    for source in &header.sources {
        let observed = match source.observed_at.parse::<jiff::Timestamp>() {
            Ok(observed) => observed,
            Err(error) => {
                return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
                    status: CranSnapshotCacheStatus::Corrupt,
                    age_seconds: None,
                    endpoints: Vec::new(),
                    diagnostic: format!("invalid source observed_at: {error}").into(),
                });
            }
        };
        let age = policy.now.duration_since(observed).as_secs();
        future_source |= age < 0;
        oldest_source_age = oldest_source_age.max(age.max(0));
    }
    if header.sources.is_empty() {
        return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
            status: CranSnapshotCacheStatus::Corrupt,
            age_seconds: None,
            endpoints: Vec::new(),
            diagnostic: "CRAN snapshot has no source observations".into(),
        });
    }
    let age_seconds = u64::try_from(oldest_source_age).unwrap_or(u64::MAX);
    let fresh = !future_source
        && oldest_source_age <= i64::try_from(policy.fallback_ttl.as_secs()).unwrap_or(i64::MAX);
    let status = if fresh {
        CranSnapshotCacheStatus::Fresh
    } else {
        CranSnapshotCacheStatus::Stale
    };
    let diagnostic = CranSnapshotCacheDiagnostic {
        status,
        age_seconds: Some(age_seconds),
        endpoints: canonical_endpoints(header),
        diagnostic: if fresh {
            "compatible CRAN snapshot generation is within the fallback freshness TTL".into()
        } else if future_source {
            "CRAN snapshot source timestamp is in the future; generation is not fresh for online reuse".into()
        } else {
            "compatible CRAN snapshot generation is stale but remains usable offline".into()
        },
    };
    CranSnapshotCacheResult::Compatible {
        loader: Box::new(loader),
        diagnostic,
    }
}

fn canonical_endpoints(header: &crate::snapshot::SnapshotHeaderV1) -> Vec<Box<str>> {
    let mut endpoints = header
        .sources
        .iter()
        .map(|source| source.endpoint.clone())
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    endpoints.into_iter().map(String::into_boxed_str).collect()
}

/// A transport-neutral diagnostic from refreshing one package's CRAN source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CranRefreshDiagnostic {
    endpoint: Box<str>,
    status: Option<u16>,
    status_detail: CranFastPathStatus,
    source: CranRefreshSource,
}

impl CranRefreshDiagnostic {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn status(&self) -> Option<u16> {
        self.status
    }

    pub fn status_detail(&self) -> &CranFastPathStatus {
        &self.status_detail
    }

    pub fn source(&self) -> CranRefreshSource {
        self.source
    }
}

enum CandidateSource {
    Fast(CranCatalog),
    Fallback(Rc<[ArchiveEntry]>),
}

/// A refreshed CRAN candidate source.
pub(crate) struct CranProvider<T> {
    package: PackageName,
    transport: RefCell<T>,
    base_url: Box<str>,
    source: CandidateSource,
    diagnostics: Vec<CranRefreshDiagnostic>,
    loaded: RefCell<Option<Result<Vec<PackageRelease>, CandidateLoadError>>>,
    evidence: Option<Rc<RefCell<Vec<CranEvidenceObservation>>>>,
}

impl<T: Transport> CranProvider<T> {
    /// Refresh one package's archive source.  The fast-path endpoint is
    /// requested exactly once per provider instance.
    #[cfg(test)]
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
            match CranCatalog::from_archive_index_rds_with_options(
                &response.body,
                &provider_rds_read_options(),
            ) {
                Ok(catalog) => {
                    diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.clone().into_boxed_str(),
                        status: Some(response.status),
                        status_detail: CranFastPathStatus::Available,
                        source: CranRefreshSource::ArchiveFastPath,
                    });
                    CandidateSource::Fast(catalog)
                }
                Err(error) => {
                    diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.clone().into_boxed_str(),
                        status: Some(response.status),
                        status_detail: CranFastPathStatus::Invalid {
                            status: response.status,
                            diagnostic: error.to_string().into_boxed_str(),
                        },
                        source: CranRefreshSource::ArchiveFastPath,
                    });
                    Self::fallback_source(&transport, &base_url)?
                }
            }
        } else {
            diagnostics.push(CranRefreshDiagnostic {
                endpoint: endpoint.clone().into_boxed_str(),
                status: Some(response.status),
                status_detail: if matches!(response.status, 404 | 410) {
                    CranFastPathStatus::Unsupported {
                        status: response.status,
                    }
                } else {
                    CranFastPathStatus::Invalid {
                        status: response.status,
                        diagnostic: "unexpected fast-path status".into(),
                    }
                },
                source: CranRefreshSource::ArchiveFastPath,
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
            evidence: None,
        })
    }

    pub(crate) fn diagnostics(&self) -> &[CranRefreshDiagnostic] {
        &self.diagnostics
    }

    fn from_source(
        transport: T,
        base_url: impl AsRef<str>,
        package: PackageName,
        source: CandidateSource,
        diagnostics: Vec<CranRefreshDiagnostic>,
        evidence: Option<Rc<RefCell<Vec<CranEvidenceObservation>>>>,
    ) -> Self {
        Self {
            package,
            transport: RefCell::new(transport),
            base_url: base_url.as_ref().trim_end_matches('/').into(),
            source,
            diagnostics,
            loaded: RefCell::new(None),
            evidence,
        }
    }

    #[cfg(test)]
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
        let entries = enumerate_archive_rds_for_provider(&response.body)
            .map_err(CranProviderError::History)?;
        Ok(CandidateSource::Fallback(Rc::from(
            entries.into_boxed_slice(),
        )))
    }

    fn load_fallback(
        &self,
        entries: &[ArchiveEntry],
    ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let mut releases = Vec::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.package() == &self.package)
        {
            let url = format!(
                "{}/src/contrib/Archive/{}",
                self.base_url,
                entry.source_archive_relative_path()
            );
            let transport = self.transport.borrow();
            let response = transport.get(&url).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!(
                        "failed to fetch {}: {error}",
                        entry.source_archive_relative_path()
                    ),
                )
            })?;
            if response.status != 200 {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!(
                        "failed to fetch {}: HTTP {}",
                        entry.source_archive_relative_path(),
                        response.status
                    ),
                ));
            }
            if response.body.len() as u64 != entry.size() {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!("size mismatch for {}", entry.source_archive_relative_path()),
                ));
            }
            let description = extract_description(&response.body).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!(
                        "invalid DESCRIPTION in {}: {error}",
                        entry.source_archive_relative_path()
                    ),
                )
            })?;
            let catalog = CranCatalog::from_description(&description).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!(
                        "invalid DESCRIPTION in {}: {error}",
                        entry.source_archive_relative_path()
                    ),
                )
            })?;
            if let Some(evidence) = &self.evidence {
                let source = source_input("cran-archive-tarball", "tar.gz", &url, &response.body);
                let records =
                    CranCatalog::observations_from_description(&description).map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::MetadataInvalid,
                            format!(
                                "invalid DESCRIPTION in {}: {error}",
                                entry.source_archive_relative_path()
                            ),
                        )
                    })?;
                let mut captured = evidence.borrow_mut();
                for record in records
                    .iter()
                    .filter(|record| record.package() == entry.package())
                {
                    captured.push(tarball_record_to_evidence(
                        record,
                        source.clone(),
                        url.clone(),
                        response.body.len() as u64,
                    ));
                }
            }
            releases.extend(catalog.candidates(entry.package()).iter().cloned());
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

#[cfg(test)]
enum CachedProvider<T> {
    Ready(CranProvider<Rc<T>>),
    Failed(CandidateLoadError),
}

/// The shared lazy runtime path used by fixture and concrete transports.
#[cfg(test)]
pub(crate) struct CranRuntimeLoader<T> {
    base_url: Box<str>,
    transport: Rc<T>,
    providers: RefCell<HashMap<PackageName, CachedProvider<T>>>,
    diagnostics: RefCell<HashMap<PackageName, Vec<CranRefreshDiagnostic>>>,
}

#[cfg(test)]
impl<T: Transport> CranRuntimeLoader<T> {
    pub(crate) fn new(transport: T, base_url: impl AsRef<str>) -> Self {
        Self {
            base_url: base_url.as_ref().trim_end_matches('/').into(),
            transport: Rc::new(transport),
            providers: RefCell::new(HashMap::new()),
            diagnostics: RefCell::new(HashMap::new()),
        }
    }

    fn refresh_provider(&self, package: &PackageName) -> CachedProvider<T> {
        match CranProvider::refresh(Rc::clone(&self.transport), &self.base_url, package.clone()) {
            Ok(provider) => {
                self.diagnostics
                    .borrow_mut()
                    .insert(package.clone(), provider.diagnostics().to_vec());
                CachedProvider::Ready(provider)
            }
            Err(error) => CachedProvider::Failed(provider_error(error)),
        }
    }

    pub(crate) fn diagnostics(&self) -> Vec<CranRefreshDiagnostic> {
        let mut diagnostics = self
            .diagnostics
            .borrow()
            .values()
            .flat_map(|items| items.iter().cloned())
            .collect::<Vec<_>>();
        diagnostics.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
        diagnostics
    }
}

#[cfg(test)]
impl<T: Transport> CandidateLoader for CranRuntimeLoader<T> {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN provider has no candidates for {package:?}"),
            ));
        };
        if !self.providers.borrow().contains_key(name) {
            let state = self.refresh_provider(name);
            self.providers
                .borrow_mut()
                .entry(name.clone())
                .or_insert(state);
        }
        let mut providers = self.providers.borrow_mut();
        let Some(provider) = providers.get_mut(name) else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                "CRAN provider cache insertion failed",
            ));
        };
        match provider {
            CachedProvider::Ready(provider) => provider.releases(package),
            CachedProvider::Failed(error) => Err(error.clone()),
        }
    }
}

/// A transport-free, process-local view handed to the resolver after refresh.
#[derive(Clone, Debug, Default)]
pub struct CranCandidateSnapshot {
    candidates: HashMap<PackageName, Vec<PackageRelease>>,
}

impl CandidateLoader for CranCandidateSnapshot {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot has no candidates for {package:?}"),
            ));
        };
        self.candidates.get(name).cloned().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot has not refreshed package {name}"),
            )
        })
    }
}

impl CranCandidateSnapshot {
    /// Builds a transport-free snapshot from already validated candidates.
    /// This is useful for hermetic orchestration tests and in-memory callers.
    pub fn from_candidates<I>(candidates: I) -> Self
    where
        I: IntoIterator<Item = (PackageName, Vec<PackageRelease>)>,
    {
        Self {
            candidates: candidates.into_iter().collect(),
        }
    }

    /// Returns whether this snapshot contains a refresh result for `package`.
    pub fn contains_package(&self, package: &PackageName) -> bool {
        self.candidates.contains_key(package)
    }

    /// Returns whether an installed-name solver key still needs refreshing.
    pub fn needs_refresh(&self, package: &SolverKey) -> bool {
        matches!(package, SolverKey::InstalledName(name) if !self.contains_package(name))
    }
}

/// A single refresh session. All network and parsing state is discarded from
/// the resolver-facing snapshot once refresh returns it.
struct CranRefreshSession<T> {
    base_url: Box<str>,
    transport: Rc<T>,
    current: Option<Result<Rc<CranCatalog>, CandidateLoadError>>,
    history: Option<Result<HistorySource, CandidateLoadError>>,
    packages: HashMap<PackageName, Result<Vec<PackageRelease>, CandidateLoadError>>,
    diagnostics: Vec<CranRefreshDiagnostic>,
    evidence: Rc<RefCell<Vec<CranEvidenceObservation>>>,
}

#[derive(Clone)]
enum HistorySource {
    Available(Rc<[ArchiveEntry]>),
    Absent,
}

impl<T: Transport> CranRefreshSession<T> {
    fn new(transport: Rc<T>, base_url: impl AsRef<str>) -> Self {
        Self {
            base_url: base_url.as_ref().trim_end_matches('/').into(),
            transport,
            current: None,
            history: None,
            packages: HashMap::new(),
            diagnostics: Vec::new(),
            evidence: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn ensure_current(&mut self) -> Result<Rc<CranCatalog>, CandidateLoadError> {
        if let Some(result) = &self.current {
            return result.clone();
        }
        let representations = [
            (CranCurrentIndexRepresentation::Rds, "PACKAGES.rds"),
            (CranCurrentIndexRepresentation::Gzip, "PACKAGES.gz"),
            (CranCurrentIndexRepresentation::PlainDcf, "PACKAGES"),
        ];
        let mut failures = Vec::new();
        let mut saw_metadata_invalid = false;
        for (representation, filename) in representations {
            let endpoint = format!("{}/src/contrib/{filename}", self.base_url);
            let response = match self.transport.get(&endpoint) {
                Ok(response) => response,
                Err(error) => {
                    self.push_current_diagnostic(
                        endpoint.clone(),
                        representation,
                        None,
                        format!("transport failure: {error}"),
                    );
                    failures.push(error.to_string());
                    continue;
                }
            };
            if response.status != 200 {
                let diagnostic = format!("unexpected current index status {}", response.status);
                self.push_current_diagnostic(
                    endpoint,
                    representation,
                    Some(response.status),
                    diagnostic.clone(),
                );
                failures.push(diagnostic);
                continue;
            }
            let parsed = match representation {
                CranCurrentIndexRepresentation::Rds => {
                    CranCatalog::from_archive_index_rds_with_options(
                        &response.body,
                        &provider_rds_read_options(),
                    )
                    .map_err(|error| error.to_string())
                }
                CranCurrentIndexRepresentation::Gzip => {
                    decode_gzip(&response.body).and_then(|body| {
                        CranCatalog::from_packages(&body).map_err(|error| error.to_string())
                    })
                }
                CranCurrentIndexRepresentation::PlainDcf => {
                    CranCatalog::from_packages(&response.body).map_err(|error| error.to_string())
                }
            };
            match parsed {
                Ok(catalog) => {
                    let records =
                        current_records(representation, &response.body).map_err(|error| {
                            let diagnostic = format!(
                                "validated current index could not be projected losslessly: {error}"
                            );
                            self.push_current_diagnostic(
                                endpoint.clone(),
                                representation,
                                Some(response.status),
                                diagnostic.clone(),
                            );
                            CandidateLoadError::new(
                                CandidateLoadErrorCategory::MetadataInvalid,
                                diagnostic,
                            )
                        })?;
                    let source = source_input(
                        "cran-current",
                        match representation {
                            CranCurrentIndexRepresentation::Rds => "rds",
                            CranCurrentIndexRepresentation::Gzip => "gzip",
                            CranCurrentIndexRepresentation::PlainDcf => "dcf",
                        },
                        &endpoint,
                        &response.body,
                    );
                    self.evidence
                        .borrow_mut()
                        .extend(records.iter().map(|record| {
                            index_record_to_evidence(
                                record,
                                source.clone(),
                                &self.base_url,
                                true,
                                FreshnessStateV1::CurrentGeneration,
                            )
                        }));
                    self.diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.into(),
                        status: Some(response.status),
                        status_detail: CranFastPathStatus::Available,
                        source: CranRefreshSource::CurrentIndex(representation),
                    });
                    let catalog = Rc::new(catalog);
                    self.current = Some(Ok(Rc::clone(&catalog)));
                    return Ok(catalog);
                }
                Err(error) => {
                    self.push_current_diagnostic(
                        endpoint,
                        representation,
                        Some(response.status),
                        error.clone(),
                    );
                    failures.push(error);
                    saw_metadata_invalid = true;
                }
            }
        }
        let error = CandidateLoadError::new(
            if saw_metadata_invalid {
                CandidateLoadErrorCategory::MetadataInvalid
            } else {
                CandidateLoadErrorCategory::TransportFailure
            },
            format!(
                "all CRAN current index representations failed: {}",
                failures.join("; ")
            ),
        );
        self.current = Some(Err(error.clone()));
        Err(error)
    }

    fn push_current_diagnostic(
        &mut self,
        endpoint: String,
        representation: CranCurrentIndexRepresentation,
        status: Option<u16>,
        diagnostic: String,
    ) {
        self.diagnostics.push(CranRefreshDiagnostic {
            endpoint: endpoint.into_boxed_str(),
            status,
            status_detail: CranFastPathStatus::Invalid {
                status: status.unwrap_or_default(),
                diagnostic: diagnostic.into_boxed_str(),
            },
            source: CranRefreshSource::CurrentIndex(representation),
        });
    }

    fn ensure_history(&mut self) -> Result<HistorySource, CandidateLoadError> {
        if let Some(result) = &self.history {
            return result.clone();
        }
        let endpoint = format!("{}/Meta/archive.rds", self.base_url);
        let result = match self.transport.get(&endpoint) {
            Err(error) => {
                self.push_history_diagnostic(
                    endpoint.clone(),
                    None,
                    format!("transport failure: {error}"),
                );
                Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!("failed to refresh {endpoint}: {error}"),
                ))
            }
            Ok(response) if matches!(response.status, 404 | 410) => {
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(response.status),
                    status_detail: CranFastPathStatus::Absent {
                        status: response.status,
                    },
                    source: CranRefreshSource::ArchiveHistory,
                });
                Ok(HistorySource::Absent)
            }
            Ok(response) if response.status != 200 => {
                let diagnostic = format!("unexpected archive history status {}", response.status);
                self.push_history_diagnostic(
                    endpoint.clone(),
                    Some(response.status),
                    diagnostic.clone(),
                );
                Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!("failed to refresh {endpoint}: HTTP {}", response.status),
                ))
            }
            Ok(response) => match enumerate_archive_rds_for_provider(&response.body) {
                Ok(entries) => Ok(HistorySource::Available(Rc::from(
                    entries.into_boxed_slice(),
                ))),
                Err(error) => {
                    let diagnostic = format!("invalid CRAN archive history: {error}");
                    self.push_history_diagnostic(
                        endpoint.clone(),
                        Some(response.status),
                        diagnostic.clone(),
                    );
                    Err(CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        diagnostic,
                    ))
                }
            },
        };
        self.history = Some(result.clone());
        result
    }

    fn push_history_diagnostic(
        &mut self,
        endpoint: String,
        status: Option<u16>,
        diagnostic: String,
    ) {
        self.diagnostics.push(CranRefreshDiagnostic {
            endpoint: endpoint.into_boxed_str(),
            status,
            status_detail: CranFastPathStatus::Invalid {
                status: status.unwrap_or_default(),
                diagnostic: diagnostic.into_boxed_str(),
            },
            source: CranRefreshSource::ArchiveHistory,
        });
    }

    fn refresh_package(
        &mut self,
        package: &PackageName,
    ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        if let Some(result) = self.packages.get(package) {
            return result.clone();
        }
        let result = self.refresh_package_uncached(package);
        self.packages.insert(package.clone(), result.clone());
        result
    }

    fn refresh_package_uncached(
        &mut self,
        package: &PackageName,
    ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let current = self.ensure_current()?.candidates(package).to_vec();
        let endpoint = format!(
            "{}/src/contrib/Archive/{}/PACKAGES.rds",
            self.base_url,
            package.as_str()
        );
        let mut package_diagnostics = Vec::new();
        let fast_result = match self.transport.get(&endpoint) {
            Err(error) => {
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: None,
                    status_detail: CranFastPathStatus::Invalid {
                        status: 0,
                        diagnostic: format!("transport failure: {error}").into_boxed_str(),
                    },
                    source: CranRefreshSource::ArchiveFastPath,
                });
                Err(FastPathFailure::Invalid {
                    category: CandidateLoadErrorCategory::TransportFailure,
                    diagnostic: format!("archive fast path for {package} failed: {error}").into(),
                })
            }
            Ok(response) if response.status == 200 => {
                match CranCatalog::from_archive_index_rds_with_options(
                    &response.body,
                    &provider_rds_read_options(),
                ) {
                    Ok(catalog) => {
                        let records = match CranCatalog::observations_from_archive_index_rds(
                            &response.body,
                        ) {
                            Ok(records) => records,
                            Err(error) => {
                                return Err(CandidateLoadError::new(
                                    CandidateLoadErrorCategory::MetadataInvalid,
                                    format!(
                                        "validated archive index could not be projected losslessly: {error}"
                                    ),
                                ));
                            }
                        };
                        let source =
                            source_input("cran-archive-index", "rds", &endpoint, &response.body);
                        self.evidence
                            .borrow_mut()
                            .extend(records.iter().map(|record| {
                                index_record_to_evidence(
                                    record,
                                    source.clone(),
                                    &self.base_url,
                                    false,
                                    FreshnessStateV1::BulkGeneration,
                                )
                            }));
                        package_diagnostics.push(CranRefreshDiagnostic {
                            endpoint: endpoint.clone().into_boxed_str(),
                            status: Some(response.status),
                            status_detail: CranFastPathStatus::Available,
                            source: CranRefreshSource::ArchiveFastPath,
                        });
                        Ok(CandidateSource::Fast(catalog))
                    }
                    Err(error) => {
                        let diagnostic = format!(
                            "archive fast path for {package} has invalid metadata: {error}"
                        );
                        package_diagnostics.push(CranRefreshDiagnostic {
                            endpoint: endpoint.clone().into_boxed_str(),
                            status: Some(response.status),
                            status_detail: CranFastPathStatus::Invalid {
                                status: response.status,
                                diagnostic: diagnostic.clone().into_boxed_str(),
                            },
                            source: CranRefreshSource::ArchiveFastPath,
                        });
                        Err(FastPathFailure::Invalid {
                            category: CandidateLoadErrorCategory::MetadataInvalid,
                            diagnostic: diagnostic.into_boxed_str(),
                        })
                    }
                }
            }
            Ok(response) => {
                let status = response.status;
                let status_detail = if matches!(status, 404 | 410) {
                    CranFastPathStatus::Unsupported { status }
                } else {
                    CranFastPathStatus::Invalid {
                        status,
                        diagnostic: "unexpected fast-path status".into(),
                    }
                };
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail,
                    source: CranRefreshSource::ArchiveFastPath,
                });
                if matches!(status, 404 | 410) {
                    Err(FastPathFailure::Unsupported)
                } else {
                    Err(FastPathFailure::Invalid {
                        category: CandidateLoadErrorCategory::TransportFailure,
                        diagnostic: format!(
                            "archive fast path for {package} returned unexpected HTTP {status}"
                        )
                        .into(),
                    })
                }
            }
        };
        let mut provider_diagnostics = Vec::new();
        let source = match fast_result {
            Ok(source) => {
                provider_diagnostics = package_diagnostics;
                source
            }
            Err(failure) => match self.resolve_fast_path_failure(package_diagnostics, failure)? {
                Some(source) => source,
                None => return Ok(current),
            },
        };
        let provider = CranProvider::from_source(
            Rc::clone(&self.transport),
            &self.base_url,
            package.clone(),
            source,
            provider_diagnostics,
            Some(Rc::clone(&self.evidence)),
        );
        self.diagnostics
            .extend(provider.diagnostics().iter().cloned());
        let archived = provider.releases(&SolverKey::InstalledName(package.clone()))?;
        let mut aggregation = ReleaseAggregation::new();
        for release in current.into_iter().chain(archived) {
            aggregation.observe_release(release).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("conflicting CRAN release metadata for {package}: {error}"),
                )
            })?;
        }
        let mut candidates = aggregation.releases().cloned().collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.version().cmp(right.version()));
        Ok(candidates)
    }

    fn refresh_packages(
        &mut self,
        roots: &[PackageName],
    ) -> Result<CranCandidateSnapshot, CandidateLoadError> {
        for package in roots {
            self.refresh_package(package)?;
        }
        Ok(CranCandidateSnapshot {
            candidates: self
                .packages
                .iter()
                .filter_map(|(package, result)| {
                    result
                        .as_ref()
                        .ok()
                        .map(|candidates| (package.clone(), candidates.clone()))
                })
                .collect(),
        })
    }
}

#[cfg(test)]
fn provider_error(error: CranProviderError) -> CandidateLoadError {
    match error {
        CranProviderError::Transport { endpoint, source } => CandidateLoadError::new(
            CandidateLoadErrorCategory::TransportFailure,
            format!("failed to refresh {endpoint}: {source}"),
        ),
        CranProviderError::History(error) => CandidateLoadError::new(
            CandidateLoadErrorCategory::MetadataInvalid,
            format!("invalid CRAN archive history: {error}"),
        ),
    }
}

#[cfg(test)]
mod tests;
