//! CRAN archive refresh and lazy DESCRIPTION fallback.

use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(test)]
use std::error::Error;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;

use self::raw_cache::{
    RawCache, RawCacheEntry, RawCacheLookup, RawCacheRepresentation, RawCacheWrite,
};
use super::archive_index::{
    CranArchiveIndexProviderError, provider_archive_index_rds, provider_rds_read_options,
};
use super::catalog::{CranCatalog, CranCatalogObservation};
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

// Raw-response/cache integration consumes this provider-private policy seam
// without coupling semantic snapshot inspection to response headers.
pub mod cache_policy;
mod negative;
// Raw-cache APIs remain provider-private and are used by current-index refresh.
#[cfg_attr(not(test), expect(dead_code))]
pub(crate) mod raw_cache;
mod refresher;
mod snapshot;
mod transport;

use self::cache_policy::{cache_control_policy, permits_reuse};
use negative::FastPathFailure;
#[cfg(test)]
use refresher::canonical_base_url;
pub use refresher::{CranSnapshotRefresher, CranSnapshotRefresherError};
use refresher::{decode_gzip, extract_description};
#[cfg(test)]
pub(crate) use snapshot::refresh_and_publish_with_transport;
use snapshot::{
    archive_rejection_to_evidence, current_records, index_record_to_evidence, source_input,
    tarball_record_to_evidence,
};
#[cfg(test)]
pub(crate) use transport::TransportError;
pub(crate) use transport::{
    Transport, TransportResponse, TransportResponseHeaders, TransportValidators,
};

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
    /// The archive index was usable after quarantining release-local semantic
    /// errors; the admitted sibling releases remain available.
    AvailableWithRejections {
        count: usize,
        diagnostic: Box<str>,
    },
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
    pub expected_endpoint: Option<Box<str>>,
}

impl CranSnapshotCachePolicy {
    pub fn at(now: jiff::Timestamp) -> Self {
        Self {
            now,
            fallback_ttl: DEFAULT_COMPATIBLE_GENERATION_TTL,
            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
            parser_schema: CRAN_PARSER_SCHEMA,
            normalization_policy: CRAN_NORMALIZATION_POLICY,
            expected_endpoint: None,
        }
    }

    pub fn with_expected_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.expected_endpoint = Some(endpoint.as_ref().trim_end_matches('/').to_owned().into());
        self
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
    let validation = store.read_current_validation().ok().flatten();
    let header_source_identities = header
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source.content_sha256.as_str()))
        .collect::<Vec<_>>();
    let validation_matches = validation.as_ref().is_some_and(|record| {
        record.registry_id == header.registry_id
            && record.generation == header.generation
            && record.compatibility_profile == header.compatibility_profile
            && record.parser_schema == header.parser_schema
            && record.normalization_policy == header.normalization_policy
            && policy
                .expected_endpoint
                .as_deref()
                .is_none_or(|endpoint| record.effective_endpoint == endpoint)
            && record
                .sources
                .iter()
                .map(|source| (source.id.as_str(), source.content_sha256.as_str()))
                .collect::<Vec<_>>()
                == header_source_identities
            && canonical_validation_source_endpoints(record) == canonical_endpoints(header)
    });
    let validation_timestamp = validation
        .clone()
        .filter(|_| validation_matches)
        .and_then(|record| record.validated_at.parse::<jiff::Timestamp>().ok());
    let endpoint_provenance_matches = policy.expected_endpoint.as_deref().is_none_or(|expected| {
        let header_has_expected_endpoint = header
            .sources
            .iter()
            .all(|source| endpoint_belongs_to(&source.endpoint, expected));
        header_has_expected_endpoint
            && validation
                .as_ref()
                .is_none_or(|record| !validation_matches || record.effective_endpoint == expected)
    });
    let diagnostic_endpoints = validation
        .as_ref()
        .filter(|_| validation_matches)
        .map(canonical_validation_endpoints)
        .unwrap_or_else(|| canonical_endpoints(header));
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
    if let Some(validated_at) = validation_timestamp {
        let age = policy.now.duration_since(validated_at).as_secs();
        future_source |= age < 0;
        oldest_source_age = age.max(0);
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
    let fresh = endpoint_provenance_matches
        && !future_source
        && oldest_source_age <= i64::try_from(policy.fallback_ttl.as_secs()).unwrap_or(i64::MAX);
    let status = if fresh {
        CranSnapshotCacheStatus::Fresh
    } else {
        CranSnapshotCacheStatus::Stale
    };
    let diagnostic = CranSnapshotCacheDiagnostic {
        status,
        age_seconds: Some(age_seconds),
        endpoints: diagnostic_endpoints,
        diagnostic: if fresh {
            "compatible CRAN snapshot generation is within the fallback freshness TTL".into()
        } else if !endpoint_provenance_matches {
            "CRAN snapshot evidence belongs to a different acquisition endpoint; it is not fresh for online reuse".into()
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

fn endpoint_belongs_to(endpoint: &str, base: &str) -> bool {
    endpoint == base
        || endpoint
            .strip_prefix(base)
            .is_some_and(|suffix| suffix.starts_with('/'))
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

fn canonical_validation_endpoints(record: &crate::snapshot::CurrentValidationV1) -> Vec<Box<str>> {
    let mut endpoints = record
        .sources
        .iter()
        .flat_map(|source| source.endpoint.split('\n'))
        .chain(record.effective_endpoint.split('\n'))
        .filter(|endpoint| !endpoint.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    endpoints.into_iter().map(String::into_boxed_str).collect()
}

fn canonical_validation_source_endpoints(
    record: &crate::snapshot::CurrentValidationV1,
) -> Vec<Box<str>> {
    let mut endpoints = record
        .sources
        .iter()
        .flat_map(|source| source.endpoint.split('\n'))
        .filter(|endpoint| !endpoint.is_empty())
        .map(str::to_owned)
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
        let endpoint = format!("{base_url}/src/contrib/Meta/archive.rds");
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
    raw_cache: Option<RawCache>,
    test_now: Option<jiff::Timestamp>,
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

struct CurrentBody {
    body: Vec<u8>,
    observed_at_timestamp: jiff::Timestamp,
    observed_at: String,
    etag: Option<Box<str>>,
    last_modified: Option<Box<str>>,
    cache_control: self::cache_policy::CacheControlHeader,
}

struct MetadataAcquisitionFailure {
    status: Option<u16>,
    category: CandidateLoadErrorCategory,
    diagnostic: Box<str>,
    fallback_allowed: bool,
}

enum MetadataParseFailure {
    Invalid(Box<str>),
    NoFallback(Box<str>),
}

impl MetadataParseFailure {
    fn allows_fallback(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }
}

impl fmt::Display for MetadataParseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(diagnostic) | Self::NoFallback(diagnostic) => {
                formatter.write_str(diagnostic)
            }
        }
    }
}

#[derive(Clone, Copy)]
enum MetadataAcquisitionOutcome {
    Cached,
    Network200,
    Revalidated304,
}

impl MetadataAcquisitionFailure {
    fn cache(error: impl std::fmt::Display) -> Self {
        Self {
            status: None,
            category: CandidateLoadErrorCategory::SnapshotInvalid,
            diagnostic: format!("CRAN metadata raw cache is invalid: {error}").into(),
            fallback_allowed: false,
        }
    }

    fn response(status: u16, diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            status: Some(status),
            category: CandidateLoadErrorCategory::TransportFailure,
            diagnostic: diagnostic.into(),
            fallback_allowed: true,
        }
    }

    fn transport(error: impl std::fmt::Display) -> Self {
        Self {
            status: None,
            category: CandidateLoadErrorCategory::TransportFailure,
            diagnostic: format!("transport failure: {error}").into(),
            fallback_allowed: true,
        }
    }

    fn invalid(status: Option<u16>, diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            status,
            category: CandidateLoadErrorCategory::MetadataInvalid,
            diagnostic: diagnostic.into(),
            fallback_allowed: true,
        }
    }

    fn parse(status: Option<u16>, diagnostic: impl Into<Box<str>>, allows_fallback: bool) -> Self {
        let mut failure = Self::invalid(status, diagnostic);
        failure.fallback_allowed = allows_fallback;
        failure
    }

    fn into_candidate(self) -> CandidateLoadError {
        CandidateLoadError::new(self.category, self.diagnostic)
    }
}

#[derive(Clone, Copy)]
enum CurrentBodyOrigin {
    Cached,
    Network200,
    Revalidated304,
}

impl CurrentBody {
    fn from_cache(entry: RawCacheEntry) -> Self {
        Self {
            body: entry.body,
            observed_at_timestamp: entry.observed_at,
            observed_at: entry.observed_at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            etag: entry.etag,
            last_modified: entry.last_modified,
            cache_control: entry.cache_control,
        }
    }

    fn from_response(response: TransportResponse, observed_at: jiff::Timestamp) -> Self {
        let TransportResponse { body, headers, .. } = response;
        Self {
            body,
            observed_at_timestamp: observed_at,
            observed_at: observed_at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            etag: headers.etag,
            last_modified: headers.last_modified,
            cache_control: headers.cache_control,
        }
    }

    fn source(
        &self,
        representation: CranCurrentIndexRepresentation,
        endpoint: &str,
    ) -> crate::snapshot::SourceInput {
        self.source_as(
            "cran-current",
            match representation {
                CranCurrentIndexRepresentation::Rds => "rds",
                CranCurrentIndexRepresentation::Gzip => "gzip",
                CranCurrentIndexRepresentation::PlainDcf => "dcf",
            },
            endpoint,
        )
    }

    fn source_as(
        &self,
        kind: &str,
        representation: &str,
        endpoint: &str,
    ) -> crate::snapshot::SourceInput {
        snapshot::source_input_with_metadata(
            kind,
            representation,
            endpoint,
            &self.body,
            self.observed_at.clone(),
            self.etag.clone(),
            self.last_modified.clone(),
        )
    }
}

impl<T: Transport> CranRefreshSession<T> {
    fn new(transport: Rc<T>, base_url: impl AsRef<str>) -> Self {
        Self::new_with_clock(transport, base_url, None, None)
    }

    fn new_with_clock(
        transport: Rc<T>,
        base_url: impl AsRef<str>,
        test_now: Option<jiff::Timestamp>,
        raw_cache: Option<RawCache>,
    ) -> Self {
        Self {
            base_url: base_url.as_ref().trim_end_matches('/').into(),
            transport,
            raw_cache,
            test_now,
            current: None,
            history: None,
            packages: HashMap::new(),
            diagnostics: Vec::new(),
            evidence: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn now(&self) -> jiff::Timestamp {
        self.test_now.unwrap_or_else(jiff::Timestamp::now)
    }

    fn attach_raw_cache(&mut self, cache: RawCache) {
        self.raw_cache = Some(cache);
    }

    fn parse_current_body(
        representation: CranCurrentIndexRepresentation,
        body: &[u8],
    ) -> Result<(CranCatalog, Vec<CranCatalogObservation>), String> {
        let catalog = match representation {
            CranCurrentIndexRepresentation::Rds => {
                CranCatalog::from_archive_index_rds_with_options(body, &provider_rds_read_options())
                    .map_err(|error| error.to_string())?
            }
            CranCurrentIndexRepresentation::Gzip => {
                let decoded = decode_gzip(body)?;
                CranCatalog::from_packages(&decoded).map_err(|error| error.to_string())?
            }
            CranCurrentIndexRepresentation::PlainDcf => {
                CranCatalog::from_packages(body).map_err(|error| error.to_string())?
            }
        };
        let records = current_records(representation, body)?;
        Ok((catalog, records))
    }

    fn acquire_metadata<V, P>(
        &self,
        endpoint: &str,
        representation: RawCacheRepresentation,
        source_kind: &str,
        source_representation: &str,
        parse: P,
    ) -> Result<
        (V, crate::snapshot::SourceInput, MetadataAcquisitionOutcome),
        MetadataAcquisitionFailure,
    >
    where
        P: Fn(&[u8]) -> Result<V, MetadataParseFailure>,
    {
        let cache_key = self
            .raw_cache
            .as_ref()
            .map(|cache| {
                cache
                    .key(endpoint, representation)
                    .map_err(MetadataAcquisitionFailure::cache)
            })
            .transpose()?;
        let mut candidate = None;
        let mut origin = None;
        let mut network_attempted = false;
        if let (Some(cache), Some(key)) = (&self.raw_cache, &cache_key) {
            match cache.lookup(key) {
                RawCacheLookup::Hit(entry) => {
                    let policy = cache_control_policy(
                        &entry.cache_control,
                        DEFAULT_COMPATIBLE_GENERATION_TTL,
                    );
                    if permits_reuse(self.now(), entry.validated_at, policy) {
                        candidate = Some(CurrentBody::from_cache(entry));
                        origin = Some(CurrentBodyOrigin::Cached);
                    } else {
                        network_attempted = true;
                        let validators = TransportValidators::from_values(
                            entry.etag.as_deref(),
                            entry.last_modified.as_deref(),
                        );
                        let response = if validators.if_none_match.is_some()
                            || validators.if_modified_since.is_some()
                        {
                            self.transport.get_with_validators(endpoint, &validators)
                        } else {
                            self.transport.get(endpoint)
                        };
                        match response {
                            Ok(response) if response.status == 304 && response.body.is_empty() => {
                                let mut body = CurrentBody::from_cache(entry);
                                if !matches!(
                                    response.headers.cache_control,
                                    self::cache_policy::CacheControlHeader::Absent
                                ) {
                                    body.cache_control = response.headers.cache_control.clone();
                                }
                                if response.headers.etag.is_some() {
                                    body.etag = response.headers.etag.clone();
                                }
                                if response.headers.last_modified.is_some() {
                                    body.last_modified = response.headers.last_modified.clone();
                                }
                                candidate = Some(body);
                                origin = Some(CurrentBodyOrigin::Revalidated304);
                            }
                            Ok(response) if response.status == 200 => {
                                candidate = Some(CurrentBody::from_response(response, self.now()));
                                origin = Some(CurrentBodyOrigin::Network200);
                            }
                            Ok(response) => {
                                return Err(MetadataAcquisitionFailure::response(
                                    response.status,
                                    format!("unexpected metadata status {}", response.status),
                                ));
                            }
                            Err(error) => {
                                return Err(MetadataAcquisitionFailure::transport(error));
                            }
                        }
                    }
                }
                RawCacheLookup::Missing | RawCacheLookup::Corrupt(_) => {}
            }
        }
        if candidate.is_none() && !network_attempted {
            match self.transport.get(endpoint) {
                Ok(response) if response.status == 200 => {
                    candidate = Some(CurrentBody::from_response(response, self.now()));
                    origin = Some(CurrentBodyOrigin::Network200);
                }
                Ok(response) => {
                    return Err(MetadataAcquisitionFailure::response(
                        response.status,
                        format!("unexpected metadata status {}", response.status),
                    ));
                }
                Err(error) => return Err(MetadataAcquisitionFailure::transport(error)),
            }
        }
        let mut retried_unconditionally = false;
        while let Some(body) = candidate.take() {
            match parse(&body.body) {
                Ok(value) => {
                    let source = body.source_as(source_kind, source_representation, endpoint);
                    let mut body = Some(body);
                    if let (Some(cache), Some(key), Some(CurrentBodyOrigin::Network200)) =
                        (&self.raw_cache, &cache_key, origin)
                    {
                        let body = body.take().expect("validated metadata body");
                        cache
                            .publish(
                                key,
                                RawCacheWrite {
                                    status: 200,
                                    body: body.body,
                                    observed_at: body.observed_at_timestamp,
                                    validated_at: body.observed_at_timestamp,
                                    etag: body.etag,
                                    last_modified: body.last_modified,
                                    cache_control: body.cache_control,
                                },
                            )
                            .map_err(MetadataAcquisitionFailure::cache)?;
                    } else if let (
                        Some(cache),
                        Some(key),
                        Some(CurrentBodyOrigin::Revalidated304),
                    ) = (&self.raw_cache, &cache_key, origin)
                    {
                        let body = body.as_ref().expect("validated metadata body");
                        let headers = TransportResponseHeaders {
                            etag: body.etag.clone(),
                            last_modified: body.last_modified.clone(),
                            cache_control: body.cache_control.clone(),
                        };
                        cache
                            .update_validated_at_with_headers(key, self.now(), &headers)
                            .map_err(MetadataAcquisitionFailure::cache)?;
                    }
                    let outcome = match origin {
                        Some(CurrentBodyOrigin::Cached) => MetadataAcquisitionOutcome::Cached,
                        Some(CurrentBodyOrigin::Network200) => {
                            MetadataAcquisitionOutcome::Network200
                        }
                        Some(CurrentBodyOrigin::Revalidated304) => {
                            MetadataAcquisitionOutcome::Revalidated304
                        }
                        None => {
                            return Err(MetadataAcquisitionFailure::invalid(
                                None,
                                "metadata acquisition has no response outcome",
                            ));
                        }
                    };
                    return Ok((value, source, outcome));
                }
                Err(error)
                    if matches!(
                        origin,
                        Some(CurrentBodyOrigin::Cached | CurrentBodyOrigin::Revalidated304)
                    ) && !retried_unconditionally =>
                {
                    retried_unconditionally = true;
                    let allows_fallback = error.allows_fallback();
                    match self.transport.get(endpoint) {
                        Ok(response) if response.status == 200 => {
                            candidate = Some(CurrentBody::from_response(response, self.now()));
                            origin = Some(CurrentBodyOrigin::Network200);
                        }
                        Ok(response) => {
                            return Err(MetadataAcquisitionFailure::parse(
                                Some(response.status),
                                format!(
                                    "cached metadata was invalid ({error}) and unconditional recovery returned HTTP {}",
                                    response.status
                                ),
                                allows_fallback,
                            ));
                        }
                        Err(fetch_error) => {
                            return Err(MetadataAcquisitionFailure::parse(
                                None,
                                format!(
                                    "cached metadata was invalid ({error}) and unconditional recovery failed: {fetch_error}"
                                ),
                                allows_fallback,
                            ));
                        }
                    }
                }
                Err(error) => {
                    let allows_fallback = error.allows_fallback();
                    return Err(MetadataAcquisitionFailure::parse(
                        Some(200),
                        error.to_string(),
                        allows_fallback,
                    ));
                }
            }
        }
        Err(MetadataAcquisitionFailure::invalid(
            None,
            "metadata acquisition produced no body",
        ))
    }

    fn cache_error(error: impl std::fmt::Display) -> CandidateLoadError {
        CandidateLoadError::new(
            CandidateLoadErrorCategory::SnapshotInvalid,
            format!("CRAN current raw cache is invalid: {error}"),
        )
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
            let cache_key = self
                .raw_cache
                .as_ref()
                .map(|cache| {
                    cache
                        .key(
                            &endpoint,
                            match representation {
                                CranCurrentIndexRepresentation::Rds => {
                                    RawCacheRepresentation::CurrentRds
                                }
                                CranCurrentIndexRepresentation::Gzip => {
                                    RawCacheRepresentation::CurrentGzip
                                }
                                CranCurrentIndexRepresentation::PlainDcf => {
                                    RawCacheRepresentation::CurrentDcf
                                }
                            },
                        )
                        .map_err(Self::cache_error)
                })
                .transpose()?;
            let mut candidate = None;
            let mut origin = None;
            let mut network_attempted = false;
            if let (Some(cache), Some(key)) = (&self.raw_cache, &cache_key) {
                match cache.lookup(key) {
                    RawCacheLookup::Hit(entry) => {
                        let policy = cache_control_policy(
                            &entry.cache_control,
                            DEFAULT_COMPATIBLE_GENERATION_TTL,
                        );
                        if permits_reuse(self.now(), entry.validated_at, policy) {
                            candidate = Some(CurrentBody::from_cache(entry));
                            origin = Some(CurrentBodyOrigin::Cached);
                        } else {
                            network_attempted = true;
                            let validators = TransportValidators::from_values(
                                entry.etag.as_deref(),
                                entry.last_modified.as_deref(),
                            );
                            let response = if validators.if_none_match.is_some()
                                || validators.if_modified_since.is_some()
                            {
                                self.transport.get_with_validators(&endpoint, &validators)
                            } else {
                                self.transport.get(&endpoint)
                            };
                            match response {
                                Ok(response)
                                    if response.status == 304 && response.body.is_empty() =>
                                {
                                    let mut body = CurrentBody::from_cache(entry);
                                    if !matches!(
                                        response.headers.cache_control,
                                        self::cache_policy::CacheControlHeader::Absent
                                    ) {
                                        body.cache_control = response.headers.cache_control.clone();
                                    }
                                    if response.headers.etag.is_some() {
                                        body.etag = response.headers.etag.clone();
                                    }
                                    if response.headers.last_modified.is_some() {
                                        body.last_modified = response.headers.last_modified.clone();
                                    }
                                    candidate = Some(body);
                                    origin = Some(CurrentBodyOrigin::Revalidated304);
                                }
                                Ok(response) if response.status == 200 => {
                                    candidate =
                                        Some(CurrentBody::from_response(response, self.now()));
                                    origin = Some(CurrentBodyOrigin::Network200);
                                }
                                Ok(response) => {
                                    let diagnostic = format!(
                                        "unexpected current index status {}",
                                        response.status
                                    );
                                    self.push_current_diagnostic(
                                        endpoint.clone(),
                                        representation,
                                        Some(response.status),
                                        diagnostic.clone(),
                                    );
                                    failures.push(diagnostic);
                                }
                                Err(error) => {
                                    let diagnostic = format!("transport failure: {error}");
                                    self.push_current_diagnostic(
                                        endpoint.clone(),
                                        representation,
                                        None,
                                        diagnostic.clone(),
                                    );
                                    failures.push(diagnostic);
                                }
                            }
                        }
                    }
                    RawCacheLookup::Missing | RawCacheLookup::Corrupt(_) => {}
                }
            }
            if candidate.is_none() && !network_attempted {
                match self.transport.get(&endpoint) {
                    Ok(response) if response.status == 200 => {
                        candidate = Some(CurrentBody::from_response(response, self.now()));
                        origin = Some(CurrentBodyOrigin::Network200);
                    }
                    Ok(response) => {
                        let diagnostic =
                            format!("unexpected current index status {}", response.status);
                        self.push_current_diagnostic(
                            endpoint.clone(),
                            representation,
                            Some(response.status),
                            diagnostic.clone(),
                        );
                        failures.push(diagnostic);
                    }
                    Err(error) => {
                        let diagnostic = format!("transport failure: {error}");
                        self.push_current_diagnostic(
                            endpoint.clone(),
                            representation,
                            None,
                            diagnostic.clone(),
                        );
                        failures.push(diagnostic);
                    }
                }
            }
            let mut retried_unconditionally = false;
            while let Some(body) = candidate.take() {
                let parsed = Self::parse_current_body(representation, &body.body);
                let (catalog, records) = match parsed {
                    Ok(parsed) => parsed,
                    Err(error)
                        if matches!(
                            origin,
                            Some(CurrentBodyOrigin::Cached | CurrentBodyOrigin::Revalidated304)
                        ) && !retried_unconditionally =>
                    {
                        retried_unconditionally = true;
                        let cached_error = error;
                        match self.transport.get(&endpoint) {
                            Ok(response) if response.status == 200 => {
                                candidate = Some(CurrentBody::from_response(response, self.now()));
                                origin = Some(CurrentBodyOrigin::Network200);
                                continue;
                            }
                            Ok(response) => {
                                let diagnostic = format!(
                                    "cached current index was invalid ({cached_error}) and unconditional recovery returned HTTP {}",
                                    response.status,
                                );
                                self.push_current_diagnostic(
                                    endpoint.clone(),
                                    representation,
                                    Some(response.status),
                                    diagnostic.clone(),
                                );
                                failures.push(diagnostic);
                            }
                            Err(fetch_error) => {
                                let diagnostic = format!(
                                    "cached current index was invalid ({cached_error}) and unconditional recovery failed: {fetch_error}"
                                );
                                self.push_current_diagnostic(
                                    endpoint.clone(),
                                    representation,
                                    None,
                                    diagnostic.clone(),
                                );
                                failures.push(diagnostic);
                            }
                        }
                        break;
                    }
                    Err(error) => {
                        self.push_current_diagnostic(
                            endpoint.clone(),
                            representation,
                            Some(200),
                            error.clone(),
                        );
                        failures.push(error);
                        saw_metadata_invalid = true;
                        break;
                    }
                };
                let mut body = Some(body);
                let source = body
                    .as_ref()
                    .expect("validated current body")
                    .source(representation, &endpoint);
                if let (Some(cache), Some(key), Some(CurrentBodyOrigin::Network200)) =
                    (&self.raw_cache, &cache_key, origin)
                {
                    let body = body.take().expect("validated current body");
                    cache
                        .publish(
                            key,
                            RawCacheWrite {
                                status: 200,
                                body: body.body,
                                observed_at: body.observed_at_timestamp,
                                validated_at: body.observed_at_timestamp,
                                etag: body.etag,
                                last_modified: body.last_modified,
                                cache_control: body.cache_control,
                            },
                        )
                        .map_err(Self::cache_error)?;
                } else if let (Some(cache), Some(key), Some(CurrentBodyOrigin::Revalidated304)) =
                    (&self.raw_cache, &cache_key, origin)
                {
                    let body = body.as_ref().expect("validated current body");
                    let headers = TransportResponseHeaders {
                        etag: body.etag.clone(),
                        last_modified: body.last_modified.clone(),
                        cache_control: body.cache_control.clone(),
                    };
                    let validated_at = self.now();
                    cache
                        .update_validated_at_with_headers(key, validated_at, &headers)
                        .map_err(Self::cache_error)?;
                }
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
                    endpoint: endpoint.clone().into(),
                    status: Some(
                        if matches!(origin, Some(CurrentBodyOrigin::Revalidated304)) {
                            304
                        } else {
                            200
                        },
                    ),
                    status_detail: CranFastPathStatus::Available,
                    source: CranRefreshSource::CurrentIndex(representation),
                });
                let catalog = Rc::new(catalog);
                self.current = Some(Ok(Rc::clone(&catalog)));
                return Ok(catalog);
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
        let endpoint = format!("{}/src/contrib/Meta/archive.rds", self.base_url);
        let result = match self.acquire_metadata(
            &endpoint,
            RawCacheRepresentation::ArchiveHistoryRds,
            "cran-archive-history",
            "rds",
            |body| {
                enumerate_archive_rds_for_provider(body)
                    .map_err(|error| MetadataParseFailure::Invalid(error.to_string().into()))
            },
        ) {
            Ok((entries, _source, _outcome)) => Ok(HistorySource::Available(Rc::from(
                entries.into_boxed_slice(),
            ))),
            Err(error) if matches!(error.status, Some(404 | 410)) => {
                let status = error.status.expect("matched status");
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail: CranFastPathStatus::Absent { status },
                    source: CranRefreshSource::ArchiveHistory,
                });
                Ok(HistorySource::Absent)
            }
            Err(error) => {
                let diagnostic = if error.category == CandidateLoadErrorCategory::MetadataInvalid {
                    format!("invalid CRAN archive history: {}", error.diagnostic)
                } else {
                    error.diagnostic.into_string()
                };
                self.push_history_diagnostic(endpoint.clone(), error.status, diagnostic.clone());
                let message = match error.category {
                    CandidateLoadErrorCategory::MetadataInvalid
                    | CandidateLoadErrorCategory::SnapshotInvalid => {
                        format!("failed to refresh {endpoint}: {diagnostic}")
                    }
                    _ => match error.status {
                        Some(status) => format!("failed to refresh {endpoint}: HTTP {status}"),
                        None => format!("failed to refresh {endpoint}: {diagnostic}"),
                    },
                };
                Err(CandidateLoadError::new(error.category, message))
            }
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
        let fast_result = match self.acquire_metadata(
            &endpoint,
            RawCacheRepresentation::PackageArchiveIndexRds,
            "cran-archive-index",
            "rds",
            |body| {
                let projection = provider_archive_index_rds(body, package).map_err(|error| {
                    let diagnostic = error.to_string().into_boxed_str();
                    match error {
                        CranArchiveIndexProviderError::AllSemantic(_)
                        | CranArchiveIndexProviderError::Identity(_) => {
                            MetadataParseFailure::NoFallback(diagnostic)
                        }
                        _ => MetadataParseFailure::Invalid(diagnostic),
                    }
                })?;
                Ok((
                    projection.catalog,
                    projection.observations,
                    projection.rejections,
                ))
            },
        ) {
            Ok(((catalog, records, rejections), source, outcome)) => {
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
                self.evidence
                    .borrow_mut()
                    .extend(rejections.iter().map(|rejection| {
                        archive_rejection_to_evidence(
                            rejection,
                            source.clone(),
                            &self.base_url,
                            FreshnessStateV1::BulkGeneration,
                        )
                    }));
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(match outcome {
                        MetadataAcquisitionOutcome::Revalidated304 => 304,
                        MetadataAcquisitionOutcome::Cached
                        | MetadataAcquisitionOutcome::Network200 => 200,
                    }),
                    status_detail: if rejections.is_empty() {
                        CranFastPathStatus::Available
                    } else {
                        CranFastPathStatus::AvailableWithRejections {
                            count: rejections.len(),
                            diagnostic: {
                                let first = rejections
                                    .first()
                                    .map(|rejection| rejection.diagnostic().to_string())
                                    .unwrap_or_else(|| "no rejection detail".to_owned());
                                let additional = rejections.len().saturating_sub(1);
                                format!(
                                    "{} archive release(s) quarantined after semantic validation; first: {first}; {additional} additional rejection(s)",
                                    rejections.len()
                                )
                                .into()
                            },
                        }
                    },
                    source: CranRefreshSource::ArchiveFastPath,
                });
                Ok(CandidateSource::Fast(catalog))
            }
            Err(error) if matches!(error.status, Some(404 | 410)) => {
                let status = error.status.expect("matched status");
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail: CranFastPathStatus::Unsupported { status },
                    source: CranRefreshSource::ArchiveFastPath,
                });
                Err(FastPathFailure::Unsupported)
            }
            Err(error) => {
                let diagnostic = match (error.category, error.status) {
                    (CandidateLoadErrorCategory::MetadataInvalid, _) => format!(
                        "archive fast path for {package} has invalid metadata: {}",
                        error.diagnostic
                    ),
                    (CandidateLoadErrorCategory::TransportFailure, Some(status)) => {
                        format!("archive fast path for {package} returned unexpected HTTP {status}")
                    }
                    _ => format!(
                        "archive fast path for {package} failed: {}",
                        error.diagnostic
                    ),
                };
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: error.status,
                    status_detail: CranFastPathStatus::Invalid {
                        status: error.status.unwrap_or_default(),
                        diagnostic: diagnostic.clone().into_boxed_str(),
                    },
                    source: CranRefreshSource::ArchiveFastPath,
                });
                if !error.fallback_allowed
                    || error.category == CandidateLoadErrorCategory::SnapshotInvalid
                {
                    self.diagnostics.extend(package_diagnostics);
                    return Err(error.into_candidate());
                }
                Err(FastPathFailure::Invalid {
                    category: error.category,
                    diagnostic: diagnostic.into_boxed_str(),
                })
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
