//! CRAN archive refresh and lazy DESCRIPTION fallback.

use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(test)]
use std::error::Error;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use self::raw_cache::{
    RawCache, RawCacheEntry, RawCacheLookup, RawCacheRepresentation, RawCacheWrite,
};
#[cfg(test)]
use super::archive_index::provider_rds_read_options;
use super::archive_index::{CranArchiveIndexProviderError, provider_archive_index_rds};
use super::catalog::{CranArchiveReleaseRejection, CranCatalog, CranCatalogObservation};
use super::evidence::CranEvidenceObservation;
#[cfg(test)]
use super::history::CranHistoryError;
use super::history::{ArchiveEntry, ArchiveHistoryRejection, enumerate_archive_rds_for_provider};
use crate::SnapshotStore;
use crate::snapshot::FreshnessStateV1;
use crate::snapshot::ReadOnlySnapshotCandidateLoader;
use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoadResult, CandidateLoader,
    PackageName, PackageRelease, QuarantinedCandidate, ReleaseAggregation, SolverKey,
};

// Raw-response/cache integration consumes this provider-private policy seam
// without coupling semantic snapshot inspection to response headers.
mod allpackages;
pub mod cache_policy;
mod negative;
mod qualification;
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
use refresher::extract_description;
pub use refresher::{CranSnapshotRefresher, CranSnapshotRefresherError};
#[cfg(test)]
pub(crate) use snapshot::refresh_and_publish_with_transport;
use snapshot::{
    allpackages_record_to_evidence, archive_rejection_to_evidence, import_current_index,
    index_record_to_evidence, source_input, tarball_record_to_evidence,
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
    AllPackages,
    CurrentIndex(CranCurrentIndexRepresentation),
}

/// The default period for which a compatible CRAN generation can be reused
/// online when the server has not supplied a stronger freshness policy.
pub const CRAN_COMPATIBILITY_PROFILE: u32 = 1;
pub const CRAN_PARSER_SCHEMA: u32 = 1;
pub const CRAN_NORMALIZATION_POLICY: u32 = 2;
pub const DEFAULT_COMPATIBLE_GENERATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The bulk historical feed is an independently configured observation
/// source. It is not derived from the configured repository URL.
pub const DEFAULT_ALLPACKAGES_FEED_ENDPOINT: &str = "https://ppm.r-pkg.org/ALLPACKAGES.zst";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CranMetadataConfig {
    pub repository_endpoint: Box<str>,
    pub allpackages_feed_endpoint: Box<str>,
    pub refresh_metadata: bool,
    /// ALLPACKAGES historical rows have no CRAN publication date. They are
    /// valid only for resolutions without a publication cutoff.
    pub allow_allpackages_history: bool,
}

impl CranMetadataConfig {
    pub fn new(
        repository_endpoint: impl Into<Box<str>>,
        allpackages_feed_endpoint: impl Into<Box<str>>,
    ) -> Self {
        Self {
            repository_endpoint: repository_endpoint.into(),
            allpackages_feed_endpoint: allpackages_feed_endpoint.into(),
            refresh_metadata: false,
            allow_allpackages_history: true,
        }
    }

    pub fn for_repository(repository_endpoint: impl Into<Box<str>>) -> Self {
        Self::new(repository_endpoint, DEFAULT_ALLPACKAGES_FEED_ENDPOINT)
    }

    pub fn with_refresh_metadata(mut self) -> Self {
        self.refresh_metadata = true;
        self
    }

    /// Disable bulk historical candidates for a dated/publication-cutoff
    /// resolution. The package-local archive source carries dated evidence
    /// and remains authoritative for that policy.
    pub fn without_allpackages_history(mut self) -> Self {
        self.allow_allpackages_history = false;
        self
    }
}

/// Clock and compatibility policy used by the CRAN snapshot reuse boundary.
/// Supplying an explicit timestamp keeps this decision deterministic in tests
/// and leaves room for HTTP cache policy to take precedence later.
#[derive(Clone, Debug)]
pub struct CranSnapshotCachePolicy {
    pub now: jiff::Timestamp,
    pub compatibility_profile: u32,
    pub parser_schema: u32,
    pub normalization_policy: u32,
    pub expected_endpoint: Option<Box<str>>,
    /// The exact provider-private auxiliary feed permitted alongside the
    /// configured repository endpoint. This is deliberately opt-in rather
    /// than a generic second provenance root.
    pub allowed_auxiliary_endpoint: Option<Box<str>>,
    pub refresh_metadata: bool,
}

impl CranSnapshotCachePolicy {
    pub fn at(now: jiff::Timestamp) -> Self {
        Self {
            now,
            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
            parser_schema: CRAN_PARSER_SCHEMA,
            normalization_policy: CRAN_NORMALIZATION_POLICY,
            expected_endpoint: None,
            allowed_auxiliary_endpoint: None,
            refresh_metadata: false,
        }
    }

    pub fn with_expected_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.expected_endpoint = Some(endpoint.as_ref().trim_end_matches('/').to_owned().into());
        self
    }

    pub fn with_allowed_auxiliary_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        let endpoint = endpoint
            .as_ref()
            .trim_end_matches('/')
            .to_owned()
            .into_boxed_str();
        self.allowed_auxiliary_endpoint = Some(endpoint);
        self
    }

    pub fn with_refresh_metadata(mut self) -> Self {
        self.refresh_metadata = true;
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
    });
    let validation_timestamp = validation
        .clone()
        .filter(|_| validation_matches)
        .and_then(|record| record.validated_at.parse::<jiff::Timestamp>().ok());
    let endpoint_provenance_matches = policy.expected_endpoint.as_deref().is_none_or(|expected| {
        let source_allowed = |endpoint: &str| {
            endpoint_belongs_to(endpoint, expected)
                || policy
                    .allowed_auxiliary_endpoint
                    .as_deref()
                    .is_some_and(|allowed| endpoint == allowed)
        };
        if validation_matches {
            validation.as_ref().is_some_and(|record| {
                record.effective_endpoint == expected
                    && record
                        .sources
                        .iter()
                        .all(|source| source_allowed(&source.endpoint))
            })
        } else {
            header
                .sources
                .iter()
                .all(|source| source_allowed(&source.endpoint))
        }
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
    let fresh = !policy.refresh_metadata
        && endpoint_provenance_matches
        && !future_source
        && oldest_source_age
            <= i64::try_from(DEFAULT_COMPATIBLE_GENERATION_TTL.as_secs()).unwrap_or(i64::MAX);
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
    Fast {
        catalog: CranCatalog,
        rejections: Rc<[CranArchiveReleaseRejection]>,
    },
    Fallback {
        entries: Rc<[ArchiveEntry]>,
        rejections: Rc<[ArchiveHistoryRejection]>,
    },
}

/// A refreshed CRAN candidate source.
pub(crate) struct CranProvider<T> {
    package: PackageName,
    transport: RefCell<T>,
    base_url: Box<str>,
    source: CandidateSource,
    diagnostics: Vec<CranRefreshDiagnostic>,
    loaded: RefCell<Option<Result<CandidateLoadResult, CandidateLoadError>>>,
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
                    CandidateSource::Fast {
                        catalog,
                        rejections: Rc::from(Vec::new().into_boxed_slice()),
                    }
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
        let projection = enumerate_archive_rds_for_provider(&response.body)
            .map_err(CranProviderError::History)?;
        Ok(CandidateSource::Fallback {
            entries: Rc::from(projection.entries.into_boxed_slice()),
            rejections: Rc::from(projection.rejections.into_boxed_slice()),
        })
    }

    fn load_fallback(
        &self,
        entries: &[ArchiveEntry],
        rejections: &[ArchiveHistoryRejection],
    ) -> Result<CandidateLoadResult, CandidateLoadError> {
        let package_rejections = rejections
            .iter()
            .filter(|rejection| rejection.package_hint() == &self.package)
            .collect::<Vec<_>>();
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
        let quarantined = package_rejections
            .iter()
            .filter_map(|rejection| {
                rejection.version().map(|version| {
                    QuarantinedCandidate::new(version.clone(), rejection.diagnostic())
                })
            })
            .collect::<Vec<_>>();
        if releases.is_empty() && !package_rejections.is_empty() && quarantined.is_empty() {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                format!(
                    "CRAN archive history has no usable releases for {} after quarantining: {}",
                    self.package,
                    package_rejections
                        .iter()
                        .map(|rejection| rejection.diagnostic())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
        }
        Ok(CandidateLoadResult::new(releases, quarantined))
    }
}

impl<T: Transport> CandidateLoader for CranProvider<T> {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let result = self.load(package)?;
        if result.candidates().is_empty() && !result.quarantined().is_empty() {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                format!("CRAN archive history has no eligible releases for {package:?}"),
            ));
        }
        Ok(result.into_parts().0)
    }

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN provider has no candidates for {package:?}"),
            ));
        };
        if name != &self.package {
            return Ok(CandidateLoadResult::new(Vec::new(), Vec::new()));
        }
        if let Some(result) = self.loaded.borrow().as_ref() {
            return result.clone();
        }
        let result = match &self.source {
            CandidateSource::Fast {
                catalog,
                rejections,
            } => {
                let candidates = catalog.candidates(&self.package).to_vec();
                let quarantined = rejections
                    .iter()
                    .filter_map(|rejection| {
                        rejection.version().map(|version| {
                            QuarantinedCandidate::new(
                                version.clone(),
                                rejection.diagnostic().to_string(),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                if candidates.is_empty() && !rejections.is_empty() && quarantined.is_empty() {
                    Err(CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        format!(
                            "CRAN archive index has no usable releases for {} after quarantining: {}",
                            self.package,
                            rejections
                                .iter()
                                .map(|rejection| rejection.diagnostic().to_string())
                                .collect::<Vec<_>>()
                                .join("; ")
                        ),
                    ))
                } else {
                    Ok(CandidateLoadResult::new(candidates, quarantined))
                }
            }
            CandidateSource::Fallback {
                entries,
                rejections,
            } => self.load_fallback(entries, rejections),
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

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
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
            CachedProvider::Ready(provider) => provider.load(package),
            CachedProvider::Failed(error) => Err(error.clone()),
        }
    }
}

/// A transport-free, process-local view handed to the resolver after refresh.
#[derive(Clone, Debug, Default)]
pub struct CranCandidateSnapshot {
    candidates: HashMap<PackageName, Vec<PackageRelease>>,
    quarantined: HashMap<PackageName, Vec<QuarantinedCandidate>>,
}

impl CandidateLoader for CranCandidateSnapshot {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let result = self.load(package)?;
        if result.candidates().is_empty() && !result.quarantined().is_empty() {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                format!("CRAN snapshot has no eligible releases for {package:?}"),
            ));
        }
        Ok(result.into_parts().0)
    }

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot has no candidates for {package:?}"),
            ));
        };
        let candidates = self.candidates.get(name).cloned().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot has not refreshed package {name}"),
            )
        })?;
        Ok(CandidateLoadResult::new(
            candidates,
            self.quarantined.get(name).cloned().unwrap_or_default(),
        ))
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
            quarantined: HashMap::new(),
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
    allpackages_feed_endpoint: Box<str>,
    refresh_metadata: bool,
    allow_allpackages_history: bool,
    transport: Rc<T>,
    raw_cache: Option<RawCache>,
    test_now: Option<jiff::Timestamp>,
    current: Option<Result<Rc<CranCatalog>, CandidateLoadError>>,
    current_surface_digest: Option<Box<str>>,
    history: Option<Result<HistorySource, CandidateLoadError>>,
    history_surface_digest: Option<Box<str>>,
    allpackages: Option<Result<Rc<AllPackagesSource>, CandidateLoadError>>,
    packages: HashMap<PackageName, Result<CandidateLoadResult, CandidateLoadError>>,
    diagnostics: Vec<CranRefreshDiagnostic>,
    evidence: Rc<RefCell<Vec<CranEvidenceObservation>>>,
}

#[derive(Clone)]
struct AllPackagesSource {
    projection: Rc<allpackages::IndexedProjection>,
    source: crate::snapshot::SourceInput,
}

struct BulkCandidateResult {
    candidates: CandidateLoadResult,
    evidence: Vec<CranEvidenceObservation>,
}

fn catalog_surface_digest(catalog: &CranCatalog) -> Box<str> {
    let mut digest = Sha256::new();
    for (package, releases) in catalog.packages() {
        digest.update(package.as_str().as_bytes());
        digest.update([0]);
        for release in releases {
            digest.update(release.version().to_string().as_bytes());
            digest.update([0]);
            digest.update(release.metadata_digest().to_string().as_bytes());
            digest.update([0]);
        }
    }
    hex_digest(digest.finalize())
}

fn history_surface_digest(entries: &[ArchiveEntry]) -> Box<str> {
    let mut rows = entries
        .iter()
        .map(|entry| {
            format!(
                "{}\0{}\0{}\0{}\0{}",
                entry.package(),
                entry.version(),
                entry.source_archive_relative_path(),
                entry.size(),
                entry.mtime()
            )
        })
        .collect::<Vec<_>>();
    rows.sort();
    let mut digest = Sha256::new();
    for row in rows {
        digest.update(row.as_bytes());
        digest.update([0]);
    }
    hex_digest(digest.finalize())
}

fn hex_digest(digest: impl AsRef<[u8]>) -> Box<str> {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into_boxed_str()
}

#[derive(Clone)]
enum HistorySource {
    Available {
        entries: Rc<[ArchiveEntry]>,
        rejections: Rc<[ArchiveHistoryRejection]>,
    },
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
    retry_after: Option<Box<str>>,
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
            retry_after: None,
            category: CandidateLoadErrorCategory::SnapshotInvalid,
            diagnostic: format!("CRAN metadata raw cache is invalid: {error}").into(),
            fallback_allowed: false,
        }
    }

    fn response(status: u16, diagnostic: impl Into<Box<str>>, retry_after: Option<&str>) -> Self {
        Self {
            status: Some(status),
            retry_after: retry_after.map(Into::into),
            category: CandidateLoadErrorCategory::TransportFailure,
            diagnostic: diagnostic.into(),
            fallback_allowed: true,
        }
    }

    fn transport(error: impl std::fmt::Display) -> Self {
        Self {
            status: None,
            retry_after: None,
            category: CandidateLoadErrorCategory::TransportFailure,
            diagnostic: format!("transport failure: {error}").into(),
            fallback_allowed: true,
        }
    }

    fn invalid(status: Option<u16>, diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            status,
            retry_after: None,
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
    fn new(transport: Rc<T>, config: CranMetadataConfig) -> Self {
        Self::new_with_clock(transport, config, None, None)
    }

    fn new_with_clock(
        transport: Rc<T>,
        config: CranMetadataConfig,
        test_now: Option<jiff::Timestamp>,
        raw_cache: Option<RawCache>,
    ) -> Self {
        Self {
            base_url: config.repository_endpoint.trim_end_matches('/').into(),
            allpackages_feed_endpoint: config
                .allpackages_feed_endpoint
                .trim_end_matches('/')
                .into(),
            refresh_metadata: config.refresh_metadata,
            allow_allpackages_history: config.allow_allpackages_history,
            transport,
            raw_cache,
            test_now,
            current: None,
            current_surface_digest: None,
            history: None,
            history_surface_digest: None,
            allpackages: None,
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
        import_current_index(representation, body)
    }

    fn acquire_metadata<V, P>(
        &self,
        endpoint: &str,
        representation: RawCacheRepresentation,
        source_kind: &str,
        source_representation: &str,
        mut parse: P,
    ) -> Result<
        (V, crate::snapshot::SourceInput, MetadataAcquisitionOutcome),
        MetadataAcquisitionFailure,
    >
    where
        P: FnMut(&[u8]) -> Result<V, MetadataParseFailure>,
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
                    if !self.refresh_metadata
                        && permits_reuse(self.now(), entry.validated_at, policy)
                    {
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
                                    response.headers.retry_after.as_deref(),
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
                        response.headers.retry_after.as_deref(),
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
                            retry_after: None,
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
                        if !self.refresh_metadata
                            && permits_reuse(self.now(), entry.validated_at, policy)
                        {
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
                        retry_after: None,
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
                self.current_surface_digest = Some(catalog_surface_digest(&catalog));
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
            Ok((projection, _source, _outcome)) => {
                if !projection.rejections.is_empty() {
                    let first = projection
                        .rejections
                        .first()
                        .map(ArchiveHistoryRejection::diagnostic)
                        .unwrap_or_else(|| "no rejection detail".to_owned());
                    let additional = projection.rejections.len().saturating_sub(1);
                    self.push_history_diagnostic(
                        endpoint.clone(),
                        Some(200),
                        format!(
                            "archive history quarantined {} package-local release(s); first: {first}; {additional} additional rejection(s)",
                            projection.rejections.len()
                        ),
                    );
                }
                let entries: Rc<[ArchiveEntry]> = Rc::from(projection.entries.into_boxed_slice());
                self.history_surface_digest = Some(history_surface_digest(&entries));
                Ok(HistorySource::Available {
                    entries,
                    rejections: Rc::from(projection.rejections.into_boxed_slice()),
                })
            }
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

    fn push_allpackages_diagnostic(&mut self, status: Option<u16>, diagnostic: String) {
        self.diagnostics.push(CranRefreshDiagnostic {
            endpoint: self.allpackages_feed_endpoint.clone(),
            status,
            status_detail: CranFastPathStatus::Invalid {
                status: status.unwrap_or_default(),
                diagnostic: diagnostic.into_boxed_str(),
            },
            source: CranRefreshSource::AllPackages,
        });
    }

    /// Acquire the independently configured bulk observation feed. Its rows
    /// remain observations until they are bound to the target repository's
    /// current/archive surface.
    fn ensure_allpackages(&mut self) -> Result<Rc<AllPackagesSource>, CandidateLoadError> {
        if let Some(result) = &self.allpackages {
            return result.clone();
        }
        if self.raw_cache.is_none() {
            let error = CandidateLoadError::new(
                CandidateLoadErrorCategory::TransportFailure,
                "ALLPACKAGES projection cache is not prepared",
            );
            self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
            self.allpackages = Some(Err(error.clone()));
            return Err(error);
        }
        if self.allpackages_feed_endpoint.is_empty() {
            let error = CandidateLoadError::new(
                CandidateLoadErrorCategory::TransportFailure,
                "ALLPACKAGES feed endpoint is not configured",
            );
            self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
            self.allpackages = Some(Err(error.clone()));
            return Err(error);
        }
        let current_catalog = self.ensure_current()?;
        self.ensure_history()?;
        let endpoint = self.allpackages_feed_endpoint.to_string();
        let qualification_path = self.raw_cache.as_ref().map(RawCache::qualification_path);
        let current_digest = self.current_surface_digest.clone().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                "current surface digest is unavailable for ALLPACKAGES qualification",
            )
        })?;
        let archive_digest = self.history_surface_digest.clone().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                "archive surface digest is unavailable for ALLPACKAGES qualification",
            )
        })?;
        let persisted_qualification = match qualification_path.as_deref() {
            Some(path) => match qualification::load_result(path) {
                Ok(record) => record,
                Err(error) => {
                    let diagnostic = format!("invalid ALLPACKAGES qualification: {error}");
                    self.push_allpackages_diagnostic(None, diagnostic.clone());
                    if let Err(remove_error) = std::fs::remove_file(path) {
                        let error = CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!(
                                "{diagnostic}; unable to remove invalid qualification: {remove_error}"
                            ),
                        );
                        self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
                        self.allpackages = Some(Err(error.clone()));
                        return Err(error);
                    }
                    None
                }
            },
            None => None,
        };
        if let Some(record) = persisted_qualification.as_ref()
            && qualification::matches(
                record,
                &self.base_url,
                &endpoint,
                &current_digest,
                &archive_digest,
                None,
            )
            && !self.refresh_metadata
            && record.status != qualification::Status::Positive
            && record
                .next_probe_at
                .as_deref()
                .and_then(|value| value.parse::<jiff::Timestamp>().ok())
                .is_some_and(|next| self.now() < next)
        {
            let error = CandidateLoadError::new(
                CandidateLoadErrorCategory::TransportFailure,
                format!(
                    "ALLPACKAGES qualification is {:?} until {}",
                    record.status,
                    record.next_probe_at.as_deref().unwrap_or("unknown")
                ),
            );
            self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
            self.allpackages = Some(Err(error.clone()));
            return Err(error);
        }
        let projection_cache = self.raw_cache.as_ref();
        let result = match self.acquire_metadata(
            &endpoint,
            RawCacheRepresentation::AllPackagesZstd,
            "cran-allpackages",
            "zstd",
            |body| {
                let projection_path = projection_cache.and_then(|cache| {
                    cache
                        .key(&endpoint, RawCacheRepresentation::AllPackagesZstd)
                        .ok()
                        .map(|key| cache.projection_path(&key, body))
                });
                let Some(path) = projection_path.as_deref() else {
                    return Err(MetadataParseFailure::Invalid(
                        "ALLPACKAGES projection cache is unavailable".into(),
                    ));
                };
                match allpackages::load_or_build_projection(body, path) {
                    Ok(projection) => Ok(projection),
                    Err(error) => {
                        // Keep this refresh fail-closed, but remove only the
                        // content-addressed derived file so the next refresh
                        // can safely rebuild it from the validated raw body.
                        let _ = std::fs::remove_file(path);
                        Err(MetadataParseFailure::NoFallback(error.into()))
                    }
                }
            },
        ) {
            Ok((projection, source, outcome)) => {
                let feed_digest = hex_digest(source.content_sha256).to_string();
                let coverage = projection
                    .classify_current(&current_catalog)
                    .map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("invalid ALLPACKAGES coverage projection: {error}"),
                        )
                    })?;
                let (mirror_positive, canonical_current_digest, canonical_archive_digest) =
                    if self.base_url.as_ref() == "https://cloud.r-project.org" {
                        // The built-in anchor is immutable by construction;
                        // avoid re-fetching it solely to qualify itself.
                        (true, current_digest.clone(), archive_digest.clone())
                    } else if let Some(record) = qualification_path
                        .as_deref()
                        .and_then(qualification::load)
                        .filter(|record| {
                            !self.refresh_metadata
                                && qualification::matches(
                                    record,
                                    &self.base_url,
                                    &endpoint,
                                    &current_digest,
                                    &archive_digest,
                                    Some(&feed_digest),
                                )
                                && record.status == qualification::Status::Positive
                                && qualification::positive_reusable(record, self.now())
                        })
                    {
                        (
                            true,
                            record.canonical_current_digest.into(),
                            record.canonical_archive_digest.into(),
                        )
                    } else {
                        self.custom_surface_matches_canonical()?
                    };
                if !mirror_positive {
                    if let Some(path) = qualification_path.as_deref() {
                        let previous = qualification::load(path);
                        let failure_count =
                            previous.map_or(1, |record| record.failure_count.saturating_add(1));
                        qualification::publish(
                            path,
                            &qualification::Record {
                                version: 1,
                                repository_endpoint: self.base_url.to_string(),
                                feed_endpoint: endpoint.clone(),
                                current_digest: current_digest.to_string(),
                                archive_digest: archive_digest.to_string(),
                                feed_digest: feed_digest.clone(),
                                feed_etag: source.etag.clone(),
                                feed_last_modified: source.last_modified.clone(),
                                canonical_current_digest: canonical_current_digest.to_string(),
                                canonical_archive_digest: canonical_archive_digest.to_string(),
                                coverage_status: coverage.status,
                                covered_count: coverage.covered_count,
                                gapped_count: coverage.gapped_count,
                                conflicting_count: coverage.conflicting_count,
                                coverage_digest: coverage.digest.clone(),
                                compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
                                parser_schema: CRAN_PARSER_SCHEMA,
                                normalization_policy: CRAN_NORMALIZATION_POLICY,
                                status: qualification::Status::Negative,
                                diagnostic:
                                    "configured repository does not match canonical CRAN surface"
                                        .into(),
                                failure_count,
                                next_probe_at: Some(qualification::failure_probe_at(
                                    self.now(),
                                    failure_count,
                                    None,
                                    fastrand::u64(..),
                                )),
                                validated_at: self.now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
                                ..qualification::Record::default()
                            },
                        )
                        .map_err(|error| {
                            CandidateLoadError::new(
                                CandidateLoadErrorCategory::SnapshotInvalid,
                                format!("unable to persist ALLPACKAGES qualification: {error}"),
                            )
                        })?;
                    }
                    let error = CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        "configured CRAN endpoint does not match canonical CRAN surface",
                    );
                    self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
                    return Err(error);
                }
                let validated_at = qualification_path
                    .as_deref()
                    .and_then(qualification::load)
                    .filter(|record| {
                        !self.refresh_metadata
                            && record.status == qualification::Status::Positive
                            && qualification::matches(
                                record,
                                &self.base_url,
                                &endpoint,
                                &current_digest,
                                &archive_digest,
                                Some(&feed_digest),
                            )
                            && qualification::positive_reusable(record, self.now())
                    })
                    .map(|record| record.validated_at)
                    .unwrap_or_else(|| self.now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string());
                if let Some(path) = qualification_path.as_deref() {
                    qualification::publish(
                        path,
                        &qualification::Record {
                            version: 1,
                            repository_endpoint: self.base_url.to_string(),
                            feed_endpoint: endpoint.clone(),
                            current_digest: current_digest.to_string(),
                            archive_digest: archive_digest.to_string(),
                            feed_digest: feed_digest.clone(),
                            feed_etag: source.etag.clone(),
                            feed_last_modified: source.last_modified.clone(),
                            canonical_current_digest: canonical_current_digest.to_string(),
                            canonical_archive_digest: canonical_archive_digest.to_string(),
                            coverage_status: coverage.status,
                            covered_count: coverage.covered_count,
                            gapped_count: coverage.gapped_count,
                            conflicting_count: coverage.conflicting_count,
                            coverage_digest: coverage.digest.clone(),
                            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
                            parser_schema: CRAN_PARSER_SCHEMA,
                            normalization_policy: CRAN_NORMALIZATION_POLICY,
                            status: qualification::Status::Positive,
                            diagnostic: "repository surface qualified as CRAN mirror".into(),
                            failure_count: 0,
                            next_probe_at: None,
                            validated_at,
                            ..qualification::Record::default()
                        },
                    )
                    .map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("unable to persist ALLPACKAGES qualification: {error}"),
                        )
                    })?;
                }
                let status = match outcome {
                    MetadataAcquisitionOutcome::Revalidated304 => 304,
                    MetadataAcquisitionOutcome::Cached | MetadataAcquisitionOutcome::Network200 => {
                        200
                    }
                };
                let detail = CranFastPathStatus::Available;
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail: detail,
                    source: CranRefreshSource::AllPackages,
                });
                Ok(Rc::new(AllPackagesSource {
                    projection: Rc::new(projection),
                    source,
                }))
            }
            Err(error) if matches!(error.status, Some(404 | 410)) => {
                let status = error.status.expect("matched status");
                if let Some(path) = qualification_path.as_deref() {
                    let failure_count = qualification::load(path)
                        .map_or(1, |record| record.failure_count.saturating_add(1));
                    qualification::publish(
                        path,
                        &qualification::Record {
                            version: 1,
                            repository_endpoint: self.base_url.to_string(),
                            feed_endpoint: endpoint.clone(),
                            current_digest: current_digest.to_string(),
                            archive_digest: archive_digest.to_string(),
                            feed_digest: String::new(),
                            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
                            parser_schema: CRAN_PARSER_SCHEMA,
                            normalization_policy: CRAN_NORMALIZATION_POLICY,
                            status: qualification::Status::Negative,
                            diagnostic: error.diagnostic.to_string(),
                            failure_count,
                            next_probe_at: Some(qualification::failure_probe_at(
                                self.now(),
                                failure_count,
                                error.retry_after.as_deref(),
                                fastrand::u64(..),
                            )),
                            validated_at: self.now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
                            ..qualification::Record::default()
                        },
                    )
                    .map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("unable to persist ALLPACKAGES qualification: {error}"),
                        )
                    })?;
                }
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail: CranFastPathStatus::Unsupported { status },
                    source: CranRefreshSource::AllPackages,
                });
                Err(error.into_candidate())
            }
            Err(error) => {
                if let Some(path) = qualification_path.as_deref() {
                    let previous = qualification::load(path);
                    let failure_count =
                        previous.map_or(1, |record| record.failure_count.saturating_add(1));
                    let status = if matches!(error.status, Some(404 | 410)) {
                        qualification::Status::Negative
                    } else {
                        qualification::Status::Unknown
                    };
                    qualification::publish(
                        path,
                        &qualification::Record {
                            version: 1,
                            repository_endpoint: self.base_url.to_string(),
                            feed_endpoint: endpoint.clone(),
                            current_digest: current_digest.to_string(),
                            archive_digest: archive_digest.to_string(),
                            feed_digest: String::new(),
                            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
                            parser_schema: CRAN_PARSER_SCHEMA,
                            normalization_policy: CRAN_NORMALIZATION_POLICY,
                            status,
                            diagnostic: error.diagnostic.to_string(),
                            failure_count,
                            next_probe_at: Some(qualification::failure_probe_at(
                                self.now(),
                                failure_count,
                                error.retry_after.as_deref(),
                                fastrand::u64(..),
                            )),
                            validated_at: self.now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
                            ..qualification::Record::default()
                        },
                    )
                    .map_err(|persist_error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("unable to persist ALLPACKAGES qualification: {persist_error}"),
                        )
                    })?;
                }
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: error.status,
                    status_detail: CranFastPathStatus::Invalid {
                        status: error.status.unwrap_or_default(),
                        diagnostic: error.diagnostic.clone(),
                    },
                    source: CranRefreshSource::AllPackages,
                });
                Err(error.into_candidate())
            }
        };
        self.allpackages = Some(result.clone());
        result
    }

    fn custom_surface_matches_canonical(
        &mut self,
    ) -> Result<(bool, Box<str>, Box<str>), CandidateLoadError> {
        let current_endpoint = "https://cloud.r-project.org/src/contrib/PACKAGES.rds";
        let (canonical_current, _, _) = self
            .acquire_metadata(
                current_endpoint,
                RawCacheRepresentation::CurrentRds,
                "cran-canonical-current",
                "rds",
                |body| {
                    Self::parse_current_body(CranCurrentIndexRepresentation::Rds, body)
                        .map(|(catalog, _)| catalog)
                        .map_err(|error| MetadataParseFailure::Invalid(error.into()))
                },
            )
            .map_err(MetadataAcquisitionFailure::into_candidate)?;
        let history_endpoint = "https://cloud.r-project.org/src/contrib/Meta/archive.rds";
        let (canonical_history, _, _) = self
            .acquire_metadata(
                history_endpoint,
                RawCacheRepresentation::ArchiveHistoryRds,
                "cran-canonical-history",
                "rds",
                |body| {
                    enumerate_archive_rds_for_provider(body)
                        .map_err(|error| MetadataParseFailure::Invalid(error.to_string().into()))
                },
            )
            .map_err(MetadataAcquisitionFailure::into_candidate)?;
        let target_current = self.current_surface_digest.as_deref().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                "target current surface digest is unavailable",
            )
        })?;
        let target_history = self.history_surface_digest.as_deref().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                "target archive surface digest is unavailable",
            )
        })?;
        let canonical_current_digest = catalog_surface_digest(&canonical_current);
        let canonical_history_digest = history_surface_digest(&canonical_history.entries);
        Ok((
            target_current == canonical_current_digest.as_ref()
                && target_history == canonical_history_digest.as_ref(),
            canonical_current_digest,
            canonical_history_digest,
        ))
    }

    fn refresh_package(
        &mut self,
        package: &PackageName,
    ) -> Result<CandidateLoadResult, CandidateLoadError> {
        if let Some(result) = self.packages.get(package) {
            return result.clone();
        }
        let result = self.refresh_package_uncached(package);
        self.packages.insert(package.clone(), result.clone());
        result
    }

    /// Projects the complete ALLPACKAGES history for one package.
    ///
    /// The result is deliberately package-granular: a single rejected or
    /// unbound archive identity makes the whole historical source fall back to
    /// the package-local archive. This prevents two presentations of one
    /// release from entering the same aggregation while retaining the current
    /// catalog as the sole authority for current identities.
    fn bulk_candidates_for_package(
        &mut self,
        package: &PackageName,
        current: &[PackageRelease],
        bulk: &AllPackagesSource,
    ) -> Result<Option<BulkCandidateResult>, CandidateLoadError> {
        let history = match self.ensure_history()? {
            HistorySource::Available {
                entries,
                rejections,
            } => {
                if rejections
                    .iter()
                    .any(|rejection| rejection.package_hint() == package)
                {
                    return Ok(None);
                }
                entries
            }
            HistorySource::Absent => return Ok(None),
        };
        let package_projection =
            bulk.projection
                .observations(package.as_str())
                .map_err(|error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::SnapshotInvalid,
                        format!("invalid ALLPACKAGES package projection for {package}: {error}"),
                    )
                })?;
        let package_rows = package_projection
            .observations
            .iter()
            .filter(|row| row.package() == package)
            .collect::<Vec<_>>();
        let package_rejections = package_projection
            .rejections
            .iter()
            .filter(|rejection| rejection.package() == Some(package))
            .collect::<Vec<_>>();
        let package_entries = history
            .iter()
            .filter(|entry| entry.package() == package)
            .collect::<Vec<_>>();
        let current_versions = current
            .iter()
            .map(|release| release.version())
            .collect::<std::collections::BTreeSet<_>>();

        // A rejection belongs to the package even when its version could not
        // be recovered. Treating it as a version-local hole would mix source
        // presentations and make the resulting history non-deterministic.
        if !package_rejections.is_empty() {
            return Ok(None);
        }

        let historical_entries = package_entries
            .iter()
            .copied()
            .filter(|entry| !current_versions.contains(entry.version()))
            .collect::<Vec<_>>();
        let historical_versions = historical_entries
            .iter()
            .map(|entry| entry.version())
            .collect::<std::collections::BTreeSet<_>>();

        // Rows for current identities are observations only; current metadata
        // always comes from the target current index. Any other feed identity
        // must have a corresponding archive occurrence, otherwise the feed is
        // incomplete for this package and the local history is authoritative.
        let historical_rows = package_rows
            .iter()
            .copied()
            .filter(|row| !current_versions.contains(row.release().version()))
            .collect::<Vec<_>>();
        let feed_versions = historical_rows
            .iter()
            .map(|row| row.release().version())
            .collect::<std::collections::BTreeSet<_>>();
        if feed_versions != historical_versions {
            return Ok(None);
        }

        let mut staged_releases = current.to_vec();
        let mut staged_evidence = Vec::new();
        for entry in &historical_entries {
            let rows = historical_rows
                .iter()
                .filter(|row| row.release().version() == entry.version())
                .copied()
                .collect::<Vec<_>>();
            let entry_count = historical_entries
                .iter()
                .filter(|other| other.version() == entry.version())
                .count();
            if entry_count != 1
                || rows.len() != 1
                || !allpackages::binds_archive_occurrence(rows[0], entry)
            {
                return Ok(None);
            }
            let row = rows[0];
            staged_releases.push(row.release().clone());
            let locator = format!(
                "{}/src/contrib/Archive/{}",
                self.base_url,
                entry.source_archive_relative_path()
            );
            staged_evidence.push(allpackages_record_to_evidence(
                row,
                bulk.source.clone(),
                locator,
                entry.size(),
            ));
        }

        let mut aggregation = ReleaseAggregation::new();
        for release in staged_releases {
            if aggregation.observe_release(release).is_err() {
                return Ok(None);
            }
        }
        let mut candidates = aggregation.releases().cloned().collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.version().cmp(right.version()));
        Ok(Some(BulkCandidateResult {
            candidates: CandidateLoadResult::new(candidates, Vec::new()),
            evidence: staged_evidence,
        }))
    }

    fn refresh_package_uncached(
        &mut self,
        package: &PackageName,
    ) -> Result<CandidateLoadResult, CandidateLoadError> {
        let current = self.ensure_current()?.candidates(package).to_vec();
        let bulk_candidates = if self.allow_allpackages_history {
            match self.ensure_allpackages() {
                Ok(bulk) => self.bulk_candidates_for_package(package, &current, &bulk)?,
                Err(_) => None,
            }
        } else {
            None
        };
        if let Some(result) = bulk_candidates {
            self.evidence.borrow_mut().extend(result.evidence);
            return Ok(result.candidates);
        }
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
                Ok(CandidateSource::Fast {
                    catalog,
                    rejections: Rc::from(rejections.into_boxed_slice()),
                })
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
                None => return Ok(CandidateLoadResult::new(current, Vec::new())),
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
        let archived = provider.load(&SolverKey::InstalledName(package.clone()))?;
        let current_versions = current
            .iter()
            .map(|release| release.version())
            .collect::<std::collections::BTreeSet<_>>();
        let mut aggregation = ReleaseAggregation::new();
        for release in &current {
            aggregation
                .observe_release(release.clone())
                .map_err(|error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        format!("conflicting CRAN release metadata for {package}: {error}"),
                    )
                })?;
        }
        for release in archived
            .candidates()
            .iter()
            .filter(|release| !current_versions.contains(release.version()))
        {
            aggregation
                .observe_release(release.clone())
                .map_err(|error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        format!("conflicting CRAN release metadata for {package}: {error}"),
                    )
                })?;
        }
        let mut candidates = aggregation.releases().cloned().collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.version().cmp(right.version()));
        Ok(CandidateLoadResult::new(
            candidates,
            archived.quarantined().to_vec(),
        ))
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
                        .map(|result| (package.clone(), result.candidates().to_vec()))
                })
                .collect(),
            quarantined: self
                .packages
                .iter()
                .filter_map(|(package, result)| {
                    result
                        .as_ref()
                        .ok()
                        .map(|result| (package.clone(), result.quarantined().to_vec()))
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
