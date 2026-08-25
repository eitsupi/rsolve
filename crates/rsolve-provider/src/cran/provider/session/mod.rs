use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use super::super::catalog::{CranCatalog, CranCatalogObservation};
use super::super::evidence::CranEvidenceObservation;
use super::super::history::{ArchiveEntry, ArchiveHistoryRejection};
use super::allpackages::IndexedProjection;
use super::cache_policy::CacheControlHeader;
use super::cache_policy::{cache_control_policy, permits_reuse};
use super::model::{
    CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA,
    CranCurrentIndexRepresentation, CranMetadataConfig, CranRefreshDiagnostic, CranRefreshProgress,
    CranRefreshProgressCallback, DEFAULT_COMPATIBLE_GENERATION_TTL,
};
use super::qualification;
use super::raw_cache::{RawCache, RawCacheEntry, RawCacheRepresentation};
use super::transport::{Transport, TransportResponse};
use super::{
    allpackages_record_to_evidence, archive_rejection_to_evidence, import_current_index,
    index_record_to_evidence, source_input_with_metadata,
};
use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoadResult, PackageName,
};

mod acquisition;
mod allpackages;
mod current;
mod history;
mod package;

/// A single refresh session. All network and parsing state is discarded from
/// the resolver-facing snapshot once refresh returns it.
pub(super) struct CranRefreshSession<T> {
    pub(in crate::cran::provider) base_url: Box<str>,
    pub(in crate::cran::provider) allpackages_feed_endpoint: Box<str>,
    pub(in crate::cran::provider) refresh_metadata: bool,
    pub(in crate::cran::provider) allow_allpackages_history: bool,
    transport: Rc<T>,
    progress: Option<CranRefreshProgressCallback>,
    raw_cache: Option<RawCache>,
    test_now: Option<jiff::Timestamp>,
    current: Option<Result<Rc<CranCatalog>, CandidateLoadError>>,
    current_surface_digest: Option<Box<str>>,
    history: Option<Result<HistorySource, CandidateLoadError>>,
    history_surface_digest: Option<Box<str>>,
    allpackages: Option<Result<Rc<AllPackagesSource>, CandidateLoadError>>,
    packages: HashMap<PackageName, Result<CandidateLoadResult, CandidateLoadError>>,
    package_local_fallback_reported: bool,
    pub(in crate::cran::provider) diagnostics: Vec<CranRefreshDiagnostic>,
    pub(in crate::cran::provider) evidence: Rc<RefCell<Vec<CranEvidenceObservation>>>,
}

#[derive(Clone)]
pub(super) struct AllPackagesSource {
    pub(super) projection: Rc<IndexedProjection>,
    pub(super) source: crate::snapshot::SourceInput,
    projection_path: std::path::PathBuf,
}

pub(super) struct BulkCandidateResult {
    pub(super) candidates: CandidateLoadResult,
    pub(super) evidence: Vec<CranEvidenceObservation>,
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
pub(super) enum HistorySource {
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
    cache_control: CacheControlHeader,
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
        source_input_with_metadata(
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
    #[cfg(test)]
    pub(in crate::cran::provider) fn new(transport: Rc<T>, config: CranMetadataConfig) -> Self {
        Self::new_with_progress(transport, config, None, None, None)
    }

    #[cfg(test)]
    pub(in crate::cran::provider) fn new_with_clock(
        transport: Rc<T>,
        config: CranMetadataConfig,
        test_now: Option<jiff::Timestamp>,
        raw_cache: Option<RawCache>,
    ) -> Self {
        Self::new_with_progress(transport, config, test_now, raw_cache, None)
    }

    pub(in crate::cran::provider) fn new_with_progress(
        transport: Rc<T>,
        config: CranMetadataConfig,
        test_now: Option<jiff::Timestamp>,
        raw_cache: Option<RawCache>,
        progress: Option<CranRefreshProgressCallback>,
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
            progress,
            raw_cache,
            test_now,
            current: None,
            current_surface_digest: None,
            history: None,
            history_surface_digest: None,
            allpackages: None,
            packages: HashMap::new(),
            package_local_fallback_reported: false,
            diagnostics: Vec::new(),
            evidence: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub(super) fn emit_progress(&self, event: CranRefreshProgress) {
        if let Some(progress) = &self.progress {
            progress(event);
        }
    }

    pub(super) fn emit_package_local_fallback(&mut self) {
        if !self.package_local_fallback_reported {
            self.package_local_fallback_reported = true;
            self.emit_progress(CranRefreshProgress::PackageLocalFallbackStarted);
        }
    }

    fn now(&self) -> jiff::Timestamp {
        self.test_now.unwrap_or_else(jiff::Timestamp::now)
    }

    pub(in crate::cran::provider) fn attach_raw_cache(&mut self, cache: RawCache) {
        self.raw_cache = Some(cache);
    }

    pub(super) fn previous_allpackages_projection_path(&self) -> Option<std::path::PathBuf> {
        let cache = self.raw_cache.as_ref()?;
        let record = qualification::load(&cache.qualification_path())?;
        // Only a positive record bound to this exact provider/feed may be
        // retained as the safe previous projection. Negative, unknown, or
        // stale records from another endpoint must not influence cleanup.
        if record.status != qualification::Status::Positive
            || record.repository_endpoint != self.base_url.as_ref()
            || record.feed_endpoint != self.allpackages_feed_endpoint.as_ref()
        {
            return None;
        }
        let key = cache
            .key(
                &self.allpackages_feed_endpoint,
                RawCacheRepresentation::AllPackagesZstd,
            )
            .ok()?;
        let path = cache.projection_path_for_hex_digest(&key, &record.feed_digest)?;
        path.is_file().then_some(path)
    }

    pub(super) fn active_allpackages_projection_path(&self) -> Option<std::path::PathBuf> {
        self.allpackages
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|source| source.projection_path.clone())
    }

    pub(in crate::cran::provider) fn parse_current_body(
        representation: CranCurrentIndexRepresentation,
        body: &[u8],
    ) -> Result<(CranCatalog, Vec<CranCatalogObservation>), String> {
        import_current_index(representation, body)
    }
}
