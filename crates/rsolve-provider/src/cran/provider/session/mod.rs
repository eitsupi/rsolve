use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use super::super::catalog::{CranCatalog, CranCatalogObservation, CranCatalogRecordContext};
use super::super::evidence::CranEvidenceObservation;
use super::super::history::{ArchiveEntry, ArchivePackagePayload};
use super::allpackages::IndexedProjection;
use super::cache_policy::CacheControlHeader;
use super::cache_policy::{cache_control_policy, permits_reuse};
use super::model::{
    CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA,
    CranCurrentIndexRepresentation, CranMetadataConfig, CranRefreshDiagnostic, CranRefreshProgress,
    CranRefreshProgressCallback, DEFAULT_COMPATIBLE_GENERATION_TTL,
};
use super::qualification;
use super::raw_cache::projection::{PackageProjection, ProjectionLookupError};
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

#[cfg(test)]
thread_local! {
    static CURRENT_PROJECTION_BUILD_COUNT: Cell<usize> = const { Cell::new(0) };
    static ARCHIVE_PROJECTION_BUILD_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
fn note_current_projection_build() {
    CURRENT_PROJECTION_BUILD_COUNT.with(|counter| counter.set(counter.get() + 1));
}

#[cfg(test)]
fn note_archive_projection_build() {
    ARCHIVE_PROJECTION_BUILD_COUNT.with(|counter| counter.set(counter.get() + 1));
}

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
    current: Option<Result<Rc<CurrentProjection>, CandidateLoadError>>,
    current_source: Option<crate::snapshot::SourceInput>,
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
pub(super) struct ArchiveHistorySource {
    projection: Option<Rc<RefCell<Option<PackageProjection>>>>,
    rebuild: Option<Rc<dyn Fn() -> Result<PackageProjection, String>>>,
    rebuild_attempted: Rc<Cell<bool>>,
    eager: Option<Rc<BTreeMap<String, ArchivePackagePayload>>>,
    entry_count: usize,
    rejection_count: usize,
    first_rejection: Option<Box<str>>,
    surface_digest: Box<str>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(super) struct ArchiveHistorySummary {
    pub(super) entry_count: usize,
    pub(super) rejection_count: usize,
    pub(super) first_rejection: Option<String>,
}

#[derive(Debug)]
enum ArchiveProjectionFailure {
    Storage(String),
    Semantic(String),
}

impl ArchiveHistorySource {
    pub(super) fn validate_projection(projection: &PackageProjection) -> Result<(), String> {
        let summary: ArchiveHistorySummary = postcard::from_bytes(projection.summary())
            .map_err(|error| format!("invalid archive history projection summary: {error}"))?;
        let record_count = summary
            .entry_count
            .checked_add(summary.rejection_count)
            .ok_or_else(|| "archive history projection record count overflow".to_owned())?;
        if record_count != projection.record_count() {
            return Err(format!(
                "archive history projection record count mismatch: expected {record_count}, stored {}",
                projection.record_count()
            ));
        }
        Ok(())
    }

    pub(super) fn from_projection(
        projection: PackageProjection,
        rebuild: Option<Rc<dyn Fn() -> Result<PackageProjection, String>>>,
    ) -> Result<Self, String> {
        Self::validate_projection(&projection)?;
        let summary: ArchiveHistorySummary = postcard::from_bytes(projection.summary())
            .map_err(|error| format!("invalid archive history projection summary: {error}"))?;
        Ok(Self {
            surface_digest: projection.surface_digest().into(),
            projection: Some(Rc::new(RefCell::new(Some(projection)))),
            rebuild,
            rebuild_attempted: Rc::new(Cell::new(false)),
            eager: None,
            entry_count: summary.entry_count,
            rejection_count: summary.rejection_count,
            first_rejection: summary.first_rejection.map(Into::into),
        })
    }

    fn decode_projection_package(
        projection: &PackageProjection,
        package: &PackageName,
    ) -> Result<Option<ArchivePackagePayload>, ArchiveProjectionFailure> {
        let Some(payload) =
            projection
                .lookup_package(package.as_str())
                .map_err(|error| match error {
                    ProjectionLookupError::Storage(error) => {
                        ArchiveProjectionFailure::Storage(error)
                    }
                    ProjectionLookupError::Invalid(error) => {
                        ArchiveProjectionFailure::Semantic(error)
                    }
                })?
        else {
            return Ok(None);
        };
        let record_count = payload.record_count;
        let payload = postcard::from_bytes::<ArchivePackagePayload>(&payload.bytes)
            .map_err(|error| ArchiveProjectionFailure::Semantic(error.to_string()))?;
        let expected = payload
            .entries
            .len()
            .checked_add(payload.rejections.len())
            .ok_or_else(|| {
                ArchiveProjectionFailure::Semantic(
                    "archive package projection record count overflow".into(),
                )
            })?;
        if expected != record_count {
            return Err(ArchiveProjectionFailure::Semantic(format!(
                "archive package projection record count mismatch: expected {expected}, stored {record_count}"
            )));
        }
        payload
            .validate_for_package(package)
            .map(Some)
            .map_err(ArchiveProjectionFailure::Semantic)
    }

    pub(super) fn package(
        &self,
        package: &PackageName,
    ) -> Result<ArchivePackagePayload, CandidateLoadError> {
        let payload = if let Some(projection_cell) = &self.projection {
            let projection_ref = projection_cell.borrow();
            let Some(projection) = projection_ref.as_ref() else {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::SnapshotInvalid,
                    "archive package projection is unavailable after a failed rebuild",
                ));
            };
            let result = Self::decode_projection_package(projection, package);
            drop(projection_ref);
            match result {
                Ok(result) => result,
                Err(ArchiveProjectionFailure::Storage(error)) => {
                    return Err(CandidateLoadError::new(
                        CandidateLoadErrorCategory::SnapshotInvalid,
                        error,
                    ));
                }
                Err(ArchiveProjectionFailure::Semantic(error)) => {
                    let Some(rebuild) = &self.rebuild else {
                        return Err(CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("invalid archive package projection: {error}"),
                        ));
                    };
                    if self.rebuild_attempted.replace(true) {
                        return Err(CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("invalid archive package projection: {error}"),
                        ));
                    }
                    let old_projection = projection_cell.borrow_mut().take();
                    drop(old_projection);
                    let rebuilt = rebuild().map_err(|rebuild_error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!(
                                "failed to rebuild archive package projection: {rebuild_error}"
                            ),
                        )
                    })?;
                    Self::validate_projection(&rebuilt).map_err(|validation_error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            validation_error,
                        )
                    })?;
                    *projection_cell.borrow_mut() = Some(rebuilt);
                    let projection_ref = projection_cell.borrow();
                    let Some(projection) = projection_ref.as_ref() else {
                        return Err(CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            "archive package projection is unavailable after rebuild",
                        ));
                    };
                    Self::decode_projection_package(projection, package).map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("invalid archive package projection after rebuild: {error:?}"),
                        )
                    })?
                }
            }
        } else {
            self.eager
                .as_ref()
                .and_then(|packages| packages.get(package.as_str()).cloned())
        };
        let payload = payload.unwrap_or_default();
        payload.validate_for_package(package).map_err(|error| {
            CandidateLoadError::new(CandidateLoadErrorCategory::SnapshotInvalid, error)
        })
    }

    pub(super) fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub(super) fn rejections(&self) -> usize {
        self.rejection_count
    }

    pub(super) fn first_rejection(&self) -> Option<&str> {
        self.first_rejection.as_deref()
    }

    pub(super) fn surface_digest(&self) -> &str {
        &self.surface_digest
    }
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

pub(super) struct CurrentProjection {
    projection: Option<PackageProjection>,
    eager_observations: Rc<[CranCatalogObservation]>,
    surface_digest: Box<str>,
}

impl fmt::Debug for CurrentProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentProjection")
            .field(
                "projection",
                &self.projection.as_ref().map(|_| "package-indexed"),
            )
            .field("eager_observation_count", &self.eager_observations.len())
            .field("surface_digest", &self.surface_digest)
            .finish()
    }
}

impl CurrentProjection {
    pub(super) fn new(projection: PackageProjection) -> Self {
        let surface_digest = projection.surface_digest().into();
        Self {
            projection: Some(projection),
            eager_observations: Rc::from([]),
            surface_digest,
        }
    }

    pub(super) fn eager(catalog: CranCatalog, observations: Vec<CranCatalogObservation>) -> Self {
        let surface_digest = catalog_surface_digest(&catalog);
        Self {
            projection: None,
            eager_observations: Rc::from(observations.into_boxed_slice()),
            surface_digest,
        }
    }

    pub(super) fn surface_digest(&self) -> &str {
        &self.surface_digest
    }

    pub(super) fn package_count(&self) -> usize {
        self.projection.as_ref().map_or_else(
            || {
                self.eager_observations
                    .iter()
                    .map(|row| row.package())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            },
            PackageProjection::package_count,
        )
    }

    pub(super) fn candidates(
        &self,
        package: &PackageName,
    ) -> Result<Vec<rsolve_core::PackageRelease>, CandidateLoadError> {
        let projection = self.observations(package)?;
        if let Some(rejection) = projection.rejections.first() {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                rejection.diagnostic().to_string(),
            ));
        }
        Ok(
            CranCatalog::from_provider_observations(&projection.observations)
                .candidates(package)
                .to_vec(),
        )
    }

    #[cfg(test)]
    pub(super) fn candidates_named(
        &self,
        package: &str,
    ) -> Option<Vec<rsolve_core::PackageRelease>> {
        let package = PackageName::new(package).ok()?;
        self.candidates(&package).ok()
    }

    pub(super) fn observations(
        &self,
        package: &PackageName,
    ) -> Result<super::super::catalog::CranProviderObservationProjection, CandidateLoadError> {
        if let Some(projection) = &self.projection {
            let Some(payload) = projection
                .lookup_package(package.as_str())
                .map_err(|error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::SnapshotInvalid,
                        error.to_string(),
                    )
                })?
            else {
                return Ok(super::super::catalog::provider_observations_from_fields(
                    Vec::new(),
                    CranCatalogRecordContext::PackagesIndex,
                    Some(package),
                ));
            };
            let record_count = payload.record_count;
            let records =
                current::decode_current_records(&payload.bytes, package).map_err(|error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::SnapshotInvalid,
                        format!("invalid current package projection: {error}"),
                    )
                })?;
            if records.len() != record_count {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::SnapshotInvalid,
                    format!(
                        "current package projection record count mismatch: expected {}, stored {record_count}",
                        records.len()
                    ),
                ));
            }
            return Ok(super::super::catalog::provider_observations_from_fields(
                records
                    .into_iter()
                    .map(|record| (record.record_index, Some(record.package), record.fields))
                    .collect(),
                CranCatalogRecordContext::PackagesIndex,
                Some(package),
            ));
        }
        let observations = self
            .eager_observations
            .iter()
            .filter(|observation| observation.package() == package)
            .cloned()
            .collect::<Vec<_>>();
        Ok(super::super::catalog::CranProviderObservationProjection {
            observations,
            rejections: Vec::new(),
        })
    }

    pub(super) fn materialize_catalog(&self) -> Result<CranCatalog, CandidateLoadError> {
        if let Some(catalog) = &self.projection {
            let mut observations = Vec::new();
            catalog
                .visit_packages(|package, payload, record_count| {
                    let package = PackageName::new(package).map_err(|error| error.to_string())?;
                    let records = current::decode_current_records(payload, &package)?;
                    if records.len() != record_count {
                        return Err(format!(
                            "current package projection record count mismatch: expected {}, stored {record_count}",
                            records.len()
                        ));
                    }
                    let projection = super::super::catalog::provider_observations_from_fields(
                        records
                            .into_iter()
                            .map(|record| {
                                (record.record_index, Some(record.package), record.fields)
                            })
                            .collect(),
                        CranCatalogRecordContext::PackagesIndex,
                        Some(&package),
                    );
                    observations.extend(projection.observations);
                    Ok(())
                })
                .map_err(|error| {
                    CandidateLoadError::new(CandidateLoadErrorCategory::SnapshotInvalid, error)
                })?;
            return Ok(CranCatalog::from_provider_observations(&observations));
        }
        Ok(CranCatalog::from_provider_observations(
            &self.eager_observations,
        ))
    }
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
    Available { source: Rc<ArchiveHistorySource> },
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
    SnapshotInvalid(Box<str>),
}

impl MetadataParseFailure {
    fn allows_fallback(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }

    fn allows_cached_retry(&self) -> bool {
        !matches!(self, Self::SnapshotInvalid(_))
    }

    fn category(&self) -> CandidateLoadErrorCategory {
        match self {
            Self::SnapshotInvalid(_) => CandidateLoadErrorCategory::SnapshotInvalid,
            Self::Invalid(_) | Self::NoFallback(_) => CandidateLoadErrorCategory::MetadataInvalid,
        }
    }
}

impl fmt::Display for MetadataParseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(diagnostic)
            | Self::NoFallback(diagnostic)
            | Self::SnapshotInvalid(diagnostic) => formatter.write_str(diagnostic),
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
    pub(in crate::cran::provider) fn reset_current_projection_build_count() {
        CURRENT_PROJECTION_BUILD_COUNT.with(|counter| counter.set(0));
    }

    #[cfg(test)]
    pub(in crate::cran::provider) fn current_projection_build_count() -> usize {
        CURRENT_PROJECTION_BUILD_COUNT.with(Cell::get)
    }

    #[cfg(test)]
    pub(in crate::cran::provider) fn reset_archive_projection_build_count() {
        ARCHIVE_PROJECTION_BUILD_COUNT.with(|counter| counter.set(0));
    }

    #[cfg(test)]
    pub(in crate::cran::provider) fn archive_projection_build_count() -> usize {
        ARCHIVE_PROJECTION_BUILD_COUNT.with(Cell::get)
    }

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
            current_source: None,
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
