use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use super::super::catalog::{CranCatalog, CranCatalogObservation, CranCatalogRecordContext};
use super::super::evidence::CranEvidenceObservation;
use super::super::history::{ArchiveEntry, ArchivePackagePayload};
use super::cache_policy::CacheControlHeader;
use super::cache_policy::{cache_control_policy, permits_reuse};
use super::model::{
    CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA,
    CranCurrentIndexRepresentation, CranMetadataConfig, CranRefreshDiagnostic, CranRefreshMetrics,
    CranRefreshProgress, CranRefreshProgressCallback, DEFAULT_COMPATIBLE_GENERATION_TTL,
};
use super::qualification;
use super::raw_cache::projection::{
    PackageProjection, ProjectionLookupError, ProjectionVisitError,
};
use super::raw_cache::{RawCache, RawCacheEntry, RawCacheRepresentation};
use super::transport::{MeasuredTransport, Transport, TransportResponse};
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

#[derive(Clone)]
pub(super) struct PackageProjectionRecovery {
    projection: Option<Rc<RefCell<Option<PackageProjection>>>>,
    rebuild: Option<Rc<dyn Fn() -> Result<PackageProjection, String>>>,
    rebuild_attempted: Rc<Cell<bool>>,
    metrics: Option<Rc<RefCell<CranRefreshMetrics>>>,
}

#[derive(Debug)]
pub(super) enum ProjectionDecodeFailure {
    Storage(String),
    Semantic(String),
}

impl PackageProjectionRecovery {
    pub(super) fn new(
        projection: PackageProjection,
        rebuild: Option<Rc<dyn Fn() -> Result<PackageProjection, String>>>,
    ) -> Self {
        Self {
            projection: Some(Rc::new(RefCell::new(Some(projection)))),
            rebuild,
            rebuild_attempted: Rc::new(Cell::new(false)),
            metrics: None,
        }
    }

    pub(super) fn with_metrics(
        projection: PackageProjection,
        rebuild: Option<Rc<dyn Fn() -> Result<PackageProjection, String>>>,
        metrics: Rc<RefCell<CranRefreshMetrics>>,
    ) -> Self {
        let mut recovery = Self::new(projection, rebuild);
        recovery.metrics = Some(metrics);
        recovery
    }

    pub(super) fn eager() -> Self {
        Self {
            projection: None,
            rebuild: None,
            rebuild_attempted: Rc::new(Cell::new(false)),
            metrics: None,
        }
    }

    pub(super) fn has_projection(&self) -> bool {
        self.projection.is_some()
    }

    pub(super) fn package_count(&self) -> usize {
        self.projection.as_ref().map_or(0, |projection| {
            projection
                .borrow()
                .as_ref()
                .map_or(0, PackageProjection::package_count)
        })
    }

    pub(super) fn decode<T, F>(&self, label: &str, decoder: F) -> Result<T, CandidateLoadError>
    where
        F: Fn(&PackageProjection) -> Result<T, ProjectionDecodeFailure>,
    {
        let Some(projection_cell) = &self.projection else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                format!("{label} projection is unavailable without a persistent cache"),
            ));
        };
        let result = {
            let projection_ref = projection_cell.borrow();
            let Some(projection) = projection_ref.as_ref() else {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::SnapshotInvalid,
                    format!("{label} projection is unavailable after a failed rebuild"),
                ));
            };
            decoder(projection)
        };
        match result {
            Ok(value) => Ok(value),
            Err(ProjectionDecodeFailure::Storage(error)) => Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                error,
            )),
            Err(ProjectionDecodeFailure::Semantic(error)) => {
                let Some(rebuild) = &self.rebuild else {
                    return Err(Self::invalid(label, error));
                };
                if self.rebuild_attempted.replace(true) {
                    return Err(Self::invalid(label, error));
                }
                let old_projection = projection_cell.borrow_mut().take();
                drop(old_projection);
                let rebuilt = rebuild().map_err(|rebuild_error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::SnapshotInvalid,
                        format!("failed to rebuild {label} projection: {rebuild_error}"),
                    )
                })?;
                if let Some(metrics) = &self.metrics {
                    metrics.borrow_mut().projection_rebuilds += 1;
                }
                *projection_cell.borrow_mut() = Some(rebuilt);
                let projection_ref = projection_cell.borrow();
                let Some(projection) = projection_ref.as_ref() else {
                    return Err(CandidateLoadError::new(
                        CandidateLoadErrorCategory::SnapshotInvalid,
                        format!("{label} projection is unavailable after rebuild"),
                    ));
                };
                decoder(projection).map_err(|error| match error {
                    ProjectionDecodeFailure::Storage(error)
                    | ProjectionDecodeFailure::Semantic(error) => CandidateLoadError::new(
                        CandidateLoadErrorCategory::SnapshotInvalid,
                        format!("invalid {label} projection after rebuild: {error}"),
                    ),
                })
            }
        }
    }

    fn invalid(label: &str, error: String) -> CandidateLoadError {
        CandidateLoadError::new(
            CandidateLoadErrorCategory::SnapshotInvalid,
            format!("invalid {label} projection: {error}"),
        )
    }
}

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
    transport: Rc<MeasuredTransport<T>>,
    pub(in crate::cran::provider) metrics: Rc<RefCell<CranRefreshMetrics>>,
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
    projection: PackageProjectionRecovery,
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
        metrics: Rc<RefCell<CranRefreshMetrics>>,
    ) -> Result<Self, String> {
        Self::validate_projection(&projection)?;
        let summary: ArchiveHistorySummary = postcard::from_bytes(projection.summary())
            .map_err(|error| format!("invalid archive history projection summary: {error}"))?;
        Ok(Self {
            surface_digest: projection.surface_digest().into(),
            projection: PackageProjectionRecovery::with_metrics(projection, rebuild, metrics),
            eager: None,
            entry_count: summary.entry_count,
            rejection_count: summary.rejection_count,
            first_rejection: summary.first_rejection.map(Into::into),
        })
    }

    fn decode_projection_package(
        projection: &PackageProjection,
        package: &PackageName,
    ) -> Result<Option<ArchivePackagePayload>, ProjectionDecodeFailure> {
        let Some(payload) =
            projection
                .lookup_package(package.as_str())
                .map_err(|error| match error {
                    ProjectionLookupError::Storage(error) => {
                        ProjectionDecodeFailure::Storage(error)
                    }
                    ProjectionLookupError::Invalid(error) => {
                        ProjectionDecodeFailure::Semantic(error)
                    }
                })?
        else {
            return Ok(None);
        };
        let record_count = payload.record_count;
        let payload = postcard::from_bytes::<ArchivePackagePayload>(&payload.bytes)
            .map_err(|error| ProjectionDecodeFailure::Semantic(error.to_string()))?;
        let expected = payload
            .entries
            .len()
            .checked_add(payload.rejections.len())
            .ok_or_else(|| {
                ProjectionDecodeFailure::Semantic(
                    "archive package projection record count overflow".into(),
                )
            })?;
        if expected != record_count {
            return Err(ProjectionDecodeFailure::Semantic(format!(
                "archive package projection record count mismatch: expected {expected}, stored {record_count}"
            )));
        }
        payload
            .validate_for_package(package)
            .map(Some)
            .map_err(ProjectionDecodeFailure::Semantic)
    }

    pub(super) fn package(
        &self,
        package: &PackageName,
    ) -> Result<ArchivePackagePayload, CandidateLoadError> {
        let payload = if self.projection.has_projection() {
            self.projection.decode("archive package", |projection| {
                Self::decode_projection_package(projection, package)
            })?
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
    pub(super) projection: PackageProjectionRecovery,
    pub(super) source: crate::snapshot::SourceInput,
    projection_path: std::path::PathBuf,
}

impl AllPackagesSource {
    pub(super) fn observations(
        &self,
        package: &str,
    ) -> Result<super::super::catalog::CranProviderObservationProjection, CandidateLoadError> {
        self.projection
            .decode(&format!("ALLPACKAGES package {package}"), |projection| {
                super::allpackages::observations(projection, package).map_err(|error| match error {
                    super::allpackages::AllPackagesProjectionError::Storage(error) => {
                        ProjectionDecodeFailure::Storage(error)
                    }
                    super::allpackages::AllPackagesProjectionError::Semantic(error) => {
                        ProjectionDecodeFailure::Semantic(error)
                    }
                })
            })
    }

    pub(super) fn classify_current(
        &self,
        current: &CranCatalog,
    ) -> Result<super::allpackages::CoverageSummary, CandidateLoadError> {
        self.projection
            .decode("ALLPACKAGES coverage", |projection| {
                super::allpackages::classify_current(projection, current).map_err(|error| {
                    match error {
                        super::allpackages::AllPackagesProjectionError::Storage(error) => {
                            ProjectionDecodeFailure::Storage(error)
                        }
                        super::allpackages::AllPackagesProjectionError::Semantic(error) => {
                            ProjectionDecodeFailure::Semantic(error)
                        }
                    }
                })
            })
    }
}

pub(super) struct BulkCandidateResult {
    pub(super) candidates: CandidateLoadResult,
    pub(super) evidence: Vec<CranEvidenceObservation>,
}

pub(super) struct CurrentProjection {
    projection: PackageProjectionRecovery,
    eager_observations: Rc<[CranCatalogObservation]>,
    built_catalog: RefCell<Option<Rc<CranCatalog>>>,
    surface_digest: Box<str>,
}

impl fmt::Debug for CurrentProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentProjection")
            .field(
                "projection",
                &self
                    .projection
                    .has_projection()
                    .then_some("package-indexed"),
            )
            .field("eager_observation_count", &self.eager_observations.len())
            .field("surface_digest", &self.surface_digest)
            .finish()
    }
}

impl CurrentProjection {
    pub(super) fn new(
        projection: PackageProjection,
        rebuild: Option<Rc<dyn Fn() -> Result<PackageProjection, String>>>,
        built_catalog: Option<Rc<CranCatalog>>,
        metrics: Rc<RefCell<CranRefreshMetrics>>,
    ) -> Self {
        let surface_digest = projection.surface_digest().into();
        Self {
            projection: PackageProjectionRecovery::with_metrics(projection, rebuild, metrics),
            eager_observations: Rc::from([]),
            built_catalog: RefCell::new(built_catalog),
            surface_digest,
        }
    }

    pub(super) fn eager(catalog: CranCatalog, observations: Vec<CranCatalogObservation>) -> Self {
        let surface_digest = catalog_surface_digest(&catalog);
        Self {
            projection: PackageProjectionRecovery::eager(),
            eager_observations: Rc::from(observations.into_boxed_slice()),
            built_catalog: RefCell::new(None),
            surface_digest,
        }
    }

    pub(super) fn surface_digest(&self) -> &str {
        &self.surface_digest
    }

    pub(super) fn package_count(&self) -> usize {
        if self.projection.has_projection() {
            self.projection.package_count()
        } else {
            self.eager_observations
                .iter()
                .map(|row| row.package())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        }
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
        if self.projection.has_projection() {
            return self.projection.decode("current package", |projection| {
                Self::decode_projection_observations(projection, package)
            });
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

    fn decode_projection_package(
        projection: &PackageProjection,
        package: &PackageName,
    ) -> Result<Vec<current::CurrentProjectionRecord>, ProjectionDecodeFailure> {
        let Some(payload) =
            projection
                .lookup_package(package.as_str())
                .map_err(|error| match error {
                    ProjectionLookupError::Storage(error) => {
                        ProjectionDecodeFailure::Storage(error)
                    }
                    ProjectionLookupError::Invalid(error) => {
                        ProjectionDecodeFailure::Semantic(error)
                    }
                })?
        else {
            return Ok(Vec::new());
        };
        let record_count = payload.record_count;
        let records = current::decode_current_records(&payload.bytes, package)
            .map_err(ProjectionDecodeFailure::Semantic)?;
        if records.len() != record_count {
            return Err(ProjectionDecodeFailure::Semantic(format!(
                "current package projection record count mismatch: expected {}, stored {record_count}",
                records.len()
            )));
        }
        Ok(records)
    }

    fn observations_from_records(
        records: Vec<current::CurrentProjectionRecord>,
        package: &PackageName,
    ) -> super::super::catalog::CranProviderObservationProjection {
        super::super::catalog::provider_observations_from_fields(
            records
                .into_iter()
                .map(|record| (record.record_index, Some(record.package), record.fields))
                .collect(),
            CranCatalogRecordContext::PackagesIndex,
            Some(package),
        )
    }

    fn decode_projection_observations(
        projection: &PackageProjection,
        package: &PackageName,
    ) -> Result<super::super::catalog::CranProviderObservationProjection, ProjectionDecodeFailure>
    {
        let records = Self::decode_projection_package(projection, package)?;
        let observations = Self::observations_from_records(records, package);
        if let Some(rejection) = observations.rejections.first() {
            return Err(ProjectionDecodeFailure::Semantic(format!(
                "current package projection contains an invalid record: {}",
                rejection.diagnostic()
            )));
        }
        Ok(observations)
    }

    pub(super) fn materialize_catalog(&self) -> Result<Rc<CranCatalog>, CandidateLoadError> {
        if let Some(catalog) = self.built_catalog.borrow_mut().take() {
            return Ok(catalog);
        }
        if self.projection.has_projection() {
            return self
                .projection
                .decode("current", Self::materialize_projection)
                .map(Rc::new);
        }
        Ok(Rc::new(CranCatalog::from_provider_observations(
            &self.eager_observations,
        )))
    }

    fn materialize_projection(
        projection: &PackageProjection,
    ) -> Result<CranCatalog, ProjectionDecodeFailure> {
        let mut observations = Vec::new();
        projection
            .visit_packages_with_error(|package, payload, record_count| {
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
                        .map(|record| (record.record_index, Some(record.package), record.fields))
                        .collect(),
                    CranCatalogRecordContext::PackagesIndex,
                    Some(&package),
                );
                if let Some(rejection) = projection.rejections.first() {
                    return Err(format!(
                        "current package projection contains an invalid record: {}",
                        rejection.diagnostic()
                    ));
                }
                observations.extend(projection.observations);
                Ok(())
            })
            .map_err(|error| match error {
                ProjectionVisitError::Storage(error) => ProjectionDecodeFailure::Storage(error),
                ProjectionVisitError::Invalid(error) => ProjectionDecodeFailure::Semantic(error),
                ProjectionVisitError::Visitor(error) => ProjectionDecodeFailure::Semantic(error),
            })?;
        Ok(CranCatalog::from_provider_observations(&observations))
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

impl<T: Transport + 'static> CranRefreshSession<T> {
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
        let metrics = Rc::new(RefCell::new(CranRefreshMetrics::default()));
        Self {
            base_url: config.repository_endpoint.trim_end_matches('/').into(),
            allpackages_feed_endpoint: config
                .allpackages_feed_endpoint
                .trim_end_matches('/')
                .into(),
            refresh_metadata: config.refresh_metadata,
            allow_allpackages_history: config.allow_allpackages_history,
            transport: Rc::new(MeasuredTransport::new(transport, Rc::clone(&metrics))),
            metrics,
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

    pub(in crate::cran::provider) fn metrics(&self) -> CranRefreshMetrics {
        self.metrics.borrow().clone()
    }

    pub(super) fn emit_progress(&self, event: CranRefreshProgress) {
        if let Some(progress) = &self.progress {
            progress(event);
        }
    }

    pub(super) fn emit_package_local_fallback(&mut self) {
        self.metrics.borrow_mut().package_local_fallbacks += 1;
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
