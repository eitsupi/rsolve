use serde::Serialize;
use std::rc::Rc;
use std::time::Duration;

/// The source buckets used by provider acquisition telemetry.  They describe
/// the kind of observation, never the endpoint from which it was obtained.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CranRefreshMetricsSource {
    CurrentIndex,
    ArchiveHistory,
    AllPackages,
    PackageLocalIndex,
    TarballDescription,
}

/// Counts collected by one CRAN refresher lifetime.
///
/// This is intentionally an immutable snapshot returned by
/// [`CranSnapshotRefresher::metrics`](crate::cran::CranSnapshotRefresher::metrics).
/// It contains no endpoint, cache path, or validator information and is not
/// persisted as part of a metadata generation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CranRefreshMetrics {
    pub http_attempts: u64,
    pub successful_response_body_bytes: u64,
    pub statuses: CranRefreshStatusMetrics,
    pub current_index: CranRefreshSourceMetrics,
    pub archive_history: CranRefreshSourceMetrics,
    pub allpackages: CranRefreshSourceMetrics,
    pub package_local_index: CranRefreshSourceMetrics,
    pub tarball_description: CranRefreshSourceMetrics,
    pub raw_cache_hits: u64,
    pub raw_cache_misses: u64,
    pub raw_cache_corrupt: u64,
    pub projection_reuses: u64,
    pub projection_builds: u64,
    pub projection_rebuilds: u64,
    pub package_history_lookups: u64,
    pub allpackages_adoptions: u64,
    pub package_local_fallbacks: u64,
    pub quarantined_releases: u64,
    pub coverage_gaps: u64,
    pub coverage_conflicts: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CranRefreshStatusMetrics {
    pub status_200: u64,
    pub status_304: u64,
    pub status_404: u64,
    pub status_410: u64,
    pub other: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CranRefreshSourceMetrics {
    pub requests: u64,
    pub successful_body_bytes: u64,
}

impl CranRefreshMetrics {
    pub(crate) fn observe_response(
        &mut self,
        source: CranRefreshMetricsSource,
        status: u16,
        body_len: usize,
    ) {
        self.http_attempts += 1;
        match status {
            200 => self.statuses.status_200 += 1,
            304 => self.statuses.status_304 += 1,
            404 => self.statuses.status_404 += 1,
            410 => self.statuses.status_410 += 1,
            _ => self.statuses.other += 1,
        }
        if (200..300).contains(&status) {
            self.successful_response_body_bytes += body_len as u64;
        }
        let bucket = match source {
            CranRefreshMetricsSource::CurrentIndex => &mut self.current_index,
            CranRefreshMetricsSource::ArchiveHistory => &mut self.archive_history,
            CranRefreshMetricsSource::AllPackages => &mut self.allpackages,
            CranRefreshMetricsSource::PackageLocalIndex => &mut self.package_local_index,
            CranRefreshMetricsSource::TarballDescription => &mut self.tarball_description,
        };
        bucket.requests += 1;
        if (200..300).contains(&status) {
            bucket.successful_body_bytes += body_len as u64;
        }
    }

    pub(crate) fn observe_attempt(&mut self, source: CranRefreshMetricsSource) {
        self.http_attempts += 1;
        let bucket = match source {
            CranRefreshMetricsSource::CurrentIndex => &mut self.current_index,
            CranRefreshMetricsSource::ArchiveHistory => &mut self.archive_history,
            CranRefreshMetricsSource::AllPackages => &mut self.allpackages,
            CranRefreshMetricsSource::PackageLocalIndex => &mut self.package_local_index,
            CranRefreshMetricsSource::TarballDescription => &mut self.tarball_description,
        };
        bucket.requests += 1;
    }
}

/// Coarse semantic milestones emitted during an online CRAN refresh.
///
/// The event stream intentionally describes refresh stages rather than
/// individual requests or package lookups, so callers can present useful
/// progress without exposing cache paths or transport details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranRefreshProgress {
    CurrentIndexStarted,
    CurrentIndexCompleted { packages: usize },
    ArchiveHistoryStarted,
    ArchiveHistoryCompleted { entries: usize },
    AllPackagesStarted,
    AllPackagesProjected,
    AllPackagesQualified { reused: bool },
    PackageLocalFallbackStarted,
    SnapshotPublishStarted { packages: usize },
    SnapshotPublishCompleted,
}

/// Provider-owned callback used by interactive orchestration to render
/// semantic refresh milestones. A missing callback keeps the provider silent.
pub type CranRefreshProgressCallback = Rc<dyn Fn(CranRefreshProgress)>;

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

/// A transport-neutral diagnostic from refreshing one package's CRAN source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CranRefreshDiagnostic {
    pub(super) endpoint: Box<str>,
    pub(super) status: Option<u16>,
    pub(super) status_detail: CranFastPathStatus,
    pub(super) source: CranRefreshSource,
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
