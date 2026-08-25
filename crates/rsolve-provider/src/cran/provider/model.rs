use std::time::Duration;

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
