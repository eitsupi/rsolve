//! CRAN archive refresh and lazy DESCRIPTION fallback.

#[cfg(test)]
use self::raw_cache::RawCache;
#[cfg(test)]
use super::history::ArchiveEntry;
#[cfg(test)]
use super::history::CranHistoryError;
use crate::SnapshotStore;
#[cfg(test)]
use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, PackageRelease,
};
#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::error::Error;
#[cfg(test)]
use std::fmt;

// Raw-response/cache integration consumes this provider-private policy seam
// without coupling semantic snapshot inspection to response headers.
mod allpackages;
pub mod cache_policy;
mod model;
mod negative;
mod persistent_cache;
mod qualification;
// Raw-cache APIs remain provider-private and are used by current-index refresh.
#[cfg_attr(not(test), expect(dead_code))]
pub(crate) mod raw_cache;
mod refresher;
mod runtime;
mod session;
mod snapshot;
mod transport;

pub use model::{
    CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA,
    CranCurrentIndexRepresentation, CranFastPathStatus, CranMetadataConfig, CranRefreshDiagnostic,
    CranRefreshSource, DEFAULT_ALLPACKAGES_FEED_ENDPOINT, DEFAULT_COMPATIBLE_GENERATION_TTL,
};
pub use persistent_cache::{
    CranSnapshotCacheDiagnostic, CranSnapshotCachePolicy, CranSnapshotCacheResult,
    CranSnapshotCacheStatus, inspect_cran_snapshot_cache,
};
pub(crate) use persistent_cache::{
    inspect_cran_snapshot_cache_with_refresh_guard, inspect_cran_snapshot_cache_without_wait,
};
#[cfg(test)]
use refresher::canonical_base_url;
use refresher::extract_description;
pub use refresher::{
    CranPersistentRefresh, CranPersistentRefreshPreflight, CranSnapshotRefresher,
    CranSnapshotRefresherError,
};
use runtime::CandidateSource;
pub use runtime::CranCandidateSnapshot;
#[cfg(test)]
use runtime::CranProvider;
#[cfg(test)]
use runtime::CranRuntimeLoader;
use session::{CranRefreshSession, HistorySource};
#[cfg(test)]
pub(crate) use snapshot::refresh_and_publish_with_transport;
use snapshot::{
    allpackages_record_to_evidence, archive_rejection_to_evidence, import_current_index,
    index_record_to_evidence, source_input_with_metadata,
};
pub(crate) use transport::Transport;
#[cfg(test)]
pub(crate) use transport::TransportError;
#[cfg(test)]
pub(crate) use transport::{TransportResponse, TransportResponseHeaders, TransportValidators};

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
