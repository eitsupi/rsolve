//! Provider-private durable storage for raw CRAN metadata responses.
//!
//! Raw responses deliberately live outside semantic generations and the
//! current-generation validation record. This module does not issue network
//! requests or decide when a response should be revalidated.

use std::fmt;
use std::io;

use serde::{Deserialize, Serialize};

use super::SnapshotStore;
use super::cache_policy::{CacheControlHeader, cache_control_policy};
use super::transport::TransportResponse;

pub(super) const RAW_CACHE_DIRECTORY: &str = "raw-cache";
pub(super) const RAW_CACHE_VERSION: &str = "v1";
pub(super) const RAW_CACHE_FORMAT: &str = "rsolve-cran-raw-response";
pub(super) const PROJECTION_DIRECTORY: &str = "projections";
pub(super) const RAW_KEY_FORMAT: &str = "rsolve-cran-raw-key";
pub(super) const ENTRY_SUFFIX: &str = ".raw";
pub(super) const HEADER_LENGTH_BYTES: usize = 4;
pub(super) const MAX_HEADER_BYTES: usize = 64 * 1024;
pub(super) const MAX_ENTRY_BYTES: u64 = super::MAX_RESPONSE_BYTES + MAX_HEADER_BYTES as u64 + 4;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectionNamespace {
    AllPackages,
    Current,
    ArchiveHistory,
    Auxiliary,
}

mod key;
pub(crate) mod projection;
mod store;
#[cfg(test)]
mod tests;
mod wire;

pub(crate) use store::RawCache;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RawCacheRepresentation {
    CurrentRds,
    CurrentGzip,
    CurrentDcf,
    ArchiveHistoryRds,
    PackageArchiveIndexRds,
    AllPackagesZstd,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawCacheKey {
    registry_id: Box<str>,
    endpoint: Box<str>,
    representation: RawCacheRepresentation,
    digest: Box<str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawCacheWrite {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
    pub(crate) observed_at: jiff::Timestamp,
    pub(crate) validated_at: jiff::Timestamp,
    pub(crate) etag: Option<Box<str>>,
    pub(crate) last_modified: Option<Box<str>>,
    pub(crate) cache_control: CacheControlHeader,
}

impl RawCacheWrite {
    #[expect(dead_code)]
    pub(crate) fn from_response(
        response: &TransportResponse,
        observed_at: jiff::Timestamp,
        validated_at: jiff::Timestamp,
    ) -> Self {
        Self {
            status: response.status,
            body: response.body.clone(),
            observed_at,
            validated_at,
            etag: response.headers.etag.clone(),
            last_modified: response.headers.last_modified.clone(),
            cache_control: response.headers.cache_control.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawCacheEntry {
    pub(crate) key: RawCacheKey,
    pub(crate) body: Vec<u8>,
    pub(crate) observed_at: jiff::Timestamp,
    pub(crate) validated_at: jiff::Timestamp,
    pub(crate) etag: Option<Box<str>>,
    pub(crate) last_modified: Option<Box<str>>,
    pub(crate) cache_control: CacheControlHeader,
}

#[derive(Debug)]
pub(crate) enum RawCacheLookup {
    Missing,
    Hit(RawCacheEntry),
    Corrupt(Box<str>),
}

#[derive(Debug)]
pub(crate) enum RawCacheError {
    Io(io::Error),
    Invalid(Box<str>),
}

impl fmt::Display for RawCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "raw cache I/O error: {error}"),
            Self::Invalid(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for RawCacheError {}

impl From<io::Error> for RawCacheError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug)]
pub(crate) enum RawCachePublishOutcome {
    Stored,
    NoStore,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawCacheHeaderV1 {
    format: String,
    version: u32,
    registry_id: String,
    key_sha256: String,
    endpoint: String,
    representation: RawCacheRepresentation,
    body_length: u64,
    body_sha256: String,
    observed_at: String,
    validated_at: String,
    etag: Option<String>,
    last_modified: Option<String>,
    cache_control: CacheControlHeader,
}
