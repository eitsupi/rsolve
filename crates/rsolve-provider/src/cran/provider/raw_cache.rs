//! Provider-private durable storage for raw CRAN metadata responses.
//!
//! Raw responses deliberately live outside semantic generations and the
//! current-generation validation record. This module does not issue network
//! requests or decide when a response should be revalidated.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rsolve_core::RegistryId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use super::cache_policy::{CacheControlHeader, cache_control_policy};
use super::transport::{TransportResponse, TransportResponseHeaders};
use super::{MAX_RESPONSE_BYTES, SnapshotStore};

const RAW_CACHE_DIRECTORY: &str = "raw-cache";
const RAW_CACHE_VERSION: &str = "v1";
const RAW_CACHE_FORMAT: &str = "rsolve-cran-raw-response";
const RAW_KEY_FORMAT: &str = "rsolve-cran-raw-key";
const ENTRY_SUFFIX: &str = ".raw";
const HEADER_LENGTH_BYTES: usize = 4;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_ENTRY_BYTES: u64 = MAX_RESPONSE_BYTES + MAX_HEADER_BYTES as u64 + 4;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RawCacheRepresentation {
    CurrentRds,
    CurrentGzip,
    CurrentDcf,
    ArchiveHistoryRds,
    PackageArchiveIndexRds,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawCacheKey {
    registry_id: Box<str>,
    endpoint: Box<str>,
    representation: RawCacheRepresentation,
    digest: Box<str>,
}

#[derive(Serialize)]
struct RawCacheKeyWire<'a> {
    format: &'static str,
    version: u32,
    registry_id: &'a str,
    endpoint: &'a str,
    representation: RawCacheRepresentation,
}

impl RawCacheKey {
    pub(crate) fn new(
        registry_id: &RegistryId,
        endpoint: &str,
        representation: RawCacheRepresentation,
    ) -> Result<Self, RawCacheError> {
        let endpoint = canonical_request_endpoint(endpoint)?;
        let registry_id = registry_id.to_string().into_boxed_str();
        let digest =
            canonical_key_digest(&registry_id, &endpoint, representation)?.into_boxed_str();
        Ok(Self {
            registry_id,
            endpoint,
            representation,
            digest,
        })
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn representation(&self) -> RawCacheRepresentation {
        self.representation
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
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

struct TemporaryPath(PathBuf);

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub(crate) struct RawCache {
    registry_id: RegistryId,
    directory: PathBuf,
}

impl RawCache {
    pub(crate) fn open(store: &SnapshotStore) -> Result<Self, RawCacheError> {
        let directory = store
            .root()
            .join(RAW_CACHE_DIRECTORY)
            .join(RAW_CACHE_VERSION);
        ensure_directory(&store.root().join(RAW_CACHE_DIRECTORY))?;
        ensure_directory(&directory)?;
        Ok(Self {
            registry_id: store.registry_id().clone(),
            directory,
        })
    }

    pub(crate) fn key(
        &self,
        endpoint: &str,
        representation: RawCacheRepresentation,
    ) -> Result<RawCacheKey, RawCacheError> {
        RawCacheKey::new(&self.registry_id, endpoint, representation)
    }

    pub(crate) fn lookup(&self, key: &RawCacheKey) -> RawCacheLookup {
        if let Err(error) = self.validate_key_registry(key) {
            return RawCacheLookup::Corrupt(error.to_string().into_boxed_str());
        }
        let path = self.entry_path(key);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return RawCacheLookup::Missing;
            }
            Err(error) => return RawCacheLookup::Corrupt(error.to_string().into_boxed_str()),
        };
        if !metadata.file_type().is_file() {
            return RawCacheLookup::Corrupt("raw cache entry is not a regular file".into());
        }
        if metadata.len() > MAX_ENTRY_BYTES {
            return RawCacheLookup::Corrupt("raw cache entry exceeds size limit".into());
        }
        match self.read_entry(&path, key, metadata.len()) {
            Ok(entry) => RawCacheLookup::Hit(entry),
            Err(error) => RawCacheLookup::Corrupt(error.to_string().into_boxed_str()),
        }
    }

    pub(crate) fn publish(
        &self,
        key: &RawCacheKey,
        write: RawCacheWrite,
    ) -> Result<RawCachePublishOutcome, RawCacheError> {
        self.validate_key_registry(key)?;
        if write.status != 200 {
            return Err(RawCacheError::Invalid(
                "only HTTP 200 responses may be stored in the raw cache".into(),
            ));
        }
        if !cache_control_policy(&write.cache_control, std::time::Duration::ZERO).can_store() {
            self.remove_entry(key)?;
            return Ok(RawCachePublishOutcome::NoStore);
        }
        let header = self.header_for_write(key, &write)?;
        self.write_entry(key, header, &write.body)?;
        Ok(RawCachePublishOutcome::Stored)
    }

    /// Advance only validation time after a later conditional validation. The
    /// observed time and body identity remain unchanged for a future 304.
    pub(crate) fn update_validated_at(
        &self,
        key: &RawCacheKey,
        validated_at: jiff::Timestamp,
    ) -> Result<(), RawCacheError> {
        self.update_validated_at_with_headers(
            key,
            validated_at,
            &TransportResponseHeaders::default(),
        )
    }

    pub(crate) fn update_validated_at_with_headers(
        &self,
        key: &RawCacheKey,
        validated_at: jiff::Timestamp,
        response_headers: &TransportResponseHeaders,
    ) -> Result<(), RawCacheError> {
        let entry = match self.lookup(key) {
            RawCacheLookup::Hit(entry) => entry,
            RawCacheLookup::Missing => {
                return Err(RawCacheError::Invalid("raw cache entry is missing".into()));
            }
            RawCacheLookup::Corrupt(error) => return Err(RawCacheError::Invalid(error)),
        };
        if validated_at < entry.validated_at {
            return Err(RawCacheError::Invalid(
                "raw cache validation time cannot move backwards".into(),
            ));
        }
        let write = RawCacheWrite {
            status: 200,
            body: entry.body,
            observed_at: entry.observed_at,
            validated_at,
            etag: response_headers.etag.clone().or(entry.etag),
            last_modified: response_headers
                .last_modified
                .clone()
                .or(entry.last_modified),
            cache_control: match &response_headers.cache_control {
                CacheControlHeader::Absent => entry.cache_control,
                _ => response_headers.cache_control.clone(),
            },
        };
        if !cache_control_policy(&write.cache_control, std::time::Duration::ZERO).can_store() {
            self.remove_entry(key)?;
            return Ok(());
        }
        let header = self.header_for_write(key, &write)?;
        self.write_entry(key, header, &write.body)
    }

    fn header_for_write(
        &self,
        key: &RawCacheKey,
        write: &RawCacheWrite,
    ) -> Result<RawCacheHeaderV1, RawCacheError> {
        if write.body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(RawCacheError::Invalid(
                "raw cache response body exceeds size limit".into(),
            ));
        }
        if write.validated_at < write.observed_at {
            return Err(RawCacheError::Invalid(
                "raw cache validation time precedes observation time".into(),
            ));
        }
        validate_cache_control(&write.cache_control)?;
        let observed_at = timestamp_string(write.observed_at)?;
        let validated_at = timestamp_string(write.validated_at)?;
        let header = RawCacheHeaderV1 {
            format: RAW_CACHE_FORMAT.into(),
            version: 1,
            registry_id: self.registry_id.to_string(),
            key_sha256: key.digest.clone().into(),
            endpoint: key.endpoint.clone().into(),
            representation: key.representation,
            body_length: write.body.len() as u64,
            body_sha256: hex(&Sha256::digest(&write.body)),
            observed_at,
            validated_at,
            etag: validate_etag(write.etag.as_deref())?,
            last_modified: validate_last_modified(write.last_modified.as_deref())?,
            cache_control: write.cache_control.clone(),
        };
        Ok(header)
    }

    fn write_entry(
        &self,
        key: &RawCacheKey,
        header: RawCacheHeaderV1,
        body: &[u8],
    ) -> Result<(), RawCacheError> {
        let header_bytes = serde_json::to_vec(&header).map_err(|error| {
            RawCacheError::Invalid(format!("unable to encode raw cache header: {error}").into())
        })?;
        if header_bytes.len() > MAX_HEADER_BYTES {
            return Err(RawCacheError::Invalid(
                "raw cache header exceeds size limit".into(),
            ));
        }
        let path = self.entry_path(key);
        let (temporary, mut file) = self.unique_temp_file()?;
        let _cleanup = TemporaryPath(temporary.clone());
        file.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        file.write_all(&header_bytes)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, &path)?;
        File::open(&path)?.sync_all()?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    fn read_entry(
        &self,
        path: &Path,
        key: &RawCacheKey,
        file_length: u64,
    ) -> Result<RawCacheEntry, RawCacheError> {
        let mut file = File::open(path)?;
        let mut length_bytes = [0_u8; HEADER_LENGTH_BYTES];
        file.read_exact(&mut length_bytes)?;
        let header_length = u32::from_le_bytes(length_bytes) as usize;
        if header_length == 0 || header_length > MAX_HEADER_BYTES {
            return Err(RawCacheError::Invalid(
                "raw cache header length is invalid".into(),
            ));
        }
        let total_prefix = HEADER_LENGTH_BYTES
            .checked_add(header_length)
            .ok_or_else(|| RawCacheError::Invalid("raw cache entry length overflow".into()))?;
        if file_length < total_prefix as u64 {
            return Err(RawCacheError::Invalid(
                "raw cache entry is truncated".into(),
            ));
        }
        let mut header_bytes = vec![0_u8; header_length];
        file.read_exact(&mut header_bytes)?;
        let header: RawCacheHeaderV1 = serde_json::from_slice(&header_bytes).map_err(|error| {
            RawCacheError::Invalid(format!("invalid raw cache header: {error}").into())
        })?;
        if serde_json::to_vec(&header).map_err(|error| {
            RawCacheError::Invalid(format!("invalid raw cache header: {error}").into())
        })? != header_bytes
        {
            return Err(RawCacheError::Invalid(
                "raw cache header is not canonical JSON".into(),
            ));
        }
        self.validate_header(key, &header)?;
        if header.body_length > MAX_RESPONSE_BYTES
            || file_length != total_prefix as u64 + header.body_length
        {
            return Err(RawCacheError::Invalid(
                "raw cache body length is invalid".into(),
            ));
        }
        let mut body = vec![0_u8; header.body_length as usize];
        file.read_exact(&mut body)?;
        if hex(&Sha256::digest(&body)) != header.body_sha256 {
            return Err(RawCacheError::Invalid(
                "raw cache body digest mismatch".into(),
            ));
        }
        let observed_at = parse_timestamp(&header.observed_at)?;
        let validated_at = parse_timestamp(&header.validated_at)?;
        Ok(RawCacheEntry {
            key: key.clone(),
            body,
            observed_at,
            validated_at,
            etag: header.etag.map(String::into_boxed_str),
            last_modified: header.last_modified.map(String::into_boxed_str),
            cache_control: header.cache_control,
        })
    }

    fn validate_header(
        &self,
        key: &RawCacheKey,
        header: &RawCacheHeaderV1,
    ) -> Result<(), RawCacheError> {
        if header.format != RAW_CACHE_FORMAT
            || header.version != 1
            || header.registry_id != self.registry_id.as_str()
            || header.key_sha256 != key.digest()
            || header.endpoint != key.endpoint()
            || header.representation != key.representation()
            || parse_hex_32(&header.key_sha256).is_err()
            || header.body_sha256.len() != 64
            || parse_hex_32(&header.body_sha256).is_err()
            || !is_canonical_endpoint(&header.endpoint)
            || canonical_key_digest(&header.registry_id, &header.endpoint, header.representation)?
                != header.key_sha256
        {
            return Err(RawCacheError::Invalid(
                "raw cache header identity is invalid".into(),
            ));
        }
        let observed_at = parse_timestamp(&header.observed_at)?;
        let validated_at = parse_timestamp(&header.validated_at)?;
        validate_etag(header.etag.as_deref())?;
        validate_last_modified(header.last_modified.as_deref())?;
        validate_cache_control(&header.cache_control)?;
        if validated_at < observed_at {
            return Err(RawCacheError::Invalid(
                "raw cache header metadata is invalid".into(),
            ));
        }
        Ok(())
    }

    fn entry_path(&self, key: &RawCacheKey) -> PathBuf {
        self.directory
            .join(format!("{}{}", key.digest(), ENTRY_SUFFIX))
    }

    fn validate_key_registry(&self, key: &RawCacheKey) -> Result<(), RawCacheError> {
        if key.registry_id.as_ref() != self.registry_id.as_str() {
            return Err(RawCacheError::Invalid(
                "raw cache key belongs to another registry".into(),
            ));
        }
        Ok(())
    }

    fn remove_entry(&self, key: &RawCacheKey) -> Result<(), RawCacheError> {
        let path = self.entry_path(key);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
                fs::remove_file(path)?;
                sync_directory(&self.directory)?;
                Ok(())
            }
            Ok(_) => Err(RawCacheError::Invalid(
                "raw cache entry is not removable".into(),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn unique_temp_file(&self) -> Result<(PathBuf, File), RawCacheError> {
        let pid = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| RawCacheError::Invalid(error.to_string().into()))?
            .as_nanos();
        for _ in 0..128 {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = self
                .directory
                .join(format!(".raw-entry-{pid}-{timestamp}-{sequence}.tmp"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(RawCacheError::Invalid(
            "unable to allocate raw cache temporary file".into(),
        ))
    }
}

fn canonical_request_endpoint(input: &str) -> Result<Box<str>, RawCacheError> {
    let url = Url::parse(input.trim()).map_err(|error| {
        RawCacheError::Invalid(format!("invalid raw cache endpoint: {error}").into())
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RawCacheError::Invalid(
            "raw cache endpoint must be an HTTP(S) URL without userinfo, query, or fragment".into(),
        ));
    }
    Ok(url.to_string().into_boxed_str())
}

fn is_canonical_endpoint(endpoint: &str) -> bool {
    canonical_request_endpoint(endpoint).is_ok_and(|canonical| canonical.as_ref() == endpoint)
}

fn canonical_key_digest(
    registry_id: &str,
    endpoint: &str,
    representation: RawCacheRepresentation,
) -> Result<String, RawCacheError> {
    let wire = RawCacheKeyWire {
        format: RAW_KEY_FORMAT,
        version: 1,
        registry_id,
        endpoint,
        representation,
    };
    let bytes = serde_json::to_vec(&wire).map_err(|error| {
        RawCacheError::Invalid(format!("unable to encode raw cache key: {error}").into())
    })?;
    Ok(hex(&Sha256::digest(bytes)))
}

fn validate_header_string(value: Option<&str>) -> Result<Option<String>, RawCacheError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty()
        || value.trim() != value
        || value.len() > 8 * 1024
        || value.chars().any(char::is_control)
        || value.contains(['\r', '\n'])
    {
        return Err(RawCacheError::Invalid(
            "raw cache validator is invalid".into(),
        ));
    }
    Ok(Some(value.to_owned()))
}

fn validate_cache_control(value: &CacheControlHeader) -> Result<(), RawCacheError> {
    if let CacheControlHeader::Valid(value) = value {
        validate_header_string(Some(value))?;
    }
    Ok(())
}

fn validate_etag(value: Option<&str>) -> Result<Option<String>, RawCacheError> {
    let Some(value) = validate_header_string(value)? else {
        return Ok(None);
    };
    let opaque = value.strip_prefix("W/").unwrap_or(&value);
    if !opaque.starts_with('"') || !opaque.ends_with('"') || opaque.len() < 2 {
        return Err(RawCacheError::Invalid("raw cache ETag is invalid".into()));
    }
    if !opaque[1..opaque.len() - 1]
        .bytes()
        .all(|byte| byte == 0x21 || (0x23..=0x7e).contains(&byte))
    {
        return Err(RawCacheError::Invalid("raw cache ETag is invalid".into()));
    }
    Ok(Some(value))
}

fn validate_last_modified(value: Option<&str>) -> Result<Option<String>, RawCacheError> {
    let Some(value) = validate_header_string(value)? else {
        return Ok(None);
    };
    let parsed = jiff::civil::DateTime::strptime("%a, %d %b %Y %H:%M:%S GMT", &value)
        .map_err(|_| RawCacheError::Invalid("raw cache Last-Modified is invalid".into()))?;
    if parsed.strftime("%a, %d %b %Y %H:%M:%S GMT").to_string() != value {
        return Err(RawCacheError::Invalid(
            "raw cache Last-Modified is not canonical IMF-fixdate".into(),
        ));
    }
    Ok(Some(value))
}

fn parse_timestamp(value: &str) -> Result<jiff::Timestamp, RawCacheError> {
    if value.len() != 20 || !value.ends_with('Z') {
        return Err(RawCacheError::Invalid(
            "raw cache timestamp is invalid".into(),
        ));
    }
    value.parse().map_err(|error| {
        RawCacheError::Invalid(format!("raw cache timestamp is invalid: {error}").into())
    })
}

fn timestamp_string(timestamp: jiff::Timestamp) -> Result<String, RawCacheError> {
    let value = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
    if value.len() != 20 || value.parse::<jiff::Timestamp>().is_err() {
        return Err(RawCacheError::Invalid(
            "raw cache timestamp cannot be represented canonically".into(),
        ));
    }
    Ok(value)
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], RawCacheError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RawCacheError::Invalid("raw cache digest is invalid".into()));
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> Result<u8, RawCacheError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RawCacheError::Invalid("raw cache digest is invalid".into())),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ensure_directory(path: &Path) -> Result<(), RawCacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(RawCacheError::Invalid(
            "raw cache namespace is not a regular directory".into(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => match fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => ensure_directory(path),
            Err(error) => Err(error.into()),
        },
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), RawCacheError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), RawCacheError> {
    // Windows has no portable directory fsync operation. The file and
    // replacement calls use write-through semantics instead.
    Ok(())
}

#[cfg(unix)]
fn replace_file(from: &Path, to: &Path) -> Result<(), RawCacheError> {
    fs::rename(from, to).map_err(Into::into)
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> Result<(), RawCacheError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let from = from
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let to = to
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::SnapshotStore;
    use std::ops::Deref;
    use tempfile::{TempDir, tempdir};

    struct StoreFixture {
        _directory: TempDir,
        store: SnapshotStore,
    }

    impl Deref for StoreFixture {
        type Target = SnapshotStore;

        fn deref(&self) -> &Self::Target {
            &self.store
        }
    }

    fn store() -> StoreFixture {
        let directory = tempdir().unwrap();
        let store = SnapshotStore::open(
            directory.path().to_path_buf(),
            RegistryId::new("cran").unwrap(),
        )
        .unwrap();
        StoreFixture {
            _directory: directory,
            store,
        }
    }

    fn key(store: &SnapshotStore) -> RawCacheKey {
        RawCacheKey::new(
            store.registry_id(),
            "https://cran.invalid/src/contrib/PACKAGES.rds",
            RawCacheRepresentation::CurrentRds,
        )
        .unwrap()
    }

    fn write(body: &[u8]) -> RawCacheWrite {
        let timestamp = "2026-08-23T00:00:00Z".parse().unwrap();
        RawCacheWrite {
            status: 200,
            body: body.to_vec(),
            observed_at: timestamp,
            validated_at: timestamp,
            etag: Some("\"tag\"".into()),
            last_modified: None,
            cache_control: CacheControlHeader::Valid("max-age=120".into()),
        }
    }

    #[test]
    fn raw_cache_round_trip_and_304_timestamp_update() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Missing));
        assert!(matches!(
            cache.publish(&key, write(b"body")).unwrap(),
            RawCachePublishOutcome::Stored
        ));
        cache.publish(&key, write(b"replacement")).unwrap();
        assert_eq!(fs::read_dir(&cache.directory).unwrap().count(), 1);
        let RawCacheLookup::Hit(entry) = cache.lookup(&key) else {
            panic!("expected hit")
        };
        assert_eq!(entry.body, b"replacement");
        let later = "2026-08-23T00:00:10Z".parse().unwrap();
        cache.update_validated_at(&key, later).unwrap();
        let RawCacheLookup::Hit(entry) = cache.lookup(&key) else {
            panic!("expected updated hit")
        };
        assert_eq!(entry.observed_at, "2026-08-23T00:00:00Z".parse().unwrap());
        assert_eq!(entry.validated_at, later);
    }

    #[test]
    fn raw_cache_preserves_validated_response_headers() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        let mut response = write(b"body");
        response.last_modified = Some("Wed, 21 Oct 2015 07:28:00 GMT".into());
        cache.publish(&key, response).unwrap();
        let RawCacheLookup::Hit(entry) = cache.lookup(&key) else {
            panic!("expected hit")
        };
        assert_eq!(entry.etag.as_deref(), Some("\"tag\""));
        assert_eq!(
            entry.last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
        assert_eq!(
            entry.cache_control,
            CacheControlHeader::Valid("max-age=120".into())
        );
    }

    #[test]
    fn raw_cache_304_no_store_evicts_without_republishing() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        cache.publish(&key, write(b"body")).unwrap();
        cache
            .update_validated_at_with_headers(
                &key,
                "2026-08-23T00:00:10Z".parse().unwrap(),
                &TransportResponseHeaders {
                    cache_control: CacheControlHeader::Valid("no-store".into()),
                    ..TransportResponseHeaders::default()
                },
            )
            .unwrap();
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Missing));
    }

    #[test]
    fn raw_cache_key_separates_endpoint_and_representation_and_rejects_unsafe_urls() {
        let store = store();
        let first = key(&store);
        let second = RawCacheKey::new(
            store.registry_id(),
            "https://cran.invalid/src/contrib/PACKAGES.gz",
            RawCacheRepresentation::CurrentGzip,
        )
        .unwrap();
        assert_ne!(first.digest(), second.digest());
        for endpoint in [
            "https://user:pass@cran.invalid/PACKAGES",
            "https://cran.invalid/PACKAGES?x=1",
            "https://cran.invalid/PACKAGES#fragment",
            "file:///tmp/PACKAGES",
        ] {
            assert!(
                RawCacheKey::new(
                    store.registry_id(),
                    endpoint,
                    RawCacheRepresentation::CurrentRds,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn raw_cache_no_store_evicts_existing_entry() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        cache.publish(&key, write(b"old")).unwrap();
        let mut response = write(b"body");
        response.cache_control = CacheControlHeader::Valid("no-store".into());
        assert!(matches!(
            cache.publish(&key, response).unwrap(),
            RawCachePublishOutcome::NoStore
        ));
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Missing));
    }

    #[test]
    fn raw_cache_rejects_invalid_cache_control_without_replacing_entry() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        cache.publish(&key, write(b"old")).unwrap();
        let oversized = "x".repeat(8 * 1024 + 1);
        for value in [
            " max-age=120".to_owned(),
            "max-age=120 ".to_owned(),
            "max-age=120\n".to_owned(),
            oversized,
        ] {
            let mut response = write(b"new");
            response.cache_control = CacheControlHeader::Valid(value.into_boxed_str());
            assert!(cache.publish(&key, response).is_err());
            let RawCacheLookup::Hit(entry) = cache.lookup(&key) else {
                panic!("invalid cache-control replaced the existing entry")
            };
            assert_eq!(entry.body, b"old");
        }
    }

    fn rewrite_header<F>(cache: &RawCache, key: &RawCacheKey, mutate: F)
    where
        F: FnOnce(&mut RawCacheHeaderV1),
    {
        let path = cache.entry_path(key);
        let bytes = fs::read(&path).unwrap();
        let header_length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let mut header: RawCacheHeaderV1 =
            serde_json::from_slice(&bytes[4..4 + header_length]).unwrap();
        mutate(&mut header);
        let header_bytes = serde_json::to_vec(&header).unwrap();
        let mut rewritten = (header_bytes.len() as u32).to_le_bytes().to_vec();
        rewritten.extend_from_slice(&header_bytes);
        rewritten.extend_from_slice(&bytes[4 + header_length..]);
        fs::write(path, rewritten).unwrap();
    }

    #[test]
    fn raw_cache_rejects_wrong_registry_key_and_header_identity() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let wrong_key = RawCacheKey::new(
            &RegistryId::new("other").unwrap(),
            "https://cran.invalid/src/contrib/PACKAGES.rds",
            RawCacheRepresentation::CurrentRds,
        )
        .unwrap();
        assert!(cache.publish(&wrong_key, write(b"body")).is_err());

        let key = key(&store);
        cache.publish(&key, write(b"body")).unwrap();
        rewrite_header(&cache, &key, |header| header.registry_id = "other".into());
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
        cache.publish(&key, write(b"body")).unwrap();
        rewrite_header(&cache, &key, |header| header.key_sha256 = "0".repeat(64));
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
    }

    #[test]
    fn raw_cache_rejects_wrong_length_or_digest_without_returning_body() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        cache.publish(&key, write(b"body")).unwrap();
        rewrite_header(&cache, &key, |header| header.body_length += 1);
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
        cache.publish(&key, write(b"body")).unwrap();
        rewrite_header(&cache, &key, |header| header.body_sha256 = "0".repeat(64));
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
    }

    #[test]
    fn raw_cache_rejects_oversized_headers_and_bodies() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        cache.publish(&key, write(b"body")).unwrap();
        let path = cache.entry_path(&key);
        let mut bytes = fs::read(&path).unwrap();
        bytes[..HEADER_LENGTH_BYTES]
            .copy_from_slice(&((MAX_HEADER_BYTES as u32) + 1).to_le_bytes());
        fs::write(&path, bytes).unwrap();
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));

        cache.publish(&key, write(b"body")).unwrap();
        rewrite_header(&cache, &key, |header| {
            header.body_length = MAX_RESPONSE_BYTES + 1;
        });
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
    }

    #[test]
    fn raw_cache_rejects_noncanonical_validators() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        cache.publish(&key, write(b"body")).unwrap();
        rewrite_header(&cache, &key, |header| {
            header.etag = Some("unquoted".into());
        });
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));

        cache.publish(&key, write(b"body")).unwrap();
        rewrite_header(&cache, &key, |header| {
            header.etag = Some("\"é\"".into());
        });
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));

        cache.publish(&key, write(b"body")).unwrap();
        rewrite_header(&cache, &key, |header| {
            header.last_modified = Some("Wed, 21 Oct 2015 07:28:00 UTC".into());
        });
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
    }

    #[cfg(unix)]
    #[test]
    fn raw_cache_rejects_entry_symlinks() {
        use std::os::unix::fs::symlink;
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        let target = cache.directory.join("outside");
        fs::write(&target, b"not-an-entry").unwrap();
        symlink(&target, cache.entry_path(&key)).unwrap();
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
    }

    #[cfg(unix)]
    #[test]
    fn raw_cache_rejects_symlink_namespaces() {
        use std::os::unix::fs::symlink;

        let first_store = store();
        let namespace = first_store.root().join(RAW_CACHE_DIRECTORY);
        fs::create_dir(&namespace).unwrap();
        fs::remove_dir(&namespace).unwrap();
        symlink(first_store.root().join("generations"), &namespace).unwrap();
        assert!(RawCache::open(&first_store).is_err());

        let second_store = store();
        let cache = RawCache::open(&second_store).unwrap();
        let version = cache.directory;
        fs::remove_dir(&version).unwrap();
        symlink(second_store.root().join("generations"), &version).unwrap();
        assert!(RawCache::open(&second_store).is_err());
    }

    #[test]
    fn raw_cache_corruption_never_returns_body() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        cache.publish(&key, write(b"body")).unwrap();
        let path = cache.entry_path(&key);
        let mut bytes = fs::read(&path).unwrap();
        bytes.pop();
        fs::write(path, bytes).unwrap();
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
    }

    #[test]
    fn raw_cache_rejects_noncanonical_header_json() {
        let store = store();
        let cache = RawCache::open(&store).unwrap();
        let key = key(&store);
        cache.publish(&key, write(b"body")).unwrap();
        let path = cache.entry_path(&key);
        let bytes = fs::read(&path).unwrap();
        let header_length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let header = &bytes[4..4 + header_length];
        let mut rewritten = ((header_length + 1) as u32).to_le_bytes().to_vec();
        rewritten.push(b' ');
        rewritten.extend_from_slice(header);
        rewritten.extend_from_slice(&bytes[4 + header_length..]);
        fs::write(path, rewritten).unwrap();
        assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
    }

    #[test]
    fn semantic_snapshot_namespace_is_untouched() {
        let store = store();
        let before = fs::read_dir(store.root().join("generations"))
            .unwrap()
            .count();
        let cache = RawCache::open(&store).unwrap();
        cache.publish(&key(&store), write(b"body")).unwrap();
        assert_eq!(
            fs::read_dir(store.root().join("generations"))
                .unwrap()
                .count(),
            before
        );
        assert!(!store.root().join("current").exists());
    }
}
