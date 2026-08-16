//! Transport-independent storage for verified source artifacts.
//!
//! The cache deliberately accepts a caller-owned reader.  Downloading bytes,
//! choosing a provider, and materializing a repository are responsibilities of
//! other layers.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use rsolve_core::{Sha256Digest, SourceArtifact};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod archive;
mod filesystem;
mod input;
mod materialization;
mod metadata;
mod object;
mod packages;
mod paths;
mod state;
mod transaction;
mod util;

use paths::CachePaths;
use util::unique_nonce;

pub use materialization::{
    MaterializationArtifact, MaterializationError, MaterializationMethod, MaterializationRecord,
    MaterializationRequest, MaterializationState, SelectedArtifact, materialize,
};
pub use packages::PackagesError;

#[cfg(test)]
use input::copy_compressed_input;
#[cfg(test)]
use metadata::descriptor_key;
#[cfg(test)]
use paths::create_cache_directories;
#[cfg(test)]
use util::hex_lower;

const PARTIAL_PREFIX: &str = ".partial.";

/// Maximum compressed input accepted when the source descriptor has no size.
///
/// A reader that produces more than this many bytes is stopped immediately and
/// the artifact is not committed. Descriptors with a size use that declared
/// size as their bound instead.
pub const MAX_COMPRESSED_INPUT_BYTES: u64 = 1 << 30;

/// The input to [`commit_artifact`].
pub struct ArtifactCommitRequest<'a> {
    /// The root directory owned by this cache instance.
    pub cache_root: &'a Path,
    /// The selected source artifact descriptor.
    pub artifact: &'a SourceArtifact,
    /// A stream supplied by the caller. It is only read after a cache miss.
    pub reader: &'a mut dyn Read,
}

/// A successfully committed source artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedArtifact {
    /// The immutable, SHA-256-addressed archive bytes.
    pub object_path: PathBuf,
    /// The committed descriptor metadata path.
    pub metadata_path: PathBuf,
    /// The SHA-256 of the archive bytes.
    pub sha256: Sha256Digest,
    /// The archive byte length.
    pub size: u64,
    /// Which upstream checksum declarations were verified.
    pub verification: VerificationStrength,
}

impl CachedArtifact {
    /// Returns the path to the immutable archive object.
    pub fn path(&self) -> &Path {
        &self.object_path
    }
}

/// Strength of the upstream verification recorded in cache metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStrength {
    /// No upstream checksum was supplied; internal SHA-256 was still computed.
    None,
    /// The upstream declaration was MD5 only. MD5 is recorded as a distinct,
    /// weaker verification signal.
    UpstreamMd5,
    /// The upstream declaration included SHA-256.
    UpstreamSha256,
    /// Both upstream MD5 and SHA-256 declarations were verified.
    UpstreamMd5AndSha256,
}

/// Errors produced while validating or atomically committing an artifact.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("unsupported upstream checksum algorithm `{algorithm}`")]
    UnsupportedChecksum { algorithm: String },
    #[error("malformed {algorithm} checksum `{value}`")]
    MalformedChecksum {
        algorithm: &'static str,
        value: String,
    },
    #[error("conflicting upstream {algorithm} checksum declarations")]
    ConflictingChecksum { algorithm: &'static str },
    #[error("{algorithm} checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch {
        algorithm: &'static str,
        expected: String,
        actual: String,
    },
    #[error("artifact size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("compressed input exceeds the configured {limit}-byte limit")]
    InputTooLarge { limit: u64 },
    #[error("cache metadata is invalid at {path}: {reason}")]
    InvalidMetadata { path: PathBuf, reason: String },
    #[error("cache object is corrupt at {path}: expected {expected}, got {actual}")]
    CorruptObject {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error(
        "failed to publish replacement object at {object}: {replacement}; the corrupt object was retained at {quarantine}, but restoring it failed: {restore}"
    )]
    ReplacementRecovery {
        object: PathBuf,
        quarantine: PathBuf,
        replacement: io::Error,
        restore: io::Error,
    },
    #[error("cache object path already contains different bytes: {path}")]
    ObjectConflict { path: PathBuf },
    #[error(
        "source artifact is not a readable gzip tar archive (or exceeds the 256 MiB/100k-entry sanity limits): {reason}"
    )]
    InvalidArchive { reason: String },
}

#[derive(Clone, Debug)]
struct Checksums {
    md5: Option<String>,
    sha256: Option<Sha256Digest>,
}

#[derive(Clone, Debug)]
struct Metadata {
    version: u32,
    descriptor_key: String,
    object_sha256: Sha256Digest,
    size: u64,
    upstream_md5: Option<String>,
    upstream_sha256: Option<Sha256Digest>,
    verification_strength: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MetadataFile {
    version: u32,
    descriptor_key: String,
    object_sha256: String,
    size: u64,
    upstream_md5: Option<String>,
    upstream_sha256: Option<String>,
    verification_strength: String,
}

/// Commit one source artifact from a caller-supplied stream.
pub fn commit_artifact(request: ArtifactCommitRequest<'_>) -> Result<CachedArtifact, CacheError> {
    commit_artifact_with_fs(request, &RealPublishFs)
}

fn commit_artifact_with_fs(
    request: ArtifactCommitRequest<'_>,
    publish_fs: &dyn PublishFs,
) -> Result<CachedArtifact, CacheError> {
    let checksums = metadata::validate_checksums(&request.artifact.upstream_checksums)?;
    let descriptor_key = metadata::descriptor_key(request.artifact, &checksums);
    let paths = CachePaths::new(request.cache_root, &descriptor_key);
    paths::create_cache_directories(&paths)?;

    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&paths.lock)
        .map_err(|source| CacheError::Io {
            operation: "create artifact lock",
            path: paths.lock.clone(),
            source,
        })?;
    lock.lock().map_err(|source| CacheError::Io {
        operation: "lock artifact",
        path: paths.lock.clone(),
        source,
    })?;

    if let Some(hit) = object::load_hit(&paths, &descriptor_key, request.artifact, &checksums)? {
        return Ok(hit);
    }

    let nonce = unique_nonce();
    let partial = paths.object_dir.join(format!("{PARTIAL_PREFIX}{}", nonce));
    let result = object::commit_miss(
        &paths,
        request.artifact,
        &checksums,
        &descriptor_key,
        request.reader,
        &partial,
        publish_fs,
    );
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

/// Convenience form of [`commit_artifact`] for callers that own the reader.
pub fn commit_source_artifact<R: Read>(
    cache_root: impl AsRef<Path>,
    artifact: &SourceArtifact,
    mut reader: R,
) -> Result<CachedArtifact, CacheError> {
    commit_artifact(ArtifactCommitRequest {
        cache_root: cache_root.as_ref(),
        artifact,
        reader: &mut reader,
    })
}

trait PublishFs {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
}

struct RealPublishFs;

impl PublishFs for RealPublishFs {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
}

#[cfg(test)]
mod materialization_tests;
#[cfg(test)]
mod tests;
