//! Transport-independent storage for verified source artifacts.
//!
//! The cache deliberately accepts a caller-owned reader.  Downloading bytes,
//! choosing a provider, and materializing a repository are responsibilities of
//! other layers.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use md5::{Digest as Md5Digest, Md5};
use nrr_core::{Sha256Digest, SourceArtifact, UpstreamChecksum};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use tar::Archive;
use thiserror::Error;

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
    let checksums = validate_checksums(&request.artifact.upstream_checksums)?;
    let descriptor_key = descriptor_key(request.artifact, &checksums);
    let paths = CachePaths::new(request.cache_root, &descriptor_key);
    create_cache_directories(&paths)?;

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

    if let Some(hit) = load_hit(&paths, &descriptor_key, request.artifact, &checksums)? {
        return Ok(hit);
    }

    let nonce = unique_nonce();
    let partial = paths.object_dir.join(format!("{PARTIAL_PREFIX}{}", nonce));
    let result = commit_miss(
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

struct CachePaths {
    lock: PathBuf,
    object_dir: PathBuf,
    metadata: PathBuf,
    lock_dir: PathBuf,
}

impl CachePaths {
    fn new(root: &Path, descriptor_key: &str) -> Self {
        let root = root.to_path_buf();
        let shard = &descriptor_key[..2];
        let lock_dir = root.join("locks/objects/sha256").join(shard);
        let lock = lock_dir.join(format!("{descriptor_key}.lock"));
        let object_dir = root.join("objects/sources/sha256");
        let metadata = root
            .join("artifacts/sources/sha256")
            .join(shard)
            .join(format!("{descriptor_key}.json"));
        Self {
            lock,
            object_dir,
            metadata,
            lock_dir,
        }
    }

    fn object(&self, digest: &Sha256Digest) -> PathBuf {
        self.object_dir
            .join(&digest.as_str()[..2])
            .join(digest.as_str())
    }

    fn object_lock(&self, digest: &Sha256Digest) -> PathBuf {
        self.lock_dir
            .parent()
            .expect("lock shard has a parent")
            .join(&digest.as_str()[..2])
            .join(format!("{}.object.lock", digest.as_str()))
    }
}

fn create_cache_directories(paths: &CachePaths) -> Result<(), CacheError> {
    for directory in [
        paths.lock_dir.clone(),
        paths.object_dir.clone(),
        paths
            .metadata
            .parent()
            .expect("metadata has a parent")
            .to_path_buf(),
    ] {
        fs::create_dir_all(&directory).map_err(|source| CacheError::Io {
            operation: "create cache directory",
            path: directory,
            source,
        })?;
    }
    Ok(())
}

fn commit_miss(
    paths: &CachePaths,
    artifact: &SourceArtifact,
    checksums: &Checksums,
    descriptor_key: &str,
    reader: &mut dyn Read,
    partial: &Path,
    publish_fs: &dyn PublishFs,
) -> Result<CachedArtifact, CacheError> {
    let mut output = open_file(partial, true, "create partial artifact")?;
    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    let size = copy_compressed_input(
        reader,
        &mut output,
        artifact.size,
        MAX_COMPRESSED_INPUT_BYTES,
        partial,
        &mut sha256,
        &mut md5,
    )?;
    output.sync_all().map_err(|source| CacheError::Io {
        operation: "sync partial artifact",
        path: partial.to_path_buf(),
        source,
    })?;
    drop(output);

    if let Some(expected) = artifact.size
        && expected != size
    {
        return Err(CacheError::SizeMismatch {
            expected,
            actual: size,
        });
    }
    let actual_sha = hex_lower(&Sha2Digest::finalize(sha256));
    if let Some(expected) = checksums.sha256.as_ref()
        && expected.as_str() != actual_sha
    {
        return Err(CacheError::ChecksumMismatch {
            algorithm: "sha256",
            expected: expected.to_string(),
            actual: actual_sha,
        });
    }
    let actual_md5 = hex_lower(&Md5Digest::finalize(md5));
    if let Some(expected) = checksums.md5.as_deref()
        && expected != actual_md5
    {
        return Err(CacheError::ChecksumMismatch {
            algorithm: "md5",
            expected: expected.to_owned(),
            actual: actual_md5,
        });
    }
    let sha256 = Sha256Digest::new(&actual_sha).expect("internal SHA-256 is always 64 hex digits");
    let object = paths.object(&sha256);
    validate_source_archive(partial)?;
    fs::create_dir_all(object.parent().expect("object has a shard parent")).map_err(|source| {
        CacheError::Io {
            operation: "create object shard directory",
            path: object.clone(),
            source,
        }
    })?;
    let object_lock_path = paths.object_lock(&sha256);
    let object_lock_parent = object_lock_path.parent().expect("object lock has a parent");
    fs::create_dir_all(object_lock_parent).map_err(|source| CacheError::Io {
        operation: "create object lock directory",
        path: object_lock_parent.to_path_buf(),
        source,
    })?;
    let object_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&object_lock_path)
        .map_err(|source| CacheError::Io {
            operation: "create object lock",
            path: object_lock_path.clone(),
            source,
        })?;
    object_lock.lock().map_err(|source| CacheError::Io {
        operation: "lock object",
        path: object_lock_path,
        source,
    })?;
    let final_partial = object.with_file_name(format!("{PARTIAL_PREFIX}{}", unique_nonce()));
    fs::rename(partial, &final_partial).map_err(|source| CacheError::Io {
        operation: "move partial into object shard",
        path: final_partial.clone(),
        source,
    })?;
    if let Err(error) = sync_directory(object.parent().expect("object has a shard parent")) {
        let _ = fs::remove_file(&final_partial);
        return Err(error);
    }
    if let Err(error) = publish_object_with_fs(&final_partial, &object, &sha256, size, publish_fs) {
        let _ = fs::remove_file(&final_partial);
        return Err(error);
    }
    sync_directory(object.parent().expect("object has a shard parent"))?;

    let metadata = Metadata {
        version: 1,
        descriptor_key: descriptor_key.to_owned(),
        object_sha256: sha256.clone(),
        size,
        upstream_md5: checksums.md5.clone(),
        upstream_sha256: checksums.sha256.clone(),
        verification_strength: verification_strength(checksums).to_owned(),
    };
    commit_metadata(&paths.metadata, &metadata)?;
    Ok(cached_artifact(paths, metadata))
}

fn copy_compressed_input<W: Write>(
    reader: &mut dyn Read,
    output: &mut W,
    expected: Option<u64>,
    hard_limit: u64,
    partial: &Path,
    sha256: &mut Sha256,
    md5: &mut Md5,
) -> Result<u64, CacheError> {
    let limit = expected.unwrap_or(hard_limit);
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        // Once the bound is reached, read exactly one byte to distinguish an
        // exact boundary from an over-limit stream. Saturating arithmetic is
        // intentional so a declared u64::MAX size cannot wrap.
        let at_limit = size >= limit;
        let capacity = if at_limit {
            1
        } else {
            limit.saturating_sub(size).min(buffer.len() as u64) as usize
        };
        let read = reader
            .read(&mut buffer[..capacity])
            .map_err(|source| CacheError::Io {
                operation: "read artifact stream",
                path: partial.to_path_buf(),
                source,
            })?;
        if read == 0 {
            if let Some(expected) = expected
                && size != expected
            {
                return Err(CacheError::SizeMismatch {
                    expected,
                    actual: size,
                });
            }
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|source| CacheError::Io {
                operation: "write partial artifact",
                path: partial.to_path_buf(),
                source,
            })?;
        Sha2Digest::update(&mut *sha256, &buffer[..read]);
        Md5Digest::update(&mut *md5, &buffer[..read]);
        size = size.saturating_add(read as u64);
        if at_limit {
            return match expected {
                Some(expected) => Err(CacheError::SizeMismatch {
                    expected,
                    actual: size,
                }),
                None => Err(CacheError::InputTooLarge { limit }),
            };
        }
    }
    Ok(size)
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

fn publish_object_with_fs(
    partial: &Path,
    object: &Path,
    expected: &Sha256Digest,
    expected_size: u64,
    fs_ops: &dyn PublishFs,
) -> Result<(), CacheError> {
    if object.exists() {
        if validate_object(object, expected, expected_size).is_ok() {
            fs_ops
                .remove_file(partial)
                .map_err(|source| CacheError::Io {
                    operation: "remove losing partial",
                    path: partial.to_path_buf(),
                    source,
                })?;
            return make_read_only(object);
        }
        let corrupt = object.with_file_name(format!(
            ".corrupt.{}-{}",
            object.file_name().unwrap().to_string_lossy(),
            unique_nonce()
        ));
        if let Err(source) = fs_ops.rename(object, &corrupt) {
            let _ = fs_ops.remove_file(partial);
            return Err(CacheError::Io {
                operation: "quarantine corrupt artifact object",
                path: object.to_path_buf(),
                source,
            });
        }
        if let Err(replacement) = fs_ops.rename(partial, object) {
            // The old bytes are still in `corrupt`. Remove only the moved
            // final partial, then restore the old object when its path is free.
            let _ = fs_ops.remove_file(partial);
            if !object.exists()
                && let Err(restore) = fs_ops.rename(&corrupt, object)
            {
                return Err(CacheError::ReplacementRecovery {
                    object: object.to_path_buf(),
                    quarantine: corrupt,
                    replacement,
                    restore,
                });
            }
            return Err(CacheError::Io {
                operation: "publish replacement artifact object",
                path: object.to_path_buf(),
                source: replacement,
            });
        }
        // The replacement is published before quarantine is removed. If this
        // cleanup fails, the new object remains committed and the old bytes
        // remain available under the quarantine path for diagnosis.
        fs_ops
            .remove_file(&corrupt)
            .map_err(|source| CacheError::Io {
                operation: "remove quarantined corrupt artifact object",
                path: corrupt,
                source,
            })?;
    } else {
        if let Err(source) = fs_ops.rename(partial, object) {
            let _ = fs_ops.remove_file(partial);
            return Err(CacheError::Io {
                operation: "publish artifact object",
                path: object.to_path_buf(),
                source,
            });
        }
    }
    make_read_only(object)
}

fn load_hit(
    paths: &CachePaths,
    descriptor_key: &str,
    artifact: &SourceArtifact,
    checksums: &Checksums,
) -> Result<Option<CachedArtifact>, CacheError> {
    if !paths.metadata.exists() {
        return Ok(None);
    }
    let metadata = read_metadata(&paths.metadata)?;
    if metadata.descriptor_key != descriptor_key
        || metadata.upstream_md5 != checksums.md5
        || metadata.upstream_sha256 != checksums.sha256
    {
        return Err(CacheError::InvalidMetadata {
            path: paths.metadata.clone(),
            reason: "descriptor does not match the requested artifact".to_owned(),
        });
    }
    if let Some(expected_size) = artifact.size
        && metadata.size != expected_size
    {
        return Err(CacheError::InvalidMetadata {
            path: paths.metadata.clone(),
            reason: "metadata size does not match the requested artifact".to_owned(),
        });
    }
    let object = paths.object(&metadata.object_sha256);
    let expected_size = artifact.size.unwrap_or(metadata.size);
    validate_object_full(&object, &metadata.object_sha256, checksums, expected_size)?;
    make_read_only(&object)?;
    Ok(Some(cached_artifact(paths, metadata)))
}

fn validate_object(
    path: &Path,
    expected: &Sha256Digest,
    expected_size: u64,
) -> Result<(), CacheError> {
    let mut input = File::open(path).map_err(|source| CacheError::Io {
        operation: "open cache object",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|source| CacheError::Io {
            operation: "validate cache object",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        Sha2Digest::update(&mut hasher, &buffer[..read]);
        size = size.saturating_add(read as u64);
    }
    let actual = hex_lower(&Sha2Digest::finalize(hasher));
    if size != expected_size || actual != expected.as_str() {
        return Err(CacheError::CorruptObject {
            path: path.to_path_buf(),
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

fn validate_object_full(
    path: &Path,
    expected: &Sha256Digest,
    checksums: &Checksums,
    expected_size: u64,
) -> Result<(), CacheError> {
    let mut input = File::open(path).map_err(|source| CacheError::Io {
        operation: "open cache object",
        path: path.to_path_buf(),
        source,
    })?;
    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|source| CacheError::Io {
            operation: "validate cache object checksums",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        Sha2Digest::update(&mut sha256, &buffer[..read]);
        Md5Digest::update(&mut md5, &buffer[..read]);
        size = size.saturating_add(read as u64);
    }
    if size != expected_size {
        return Err(CacheError::SizeMismatch {
            expected: expected_size,
            actual: size,
        });
    }
    let actual_sha = hex_lower(&Sha2Digest::finalize(sha256));
    if actual_sha != expected.as_str() {
        return Err(CacheError::CorruptObject {
            path: path.to_path_buf(),
            expected: expected.to_string(),
            actual: actual_sha,
        });
    }
    if let Some(upstream) = checksums.sha256.as_ref()
        && upstream.as_str() != actual_sha
    {
        return Err(CacheError::ChecksumMismatch {
            algorithm: "sha256",
            expected: upstream.to_string(),
            actual: actual_sha,
        });
    }
    let actual_md5 = hex_lower(&Md5Digest::finalize(md5));
    if let Some(upstream) = checksums.md5.as_deref()
        && upstream != actual_md5
    {
        return Err(CacheError::ChecksumMismatch {
            algorithm: "md5",
            expected: upstream.to_owned(),
            actual: actual_md5,
        });
    }
    Ok(())
}

fn validate_source_archive(path: &Path) -> Result<(), CacheError> {
    const MAX_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_ENTRIES: usize = 100_000;
    let input = File::open(path).map_err(|source| CacheError::Io {
        operation: "open source archive for sanity check",
        path: path.to_path_buf(),
        source,
    })?;
    let decoder = GzDecoder::new(input);
    let mut archive = Archive::new(decoder);
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for (index, entry) in archive
        .entries()
        .map_err(|source| CacheError::InvalidArchive {
            reason: source.to_string(),
        })?
        .enumerate()
    {
        if index >= MAX_ENTRIES {
            return Err(CacheError::InvalidArchive {
                reason: "archive contains too many entries".to_owned(),
            });
        }
        let mut entry = entry.map_err(|source| CacheError::InvalidArchive {
            reason: source.to_string(),
        })?;
        let remaining = MAX_UNCOMPRESSED_BYTES.saturating_sub(total);
        let copied = io::copy(
            &mut entry.by_ref().take(remaining.saturating_add(1)),
            &mut io::sink(),
        )
        .map_err(|source| CacheError::InvalidArchive {
            reason: source.to_string(),
        })?;
        total = total.saturating_add(copied);
        entries += 1;
        if copied > remaining || total > MAX_UNCOMPRESSED_BYTES {
            return Err(CacheError::InvalidArchive {
                reason: "archive exceeds sanity-check size limit".to_owned(),
            });
        }
    }
    if entries == 0 {
        return Err(CacheError::InvalidArchive {
            reason: "archive contains no entries".to_owned(),
        });
    }
    Ok(())
}

fn commit_metadata(path: &Path, metadata: &Metadata) -> Result<(), CacheError> {
    let temp = path.with_file_name(format!(
        "{}.tmp.{}",
        path.file_name().unwrap().to_string_lossy(),
        unique_nonce()
    ));
    let mut output = open_file(&temp, true, "create metadata temporary")?;
    let file = MetadataFile {
        version: metadata.version,
        descriptor_key: metadata.descriptor_key.clone(),
        object_sha256: metadata.object_sha256.to_string(),
        size: metadata.size,
        upstream_md5: metadata.upstream_md5.clone(),
        upstream_sha256: metadata.upstream_sha256.as_ref().map(ToString::to_string),
        verification_strength: metadata.verification_strength.clone(),
    };
    let encoded =
        serde_json::to_vec_pretty(&file).map_err(|source| CacheError::InvalidMetadata {
            path: temp.clone(),
            reason: source.to_string(),
        })?;
    let result = (|| {
        output
            .write_all(&encoded)
            .map_err(|source| CacheError::Io {
                operation: "write metadata temporary",
                path: temp.clone(),
                source,
            })?;
        output.sync_all().map_err(|source| CacheError::Io {
            operation: "sync metadata temporary",
            path: temp.clone(),
            source,
        })?;
        drop(output);
        fs::rename(&temp, path).map_err(|source| CacheError::Io {
            operation: "commit artifact metadata",
            path: path.to_path_buf(),
            source,
        })?;
        sync_directory(path.parent().expect("metadata has a parent"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn read_metadata(path: &Path) -> Result<Metadata, CacheError> {
    let contents = fs::read_to_string(path).map_err(|source| CacheError::Io {
        operation: "read artifact metadata",
        path: path.to_path_buf(),
        source,
    })?;
    let file: MetadataFile =
        serde_json::from_str(&contents).map_err(|source| CacheError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: source.to_string(),
        })?;
    if file.version != 1 {
        return Err(CacheError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: "unknown metadata version".to_owned(),
        });
    }
    let object_sha256 =
        Sha256Digest::new(&file.object_sha256).map_err(|_| CacheError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: "invalid object digest".to_owned(),
        })?;
    let upstream_md5 = if let Some(value) = file.upstream_md5 {
        validate_md5(&value)?;
        Some(value.to_ascii_lowercase())
    } else {
        None
    };
    let upstream_sha256 = file
        .upstream_sha256
        .as_deref()
        .map(|value| {
            Sha256Digest::new(value).map_err(|_| CacheError::InvalidMetadata {
                path: path.to_path_buf(),
                reason: "invalid upstream SHA-256".to_owned(),
            })
        })
        .transpose()?;
    let expected_strength = verification_strength(&Checksums {
        md5: upstream_md5.clone(),
        sha256: upstream_sha256.clone(),
    });
    if file.verification_strength != expected_strength {
        return Err(CacheError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: "verification strength does not match checksum fields".to_owned(),
        });
    }
    Ok(Metadata {
        version: file.version,
        descriptor_key: file.descriptor_key,
        object_sha256,
        size: file.size,
        upstream_md5,
        upstream_sha256,
        verification_strength: file.verification_strength,
    })
}

fn validate_checksums(values: &[UpstreamChecksum]) -> Result<Checksums, CacheError> {
    let mut md5 = None;
    let mut sha256 = None;
    for value in values {
        match value {
            UpstreamChecksum::Md5(value) => {
                validate_md5(value)?;
                let canonical = value.to_ascii_lowercase();
                if md5
                    .as_deref()
                    .is_some_and(|existing| existing != canonical.as_str())
                {
                    return Err(CacheError::ConflictingChecksum { algorithm: "md5" });
                }
                md5 = Some(canonical);
            }
            UpstreamChecksum::Sha256(value) => {
                if sha256.as_ref().is_some_and(|existing| existing != value) {
                    return Err(CacheError::ConflictingChecksum {
                        algorithm: "sha256",
                    });
                }
                sha256 = Some(value.clone());
            }
            UpstreamChecksum::Other { algorithm, .. } => {
                match algorithm.to_ascii_lowercase().as_str() {
                    "md5" => {
                        return Err(CacheError::MalformedChecksum {
                            algorithm: "md5",
                            value: "unsupported declaration shape".to_owned(),
                        });
                    }
                    "sha256" | "sha-256" => {
                        return Err(CacheError::MalformedChecksum {
                            algorithm: "sha256",
                            value: "unsupported declaration shape".to_owned(),
                        });
                    }
                    _ => {
                        return Err(CacheError::UnsupportedChecksum {
                            algorithm: algorithm.to_string(),
                        });
                    }
                }
            }
        }
    }
    Ok(Checksums { md5, sha256 })
}

fn validate_md5(value: &str) -> Result<(), CacheError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CacheError::MalformedChecksum {
            algorithm: "md5",
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn descriptor_key(artifact: &SourceArtifact, checksums: &Checksums) -> String {
    let mut bytes = b"nrr/source-artifact/v1\0".to_vec();
    append_field(&mut bytes, artifact.locator.as_str().as_bytes());
    append_field(
        &mut bytes,
        checksums.md5.as_deref().unwrap_or("").as_bytes(),
    );
    append_field(
        &mut bytes,
        checksums
            .sha256
            .as_ref()
            .map(Sha256Digest::as_str)
            .unwrap_or("")
            .as_bytes(),
    );
    append_field(
        &mut bytes,
        artifact
            .size
            .map(|size| size.to_string())
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    let digest = Sha256::digest(bytes);
    hex_lower(&digest)
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

fn cached_artifact(paths: &CachePaths, metadata: Metadata) -> CachedArtifact {
    let verification = match (
        metadata.upstream_md5.is_some(),
        metadata.upstream_sha256.is_some(),
    ) {
        (false, false) => VerificationStrength::None,
        (true, false) => VerificationStrength::UpstreamMd5,
        (false, true) => VerificationStrength::UpstreamSha256,
        (true, true) => VerificationStrength::UpstreamMd5AndSha256,
    };
    CachedArtifact {
        object_path: paths.object(&metadata.object_sha256),
        metadata_path: paths.metadata.clone(),
        sha256: metadata.object_sha256,
        size: metadata.size,
        verification,
    }
}

fn verification_strength(checksums: &Checksums) -> &'static str {
    match (checksums.md5.is_some(), checksums.sha256.is_some()) {
        (false, false) => "none",
        (true, false) => "upstream-md5",
        (false, true) => "upstream-sha256",
        (true, true) => "upstream-md5-and-sha256",
    }
}

fn open_file(path: &Path, create_new: bool, operation: &'static str) -> Result<File, CacheError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    options.open(path).map_err(|source| CacheError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })
}

fn make_read_only(path: &Path) -> Result<(), CacheError> {
    let mut permissions = fs::metadata(path)
        .map_err(|source| CacheError::Io {
            operation: "inspect published object",
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(|source| CacheError::Io {
        operation: "make published object read-only",
        path: path.to_path_buf(),
        source,
    })
}

fn sync_directory(path: &Path) -> Result<(), CacheError> {
    match File::open(path).and_then(|directory| directory.sync_all()) {
        Ok(()) => Ok(()),
        Err(source)
            if matches!(
                source.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ) =>
        {
            Ok(())
        }
        Err(source) => Err(CacheError::Io {
            operation: "sync cache directory",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn unique_nonce() -> String {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{}", std::process::id(), time.as_nanos())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::cell::Cell;
    use std::io::Cursor;
    use tar::{Builder, Header};

    fn temporary_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "nrr-repository-{label}-{}-{}",
            std::process::id(),
            unique_nonce()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn artifact(checksums: Vec<UpstreamChecksum>, size: Option<u64>) -> SourceArtifact {
        SourceArtifact {
            locator: nrr_core::ArtifactLocator::new("fixture://source/example").unwrap(),
            upstream_checksums: checksums,
            size,
        }
    }

    fn md5(bytes: &[u8]) -> String {
        hex_lower(&Md5::digest(bytes))
    }

    fn archive_bytes() -> Vec<u8> {
        archive_bytes_with("fixture source\n", "example/DESCRIPTION")
    }

    fn archive_bytes_with(contents: &str, name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        let encoder = GzEncoder::new(&mut encoded, Compression::default());
        let mut builder = Builder::new(encoder);
        let contents = contents.as_bytes();
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, contents).unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
        encoded
    }

    fn empty_archive_bytes() -> Vec<u8> {
        let mut encoded = Vec::new();
        let encoder = GzEncoder::new(&mut encoded, Compression::default());
        Builder::new(encoder)
            .into_inner()
            .unwrap()
            .finish()
            .unwrap();
        encoded
    }

    fn contains_file_named(root: &Path, suffix: &str) -> bool {
        let Ok(entries) = fs::read_dir(root) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                contains_file_named(&path, suffix)
            } else {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(suffix))
            }
        })
    }

    fn contains_file_prefix(root: &Path, prefix: &str) -> bool {
        let Ok(entries) = fs::read_dir(root) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                contains_file_prefix(&path, prefix)
            } else {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
            }
        })
    }

    #[test]
    fn commits_and_reuses_without_reading_a_hit_stream() {
        let root = temporary_root("hit");
        let bytes = archive_bytes();
        let artifact = artifact(
            vec![UpstreamChecksum::Md5(md5(&bytes).into())],
            Some(bytes.len() as u64),
        );
        let first = commit_source_artifact(&root, &artifact, Cursor::new(bytes.clone())).unwrap();
        let reads = Cell::new(false);
        let mut reader = TrackingReader { reads: &reads };
        let second = commit_artifact(ArtifactCommitRequest {
            cache_root: &root,
            artifact: &artifact,
            reader: &mut reader,
        })
        .unwrap();
        assert_eq!(first, second);
        assert!(!reads.get());
        assert!(
            fs::metadata(&first.object_path)
                .unwrap()
                .permissions()
                .readonly()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_mismatches_and_does_not_commit_metadata() {
        for (label, checksums, size) in [
            (
                "md5",
                vec![UpstreamChecksum::Md5(
                    "00000000000000000000000000000000".into(),
                )],
                None,
            ),
            (
                "sha256",
                vec![UpstreamChecksum::Sha256(
                    Sha256Digest::new("0".repeat(64)).unwrap(),
                )],
                None,
            ),
            ("size", vec![], Some(99)),
        ] {
            let root = temporary_root(label);
            let descriptor = artifact(checksums, size);
            let error = commit_source_artifact(&root, &descriptor, Cursor::new(archive_bytes()))
                .unwrap_err();
            assert!(matches!(
                error,
                CacheError::ChecksumMismatch { .. } | CacheError::SizeMismatch { .. }
            ));
            assert!(!contains_file_named(&root.join("artifacts"), ".json"));
            assert!(!contains_file_prefix(
                &root.join("objects/sources/sha256"),
                PARTIAL_PREFIX
            ));
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn rejects_malformed_and_unsupported_checksums() {
        let root = temporary_root("checksum");
        let malformed = artifact(vec![UpstreamChecksum::Md5("bad".into())], None);
        assert!(matches!(
            commit_source_artifact(&root, &malformed, Cursor::new(archive_bytes())),
            Err(CacheError::MalformedChecksum { .. })
        ));
        let unsupported = artifact(
            vec![UpstreamChecksum::Other {
                algorithm: "sha1".into(),
                value: "anything".into(),
            }],
            None,
        );
        assert!(matches!(
            commit_source_artifact(&root, &unsupported, Cursor::new(archive_bytes())),
            Err(CacheError::UnsupportedChecksum { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_case_insensitive_duplicate_md5_declarations() {
        let root = temporary_root("md5-case");
        let bytes = archive_bytes();
        let digest = md5(&bytes);
        let descriptor = artifact(
            vec![
                UpstreamChecksum::Md5(digest.to_ascii_uppercase().into()),
                UpstreamChecksum::Md5(digest.into()),
            ],
            Some(bytes.len() as u64),
        );
        assert!(commit_source_artifact(&root, &descriptor, Cursor::new(bytes)).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_invalid_and_empty_archives() {
        let root = temporary_root("archive-shape");
        let descriptor = artifact(vec![], None);
        for bytes in [b"not gzip".to_vec(), empty_archive_bytes()] {
            assert!(matches!(
                commit_source_artifact(&root, &descriptor, Cursor::new(bytes)),
                Err(CacheError::InvalidArchive { .. })
            ));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hit_revalidates_upstream_sha_when_metadata_points_to_another_object() {
        let root = temporary_root("tampered-metadata");
        let first_bytes = archive_bytes();
        let first_sha = Sha256::digest(&first_bytes);
        let first = artifact(
            vec![UpstreamChecksum::Sha256(
                Sha256Digest::new(hex_lower(&first_sha)).unwrap(),
            )],
            Some(first_bytes.len() as u64),
        );
        let committed =
            commit_source_artifact(&root, &first, Cursor::new(first_bytes.clone())).unwrap();
        let other_bytes = archive_bytes_with("different fixture\n", "other/DESCRIPTION");
        let other =
            commit_source_artifact(&root, &artifact(vec![], None), Cursor::new(other_bytes))
                .unwrap();
        let mut metadata = fs::read_to_string(&committed.metadata_path).unwrap();
        metadata = metadata.replace(
            &format!("\"object_sha256\": \"{}\"", committed.sha256.as_str()),
            &format!("\"object_sha256\": \"{}\"", other.sha256.as_str()),
        );
        fs::write(&committed.metadata_path, metadata).unwrap();
        let reads = Cell::new(false);
        let mut reader = TrackingReader { reads: &reads };
        let error = commit_artifact(ArtifactCommitRequest {
            cache_root: &root,
            artifact: &first,
            reader: &mut reader,
        })
        .unwrap_err();
        assert!(matches!(error, CacheError::ChecksumMismatch { .. }));
        assert!(!reads.get());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_from_an_unrelated_stale_partial() {
        let root = temporary_root("stale");
        let descriptor = artifact(vec![], None);
        let key = descriptor_key(
            &descriptor,
            &Checksums {
                md5: None,
                sha256: None,
            },
        );
        let paths = CachePaths::new(&root, &key);
        create_cache_directories(&paths).unwrap();
        fs::write(paths.object_dir.join(".partial.dead-process"), b"stale").unwrap();
        let bytes = archive_bytes();
        let result = commit_source_artifact(&root, &descriptor, Cursor::new(bytes.clone()));
        assert!(result.is_ok());
        assert!(paths.object_dir.join(".partial.dead-process").exists());
        let committed = result.unwrap();
        fs::remove_file(&committed.metadata_path).unwrap();
        let repaired = commit_source_artifact(&root, &descriptor, Cursor::new(bytes)).unwrap();
        assert_eq!(committed.object_path, repaired.object_path);
        assert!(repaired.metadata_path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn metadata_is_strict_json_and_rejects_unknown_fields() {
        let root = temporary_root("strict-metadata");
        let descriptor = artifact(vec![], None);
        let bytes = archive_bytes();
        let committed =
            commit_source_artifact(&root, &descriptor, Cursor::new(bytes.clone())).unwrap();
        let mut metadata = fs::read_to_string(&committed.metadata_path).unwrap();
        let end = metadata.rfind('}').unwrap();
        metadata.insert_str(end, ",\n  \"unexpected\": true\n");
        fs::write(&committed.metadata_path, metadata).unwrap();
        let error = commit_source_artifact(&root, &descriptor, Cursor::new(bytes)).unwrap_err();
        assert!(matches!(error, CacheError::InvalidMetadata { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hit_rejects_tampered_metadata_size_before_returning_a_handle() {
        let root = temporary_root("tampered-size");
        let bytes = archive_bytes();
        let digest = Sha256::digest(&bytes);
        let descriptor = artifact(
            vec![UpstreamChecksum::Sha256(
                Sha256Digest::new(hex_lower(&digest)).unwrap(),
            )],
            Some(bytes.len() as u64),
        );
        let committed =
            commit_source_artifact(&root, &descriptor, Cursor::new(bytes.clone())).unwrap();
        let mut metadata = fs::read_to_string(&committed.metadata_path).unwrap();
        metadata = metadata.replace(
            &format!("\"size\": {}", bytes.len()),
            &format!("\"size\": {}", bytes.len() + 1),
        );
        fs::write(&committed.metadata_path, metadata).unwrap();
        let reads = Cell::new(false);
        let mut reader = TrackingReader { reads: &reads };
        let error = commit_artifact(ArtifactCommitRequest {
            cache_root: &root,
            artifact: &descriptor,
            reader: &mut reader,
        })
        .unwrap_err();
        assert!(matches!(error, CacheError::InvalidMetadata { .. }));
        assert!(!reads.get());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_copy_checks_exact_boundary_and_stops_on_first_excess_byte() {
        for (input, expected, result, written, reads) in [
            (b"abc".as_slice(), Some(3), Ok(3), b"abc".as_slice(), 2),
            (
                b"abcd".as_slice(),
                Some(3),
                Err(CacheError::SizeMismatch {
                    expected: 3,
                    actual: 4,
                }),
                b"abcd".as_slice(),
                2,
            ),
            (
                b"ab".as_slice(),
                Some(3),
                Err(CacheError::SizeMismatch {
                    expected: 3,
                    actual: 2,
                }),
                b"ab".as_slice(),
                2,
            ),
        ] {
            let mut reader = CountingReader::new(input);
            let mut output = Vec::new();
            let mut sha256 = Sha256::new();
            let mut md5 = Md5::new();
            let actual = copy_compressed_input(
                &mut reader,
                &mut output,
                expected,
                3,
                Path::new("test-partial"),
                &mut sha256,
                &mut md5,
            );
            match result {
                Ok(size) => assert_eq!(actual.unwrap(), size),
                Err(expected_error) => {
                    assert_eq!(actual.unwrap_err().to_string(), expected_error.to_string())
                }
            }
            assert_eq!(output, written);
            assert_eq!(reader.reads.get(), reads);
        }
    }

    #[test]
    fn bounded_copy_reports_unbounded_limit_and_handles_u64_max_without_overflow() {
        let mut reader = CountingReader::new(b"abcd");
        let mut output = Vec::new();
        let mut sha256 = Sha256::new();
        let mut md5 = Md5::new();
        let error = copy_compressed_input(
            &mut reader,
            &mut output,
            None,
            3,
            Path::new("test-partial"),
            &mut sha256,
            &mut md5,
        )
        .unwrap_err();
        assert!(matches!(error, CacheError::InputTooLarge { limit: 3 }));
        assert_eq!(output, b"abcd");
        assert_eq!(reader.reads.get(), 2);

        let mut reader = CountingReader::new(b"");
        let mut output = Vec::new();
        let mut sha256 = Sha256::new();
        let mut md5 = Md5::new();
        let error = copy_compressed_input(
            &mut reader,
            &mut output,
            Some(u64::MAX),
            3,
            Path::new("test-partial"),
            &mut sha256,
            &mut md5,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CacheError::SizeMismatch {
                expected: u64::MAX,
                actual: 0
            }
        ));
    }

    #[test]
    fn bounded_expected_input_does_not_commit_or_read_past_first_excess_byte() {
        let root = temporary_root("bounded-input");
        let bytes = archive_bytes();
        let descriptor = artifact(vec![], Some(bytes.len() as u64));
        let mut input = bytes.clone();
        input.extend_from_slice(b"excess");
        let mut reader = CountingReader::new(&input);
        let error = commit_artifact(ArtifactCommitRequest {
            cache_root: &root,
            artifact: &descriptor,
            reader: &mut reader,
        })
        .unwrap_err();
        assert!(matches!(error, CacheError::SizeMismatch { .. }));
        assert_eq!(reader.reads.get(), 2);
        assert!(!contains_file_named(&root.join("artifacts"), ".json"));
        assert!(!contains_file_prefix(
            &root.join("objects/sources/sha256"),
            PARTIAL_PREFIX
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_replacement_restores_corrupt_object_and_cleans_partial() {
        let root = temporary_root("replacement-failure");
        let bytes = archive_bytes();
        let descriptor = artifact(vec![], Some(bytes.len() as u64));
        let key = descriptor_key(
            &descriptor,
            &Checksums {
                md5: None,
                sha256: None,
            },
        );
        let paths = CachePaths::new(&root, &key);
        create_cache_directories(&paths).unwrap();
        let digest = Sha256Digest::new(hex_lower(&Sha256::digest(&bytes))).unwrap();
        let object = paths.object(&digest);
        fs::create_dir_all(object.parent().unwrap()).unwrap();
        let old = b"old corrupt bytes";
        fs::write(&object, old).unwrap();
        let fs_ops = RenameFailureFs::new(2);
        let error = commit_artifact_with_fs(
            ArtifactCommitRequest {
                cache_root: &root,
                artifact: &descriptor,
                reader: &mut Cursor::new(bytes),
            },
            &fs_ops,
        )
        .unwrap_err();
        assert!(matches!(error, CacheError::Io { .. }));
        assert_eq!(fs::read(&object).unwrap(), old);
        assert!(!contains_file_prefix(&root, ".corrupt."));
        assert!(!contains_file_prefix(&root, PARTIAL_PREFIX));
        assert!(!paths.metadata.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_replacement_restore_retains_quarantine_and_cleans_partial() {
        let root = temporary_root("replacement-restore-failure");
        let bytes = archive_bytes();
        let descriptor = artifact(vec![], Some(bytes.len() as u64));
        let key = descriptor_key(
            &descriptor,
            &Checksums {
                md5: None,
                sha256: None,
            },
        );
        let paths = CachePaths::new(&root, &key);
        create_cache_directories(&paths).unwrap();
        let digest = Sha256Digest::new(hex_lower(&Sha256::digest(&bytes))).unwrap();
        let object = paths.object(&digest);
        fs::create_dir_all(object.parent().unwrap()).unwrap();
        let old = b"old corrupt bytes";
        fs::write(&object, old).unwrap();
        let fs_ops = RenameFailureFs::with_failures(2, 3);
        let error = commit_artifact_with_fs(
            ArtifactCommitRequest {
                cache_root: &root,
                artifact: &descriptor,
                reader: &mut Cursor::new(bytes),
            },
            &fs_ops,
        )
        .unwrap_err();
        let quarantine = match error {
            CacheError::ReplacementRecovery { quarantine, .. } => quarantine,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(!object.exists());
        assert_eq!(fs::read(&quarantine).unwrap(), old);
        assert!(!contains_file_prefix(&root, PARTIAL_PREFIX));
        assert!(!paths.metadata.exists());
        fs::remove_dir_all(root).unwrap();
    }

    struct CountingReader<'a> {
        bytes: &'a [u8],
        offset: usize,
        reads: Cell<usize>,
    }

    impl CountingReader<'_> {
        fn new(bytes: &[u8]) -> CountingReader<'_> {
            CountingReader {
                bytes,
                offset: 0,
                reads: Cell::new(0),
            }
        }
    }

    impl Read for CountingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            let available = self.bytes.len().saturating_sub(self.offset);
            let count = available.min(buffer.len());
            buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    struct RenameFailureFs {
        fail_at: [usize; 2],
        renames: Cell<usize>,
    }

    impl RenameFailureFs {
        fn new(fail_at: usize) -> Self {
            Self::with_failures(fail_at, usize::MAX)
        }

        fn with_failures(first: usize, second: usize) -> Self {
            Self {
                fail_at: [first, second],
                renames: Cell::new(0),
            }
        }
    }

    impl PublishFs for RenameFailureFs {
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            let count = self.renames.get() + 1;
            self.renames.set(count);
            if self.fail_at.contains(&count) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected rename failure",
                ));
            }
            fs::rename(from, to)
        }

        fn remove_file(&self, path: &Path) -> io::Result<()> {
            fs::remove_file(path)
        }
    }

    struct TrackingReader<'a> {
        reads: &'a Cell<bool>,
    }

    impl Read for TrackingReader<'_> {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.set(true);
            panic!("cache hit consumed reader")
        }
    }
}
