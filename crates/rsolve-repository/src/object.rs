use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::Path;

use md5::{Digest as Md5Digest, Md5};
use rsolve_core::{Sha256Digest, SourceArtifact};
use sha2::{Digest as Sha2Digest, Sha256};

use super::{
    ArtifactValidationExpectation, CacheError, CachePaths, CachedArtifact, Checksums, Metadata,
    PublishFs,
};
use crate::archive::validate_source_archive;
use crate::input::copy_compressed_input;
use crate::metadata::{cached_artifact, commit_metadata, read_metadata, verification_strength};
use crate::util::{hex_lower, make_read_only, open_file, sync_directory, unique_nonce};

#[allow(clippy::too_many_arguments)]
pub(super) fn commit_miss(
    paths: &CachePaths,
    artifact: &SourceArtifact,
    checksums: &Checksums,
    descriptor_key: &str,
    reader: &mut dyn Read,
    partial: &Path,
    expectation: Option<&ArtifactValidationExpectation>,
    publish_fs: &dyn PublishFs,
) -> Result<CachedArtifact, CacheError> {
    let mut output = open_file(partial, true, "create partial artifact")?;
    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    let size = copy_compressed_input(
        reader,
        &mut output,
        artifact.size,
        super::MAX_COMPRESSED_INPUT_BYTES,
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
    validate_source_archive(partial, expectation)?;
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
    let final_partial =
        object.with_file_name(format!("{}{}", super::PARTIAL_PREFIX, unique_nonce()));
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
    } else if let Err(source) = fs_ops.rename(partial, object) {
        let _ = fs_ops.remove_file(partial);
        return Err(CacheError::Io {
            operation: "publish artifact object",
            path: object.to_path_buf(),
            source,
        });
    }
    make_read_only(object)
}

pub(super) fn load_hit(
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
