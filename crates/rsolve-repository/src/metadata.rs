use std::fs;
use std::io::Write;
use std::path::Path;

use rsolve_core::{Sha256Digest, SourceArtifact, UpstreamChecksum};
use sha2::{Digest as Sha2Digest, Sha256};

use super::{
    CacheError, CachePaths, CachedArtifact, Checksums, Metadata, MetadataFile, VerificationStrength,
};
use crate::util::{hex_lower, open_file, sync_directory, unique_nonce};

pub(super) fn validate_checksums(values: &[UpstreamChecksum]) -> Result<Checksums, CacheError> {
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

pub(super) fn validate_md5(value: &str) -> Result<(), CacheError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CacheError::MalformedChecksum {
            algorithm: "md5",
            value: value.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn descriptor_key(artifact: &SourceArtifact, checksums: &Checksums) -> String {
    let mut bytes = b"rsolve/source-artifact/v1\0".to_vec();
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
    let digest = <Sha256 as Sha2Digest>::digest(bytes);
    hex_lower(&digest)
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

pub(super) fn commit_metadata(path: &Path, metadata: &Metadata) -> Result<(), CacheError> {
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

pub(super) fn read_metadata(path: &Path) -> Result<Metadata, CacheError> {
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

pub(super) fn cached_artifact(paths: &CachePaths, metadata: Metadata) -> CachedArtifact {
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

pub(super) fn verification_strength(checksums: &Checksums) -> &'static str {
    match (checksums.md5.is_some(), checksums.sha256.is_some()) {
        (false, false) => "none",
        (true, false) => "upstream-md5",
        (false, true) => "upstream-sha256",
        (true, true) => "upstream-md5-and-sha256",
    }
}
