use std::fs;
use std::path::{Path, PathBuf};

use super::{CacheError, Sha256Digest};

pub(super) struct CachePaths {
    pub(super) lock: PathBuf,
    pub(super) object_dir: PathBuf,
    pub(super) metadata: PathBuf,
    pub(super) lock_dir: PathBuf,
}

impl CachePaths {
    pub(super) fn new(root: &Path, descriptor_key: &str) -> Self {
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

    pub(super) fn object(&self, digest: &Sha256Digest) -> PathBuf {
        self.object_dir
            .join(&digest.as_str()[..2])
            .join(digest.as_str())
    }

    pub(super) fn object_lock(&self, digest: &Sha256Digest) -> PathBuf {
        self.lock_dir
            .parent()
            .expect("lock shard has a parent")
            .join(&digest.as_str()[..2])
            .join(format!("{}.object.lock", digest.as_str()))
    }
}

pub(super) fn create_cache_directories(paths: &CachePaths) -> Result<(), CacheError> {
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
