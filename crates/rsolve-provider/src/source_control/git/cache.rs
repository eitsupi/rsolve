//! Per-normalized-URL Git object cache and Git-to-tree adapter.

use std::io::Read;
use std::path::Path;

use rsolve_core::{GitCommitId, GitHashAlgorithm, RepositorySubdir};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{Backend, GitAcquisitionRequest, GitCommandRunner};
use crate::source_control::tree::{
    self, AdvisoryLock, ImmutableSourceView, TreeBuilder, TreeEntry, TreeError, ViewBinding,
};

const MAX_ORIGIN_BYTES: u64 = 16 * 1024;

/// A cached immutable source view and its validated Git facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedGitSource {
    url: rsolve_core::NormalizedGitUrl,
    commit: GitCommitId,
    view: ImmutableSourceView,
}

impl CachedGitSource {
    pub fn url(&self) -> &rsolve_core::NormalizedGitUrl {
        &self.url
    }

    pub fn commit(&self) -> &GitCommitId {
        &self.commit
    }

    pub fn view(&self) -> &ImmutableSourceView {
        &self.view
    }
}

#[derive(Debug, Error)]
pub enum GitCacheError {
    #[error(transparent)]
    Git(#[from] super::GitError),
    #[error(transparent)]
    Tree(#[from] TreeError),
    #[error("offline Git source view is unavailable")]
    OfflineSourceViewMiss,
    #[error("Git source cache metadata is invalid")]
    InvalidMetadata,
    #[error("Git object validation failed while {operation}")]
    ObjectCorrupt { operation: &'static str },
    #[error("unsupported Git tree entry mode {mode}")]
    UnsupportedEntry { mode: String },
    #[error("requested Git source subdirectory was not found or is empty")]
    SubdirectoryNotFound,
    #[error("Git source tree is empty")]
    EmptyTree,
}

pub(crate) fn acquire<R: GitCommandRunner>(
    backend: &Backend<R>,
    cache_root: &Path,
    request: &GitAcquisitionRequest,
    subdirectory: Option<&RepositorySubdir>,
) -> Result<CachedGitSource, GitCacheError> {
    super::validate_url(&request.url)?;
    let url_key = key("repository", request.url.as_str().as_bytes());
    let repository_root = cache_root
        .join("rsolve/vcs-v1/git/repositories")
        .join(&url_key);
    tree::ensure_directory(&repository_root)?;
    let repository_lock = repository_root.join("repository.lock");
    let repository_guard = AdvisoryLock::acquire(&repository_lock)?;
    let requested_algorithm = match &request.revision {
        super::GitRevisionRequest::Pinned(commit) => Some(commit.algorithm()),
        super::GitRevisionRequest::Requested(super::GitSelector::Rev(revision)) => {
            GitCommitId::new(revision)
                .ok()
                .map(|commit| commit.algorithm())
        }
        super::GitRevisionRequest::Requested(_) => None,
    };
    validate_origin(
        &repository_root.join("origin.toml"),
        &request.url,
        requested_algorithm,
    )?;
    let repository_dir = repository_root.join("repository.git");
    match std::fs::symlink_metadata(&repository_dir) {
        Ok(stat) if stat.file_type().is_symlink() || !stat.is_dir() => {
            return Err(GitCacheError::InvalidMetadata);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(GitCacheError::InvalidMetadata),
    }
    let mut local_request = request.clone();
    local_request.repository_dir = repository_dir.clone();
    let acquisition = backend.acquire(&local_request)?;
    write_origin(
        &repository_root.join("origin.toml"),
        &request.url,
        acquisition.commit().algorithm(),
        request.offline,
    )?;
    drop(repository_guard);

    let algorithm = match acquisition.commit().algorithm() {
        GitHashAlgorithm::Sha1 => "sha1",
        GitHashAlgorithm::Sha256 => "sha256",
    };
    let subdir_key = key(
        "subdirectory",
        subdirectory
            .map(|value| value.as_str().as_bytes())
            .unwrap_or_default(),
    );
    let source_root = cache_root
        .join("rsolve/vcs-v1/git/sources")
        .join(&url_key)
        .join(algorithm)
        .join(acquisition.commit().as_str())
        .join(&subdir_key);
    tree::ensure_directory(source_root.parent().expect("source has parent"))?;
    let mut source_key = Vec::new();
    append_key_part(&mut source_key, request.url.as_str().as_bytes());
    append_key_part(&mut source_key, url_key.as_bytes());
    append_key_part(&mut source_key, algorithm.as_bytes());
    append_key_part(&mut source_key, acquisition.commit().as_str().as_bytes());
    append_key_part(
        &mut source_key,
        subdirectory
            .map(|value| value.as_str().as_bytes())
            .unwrap_or_default(),
    );
    let source_lock = cache_root
        .join("rsolve/vcs-v1/git/source-locks")
        .join(format!("{}.lock", key("source", &source_key)));
    if let Some(parent) = source_lock.parent() {
        tree::ensure_directory(parent)?;
    }
    let _repository_shared = AdvisoryLock::acquire_shared(&repository_lock)?;
    let _source_guard = AdvisoryLock::acquire(&source_lock)?;
    if request.offline {
        match std::fs::symlink_metadata(&source_root) {
            Ok(stat) if stat.file_type().is_symlink() || !stat.is_dir() => {
                return Err(GitCacheError::Tree(TreeError::InvalidMarker {
                    path: source_root,
                }));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(GitCacheError::OfflineSourceViewMiss);
            }
            Err(error) => {
                return Err(GitCacheError::Tree(TreeError::Io {
                    reason: error.to_string(),
                }));
            }
        }
    }
    let tree_oid = commit_tree_oid(backend, &repository_dir, acquisition.commit())?;
    let entries = if request.offline {
        Vec::new()
    } else {
        read_tree_entries(backend, &repository_dir, acquisition.commit(), subdirectory)?
    };
    let subdir = subdirectory.map(|value| value.as_str()).unwrap_or("");
    let mut metadata = vec![
        ("url_key", url_key.as_str()),
        ("url", request.url.as_str()),
        ("algorithm", algorithm),
        ("commit", acquisition.commit().as_str()),
        ("subdirectory", subdir),
    ];
    metadata.push(("tree_oid", tree_oid.as_str()));
    let binding = ViewBinding::new("git", &metadata)?;
    let view = tree::publish_with_binding(&source_root, entries, &binding)?;
    Ok(CachedGitSource {
        url: acquisition.url().clone(),
        commit: acquisition.commit().clone(),
        view,
    })
}

fn read_tree_entries<R: GitCommandRunner>(
    backend: &Backend<R>,
    repository_dir: &Path,
    commit: &GitCommitId,
    subdirectory: Option<&RepositorySubdir>,
) -> Result<Vec<TreeEntry>, GitCacheError> {
    let mut args = vec![
        super::arg("--no-replace-objects"),
        super::arg("--literal-pathspecs"),
        super::arg("--git-dir"),
        repository_dir.as_os_str().to_os_string(),
        super::arg("ls-tree"),
        super::arg("-z"),
        super::arg("-r"),
        super::arg(commit.to_string()),
    ];
    if let Some(subdirectory) = subdirectory {
        args.push(super::arg("--"));
        args.push(super::arg(subdirectory.as_str()));
    }
    let output = backend
        .run_checked(args, "read Git tree", super::MAX_TREE_OUTPUT_BYTES)
        .map_err(|error| match error {
            super::GitError::OutputTooLarge { .. } => GitCacheError::Tree(TreeError::EntryLimit),
            _ => GitCacheError::ObjectCorrupt {
                operation: "reading commit tree",
            },
        })?;
    if !output.stdout.is_empty() && !output.stdout.ends_with(&[0]) {
        return Err(GitCacheError::ObjectCorrupt {
            operation: "parsing Git tree output",
        });
    }
    let prefix = subdirectory
        .map(|value| format!("{}/", value.as_str()))
        .unwrap_or_default();
    let mut builder = TreeBuilder::new();
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let Some(separator) = record.iter().position(|byte| *byte == b'\t') else {
            return Err(GitCacheError::ObjectCorrupt {
                operation: "parsing Git tree output",
            });
        };
        let (header, path_bytes) = record.split_at(separator);
        let path_bytes = &path_bytes[1..];
        let path = std::str::from_utf8(path_bytes)
            .map_err(|_| GitCacheError::Tree(TreeError::NonCanonicalPath))?;
        let mut tokens = header
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|part| !part.is_empty());
        let (Some(mode_bytes), Some(kind_bytes), Some(object_bytes)) =
            (tokens.next(), tokens.next(), tokens.next())
        else {
            return Err(GitCacheError::ObjectCorrupt {
                operation: "validating Git tree entry",
            });
        };
        if tokens.next().is_some() {
            return Err(GitCacheError::ObjectCorrupt {
                operation: "validating Git tree entry",
            });
        }
        let mode = std::str::from_utf8(mode_bytes).map_err(|_| GitCacheError::ObjectCorrupt {
            operation: "validating Git tree entry",
        })?;
        let kind = std::str::from_utf8(kind_bytes).map_err(|_| GitCacheError::ObjectCorrupt {
            operation: "validating Git tree entry",
        })?;
        let object =
            std::str::from_utf8(object_bytes).map_err(|_| GitCacheError::ObjectCorrupt {
                operation: "validating Git tree entry",
            })?;
        if mode != "100644" && mode != "100755" {
            return Err(GitCacheError::UnsupportedEntry {
                mode: mode.to_owned(),
            });
        }
        if kind != "blob" {
            return Err(GitCacheError::UnsupportedEntry {
                mode: mode.to_owned(),
            });
        }
        let object_id = GitCommitId::new(object).map_err(|_| GitCacheError::ObjectCorrupt {
            operation: "validating Git blob OID",
        })?;
        if object_id.algorithm() != commit.algorithm() {
            return Err(GitCacheError::ObjectCorrupt {
                operation: "validating Git blob hash algorithm",
            });
        }
        let relative = path
            .strip_prefix(&prefix)
            .ok_or(GitCacheError::Tree(TreeError::UnsafePath))?;
        builder.check_path(relative)?;
        let remaining = builder.remaining_bytes();
        let blob_limit = (remaining as usize)
            .saturating_add(1)
            .min(super::MAX_BLOB_OUTPUT_BYTES + 1);
        let blob = backend
            .run_checked(
                vec![
                    super::arg("--no-replace-objects"),
                    super::arg("--git-dir"),
                    repository_dir.as_os_str().to_os_string(),
                    super::arg("cat-file"),
                    super::arg("blob"),
                    super::arg(object_id.as_str()),
                ],
                "read Git blob",
                blob_limit,
            )
            .map_err(|error| match error {
                super::GitError::OutputTooLarge { .. } => {
                    GitCacheError::Tree(blob_overflow_error(remaining))
                }
                _ => GitCacheError::ObjectCorrupt {
                    operation: "reading Git blob",
                },
            })?;
        builder.add(
            TreeEntry::regular(relative.to_owned(), blob.stdout).executable(mode == "100755"),
        )?;
    }
    let entries = builder.finish().0;
    if entries.is_empty() {
        return Err(if subdirectory.is_some() {
            GitCacheError::SubdirectoryNotFound
        } else {
            GitCacheError::EmptyTree
        });
    }
    Ok(entries)
}

fn blob_overflow_error(remaining: u64) -> TreeError {
    if remaining < super::MAX_BLOB_OUTPUT_BYTES as u64 {
        TreeError::TotalLimit
    } else {
        TreeError::BlobLimit
    }
}

fn write_origin(
    path: &Path,
    url: &rsolve_core::NormalizedGitUrl,
    algorithm: rsolve_core::GitHashAlgorithm,
    offline: bool,
) -> Result<(), GitCacheError> {
    let algorithm = match algorithm {
        rsolve_core::GitHashAlgorithm::Sha1 => "sha1",
        rsolve_core::GitHashAlgorithm::Sha256 => "sha256",
    };
    let expected = format!("schema = 1\nurl = \"{url}\"\nalgorithm = \"{algorithm}\"\n");
    match std::fs::symlink_metadata(path) {
        Ok(stat) if stat.file_type().is_symlink() || !stat.is_file() => {
            return Err(GitCacheError::InvalidMetadata);
        }
        Ok(_) => {
            let actual = read_metadata(path)?;
            if actual != expected {
                return Err(GitCacheError::InvalidMetadata);
            }
            return Ok(());
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(GitCacheError::InvalidMetadata);
        }
        Err(_) if offline => return Err(GitCacheError::InvalidMetadata),
        Err(_) => {}
    }
    let staging = path.with_file_name(".origin.toml.partial");
    match std::fs::symlink_metadata(&staging) {
        Ok(stat) if stat.file_type().is_symlink() || !stat.is_file() => {
            return Err(GitCacheError::InvalidMetadata);
        }
        Ok(_) => std::fs::remove_file(&staging).map_err(|_| GitCacheError::InvalidMetadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(GitCacheError::InvalidMetadata),
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)
        .map_err(|error| TreeError::Io {
            reason: error.to_string(),
        })?;
    use std::io::Write;
    file.write_all(expected.as_bytes())
        .map_err(|error| TreeError::Io {
            reason: error.to_string(),
        })?;
    file.sync_all().map_err(|error| TreeError::Io {
        reason: error.to_string(),
    })?;
    std::fs::rename(&staging, path).map_err(|error| TreeError::Io {
        reason: error.to_string(),
    })?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .map_err(|error| TreeError::Io {
                reason: error.to_string(),
            })?
            .sync_all()
            .map_err(|error| TreeError::Io {
                reason: error.to_string(),
            })?;
    }
    Ok(())
}

fn validate_origin(
    path: &Path,
    url: &rsolve_core::NormalizedGitUrl,
    expected_algorithm: Option<rsolve_core::GitHashAlgorithm>,
) -> Result<(), GitCacheError> {
    match std::fs::symlink_metadata(path) {
        Ok(stat) if stat.file_type().is_symlink() || !stat.is_file() => {
            Err(GitCacheError::InvalidMetadata)
        }
        Ok(_) => {
            let contents = read_metadata(path)?;
            let mut lines = contents.lines();
            let expected_url = format!("url = \"{url}\"");
            if lines.next() != Some("schema = 1") || lines.next() != Some(expected_url.as_str()) {
                return Err(GitCacheError::InvalidMetadata);
            }
            let actual_algorithm = lines.next().ok_or(GitCacheError::InvalidMetadata)?;
            if !matches!(
                actual_algorithm,
                "algorithm = \"sha1\"" | "algorithm = \"sha256\""
            ) || lines.next().is_some()
            {
                return Err(GitCacheError::InvalidMetadata);
            }
            if let Some(expected_algorithm) = expected_algorithm {
                let expected = match expected_algorithm {
                    rsolve_core::GitHashAlgorithm::Sha1 => "algorithm = \"sha1\"",
                    rsolve_core::GitHashAlgorithm::Sha256 => "algorithm = \"sha256\"",
                };
                if actual_algorithm != expected {
                    return Err(GitCacheError::InvalidMetadata);
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(GitCacheError::InvalidMetadata),
    }
}

fn read_metadata(path: &Path) -> Result<String, GitCacheError> {
    let stat = std::fs::symlink_metadata(path).map_err(|_| GitCacheError::InvalidMetadata)?;
    if stat.file_type().is_symlink() || !stat.is_file() || stat.len() > MAX_ORIGIN_BYTES {
        return Err(GitCacheError::InvalidMetadata);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| GitCacheError::InvalidMetadata)?
        .take(MAX_ORIGIN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| GitCacheError::InvalidMetadata)?;
    if bytes.len() as u64 > MAX_ORIGIN_BYTES {
        return Err(GitCacheError::InvalidMetadata);
    }
    String::from_utf8(bytes).map_err(|_| GitCacheError::InvalidMetadata)
}

fn commit_tree_oid<R: GitCommandRunner>(
    backend: &Backend<R>,
    repository_dir: &Path,
    commit: &GitCommitId,
) -> Result<String, GitCacheError> {
    let output = backend
        .run_checked(
            vec![
                super::arg("--no-replace-objects"),
                super::arg("--git-dir"),
                repository_dir.as_os_str().to_os_string(),
                super::arg("rev-parse"),
                super::arg(format!("{commit}^{{tree}}")),
            ],
            "read Git commit tree",
            super::MAX_OUTPUT_BYTES,
        )
        .map_err(|_| GitCacheError::ObjectCorrupt {
            operation: "reading commit tree object",
        })?;
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| GitCacheError::InvalidMetadata)?
        .trim();
    let tree = GitCommitId::new(value).map_err(|_| GitCacheError::ObjectCorrupt {
        operation: "validating commit tree OID",
    })?;
    if tree.algorithm() != commit.algorithm() {
        return Err(GitCacheError::ObjectCorrupt {
            operation: "validating commit tree hash algorithm",
        });
    }
    Ok(tree.as_str().to_owned())
}

fn append_key_part(buffer: &mut Vec<u8>, part: &[u8]) {
    buffer.extend_from_slice(&(part.len() as u64).to_be_bytes());
    buffer.extend_from_slice(part);
}

fn key(namespace: &str, value: &[u8]) -> String {
    let mut bytes = b"rsolve/vcs-v1/git/".to_vec();
    bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests;
