//! Backend-neutral immutable source-tree validation and publication.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use cap_fs_ext::OpenOptionsExt as CapFsExtOpenOptionsExt;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::cache_fs::{self, CapabilityLock, DirectoryCapability};

const SOURCE_SCHEMA: u32 = 1;
const MAX_ENTRIES: usize = 100_000;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
pub(crate) const MAX_PATH_DEPTH: usize = 64;
const MAX_MARKER_BYTES: u64 = 16 * 1024;
const POLICY_REVISION: u32 = 1;
pub(crate) const MAX_CLEANUP_DEPTH: usize = MAX_PATH_DEPTH + 2;
pub(crate) const MAX_CLEANUP_NODES: usize = MAX_ENTRIES
    .saturating_mul(MAX_PATH_DEPTH.saturating_add(1))
    .saturating_add(2);

const BASE_MARKER_KEYS: &[&str] = &[
    "schema",
    "policy",
    "binding_namespace",
    "tree_digest",
    "entries",
    "total_bytes",
];

/// Opaque backend facts bound to an immutable source view. The tree layer
/// intentionally does not interpret revision, URL, or object-format fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ViewBinding {
    namespace: String,
    facts: BTreeMap<String, String>,
}

/// Incremental source-tree validator used before backend blobs are fetched.
pub(crate) struct TreeBuilder {
    entries: Vec<TreeEntry>,
    seen: BTreeSet<String>,
    total: u64,
}

impl TreeBuilder {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            seen: BTreeSet::new(),
            total: 0,
        }
    }

    pub(crate) fn add(&mut self, entry: TreeEntry) -> Result<(), TreeError> {
        self.check_path(&entry.path)?;
        if entry.bytes.len() as u64 > MAX_BLOB_BYTES {
            return Err(TreeError::BlobLimit);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(TreeError::EntryLimit);
        }
        let key = entry.path.to_ascii_lowercase();
        if !self.seen.insert(key) {
            return Err(TreeError::PathCollision);
        }
        self.total = self
            .total
            .checked_add(entry.bytes.len() as u64)
            .ok_or(TreeError::TotalLimit)?;
        if self.total > MAX_TOTAL_BYTES {
            return Err(TreeError::TotalLimit);
        }
        self.entries.push(entry);
        Ok(())
    }

    pub(crate) fn check_path(&self, path: &str) -> Result<(), TreeError> {
        validate_path(path)?;
        if self.entries.len() >= MAX_ENTRIES {
            return Err(TreeError::EntryLimit);
        }
        let key = path.to_ascii_lowercase();
        let predecessor_is_collision = self
            .seen
            .range(..=key.clone())
            .next_back()
            .is_some_and(|existing| is_path_prefix(existing, &key));
        let successor_is_collision = self
            .seen
            .range(key.clone()..)
            .next()
            .is_some_and(|existing| is_path_prefix(&key, existing));
        if predecessor_is_collision || successor_is_collision {
            return Err(TreeError::PathCollision);
        }
        Ok(())
    }

    pub(crate) fn remaining_bytes(&self) -> u64 {
        MAX_TOTAL_BYTES.saturating_sub(self.total)
    }

    pub(crate) fn finish(mut self) -> (Vec<TreeEntry>, u64) {
        self.entries
            .sort_by(|left, right| left.path.cmp(&right.path));
        (self.entries, self.total)
    }
}

impl ViewBinding {
    pub(crate) fn new(
        namespace: impl Into<String>,
        facts: &[(&str, &str)],
    ) -> Result<Self, TreeError> {
        let namespace = namespace.into();
        if !valid_marker_atom(&namespace) {
            return Err(TreeError::InvalidMarker {
                path: PathBuf::new(),
            });
        }
        let mut values = BTreeMap::new();
        for &(key, value) in facts {
            if !valid_marker_atom(key)
                || value.contains(['\n', '\r', '"'])
                || values.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return Err(TreeError::InvalidMarker {
                    path: PathBuf::new(),
                });
            }
        }
        Ok(Self {
            namespace,
            facts: values,
        })
    }
}

/// A regular backend-neutral tree entry. Symlinks, gitlinks, and unknown
/// modes are intentionally not representable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TreeEntry {
    path: String,
    bytes: Vec<u8>,
    executable: bool,
}

impl TreeEntry {
    pub(crate) fn regular(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            bytes,
            executable: false,
        }
    }

    pub(crate) fn executable(mut self, executable: bool) -> Self {
        self.executable = executable;
        self
    }
}

/// An immutable source-view handle. It is a Git-independent tree path, not
/// an installable R source archive.
#[derive(Clone, Debug)]
pub struct ImmutableSourceView {
    path: PathBuf,
    directory: Arc<Dir>,
    entry_facts: Arc<BTreeMap<String, ValidatedEntry>>,
    tree_digest: String,
    entries: usize,
    total_bytes: u64,
}

impl PartialEq for ImmutableSourceView {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.tree_digest == other.tree_digest
            && self.entries == other.entries
            && self.total_bytes == other.total_bytes
    }
}

impl Eq for ImmutableSourceView {}

impl ImmutableSourceView {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn tree_digest(&self) -> &str {
        &self.tree_digest
    }

    pub fn entries(&self) -> usize {
        self.entries
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Reads a previously validated regular file through the retained tree
    /// capability and verifies that its size, mode, and content are unchanged.
    pub(crate) fn read_validated_file(
        &self,
        path: impl AsRef<Path>,
        limit: u64,
    ) -> Result<Vec<u8>, ValidatedFileError> {
        let relative = path
            .as_ref()
            .to_str()
            .ok_or(ValidatedFileError::NotValidated)?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let fact = self
            .entry_facts
            .get(&relative)
            .ok_or(ValidatedFileError::Missing)?;
        if fact.size > limit {
            return Err(ValidatedFileError::TooLarge { limit });
        }

        let mut options = CapOpenOptions::new();
        options.read(true);
        options.follow(FollowSymlinks::No);
        #[cfg(unix)]
        CapFsExtOpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
        let file = match self.directory.open_with(path, &options) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ValidatedFileError::Missing);
            }
            #[cfg(unix)]
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(ValidatedFileError::Symlink);
            }
            Err(error) => {
                return Err(ValidatedFileError::Io {
                    reason: error.to_string(),
                });
            }
        };
        let metadata = file.metadata().map_err(|error| ValidatedFileError::Io {
            reason: error.to_string(),
        })?;
        if !metadata.is_file() {
            return Err(ValidatedFileError::NotRegular);
        }
        if metadata.len() != fact.size || is_executable(&metadata) != fact.executable {
            return Err(ValidatedFileError::Changed);
        }
        let mut bytes = Vec::with_capacity(fact.size as usize);
        file.take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| ValidatedFileError::Io {
                reason: error.to_string(),
            })?;
        if bytes.len() as u64 != fact.size || blob_digest(&bytes) != fact.digest {
            return Err(ValidatedFileError::Changed);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedEntry {
    digest: [u8; 32],
    size: u64,
    executable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub(crate) enum ValidatedFileError {
    #[error("validated source-tree file is missing")]
    Missing,
    #[error("validated source-tree file is a symlink")]
    Symlink,
    #[error("validated source-tree file is not regular")]
    NotRegular,
    #[error("validated source-tree file exceeds the configured limit")]
    TooLarge { limit: u64 },
    #[error("source-tree file changed after validation")]
    Changed,
    #[error("source-tree file I/O failed: {reason}")]
    Io { reason: String },
    #[error("source-tree path was not validated")]
    NotValidated,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum TreeError {
    #[error("unsafe source-tree path")]
    UnsafePath,
    #[error("source-tree path is not normalized NFC")]
    NonCanonicalPath,
    #[error("source-tree path collides with another entry")]
    PathCollision,
    #[error("source-tree entry limit exceeded")]
    EntryLimit,
    #[error("source-tree byte limit exceeded")]
    TotalLimit,
    #[error("source-tree blob limit exceeded")]
    BlobLimit,
    #[error("source-tree publication conflict at {path}")]
    PublicationConflict { path: PathBuf },
    #[error("source-tree cache marker is invalid at {path}")]
    InvalidMarker { path: PathBuf },
    #[error("source-tree publication I/O failed: {reason}")]
    Io { reason: String },
    #[error("source-tree lock is unavailable")]
    LockUnavailable,
}

/// Validates and atomically publishes entries into `destination`.
#[cfg(test)]
pub(crate) fn publish<I>(
    destination: impl AsRef<Path>,
    entries: I,
) -> Result<ImmutableSourceView, TreeError>
where
    I: IntoIterator<Item = TreeEntry>,
{
    publish_with_binding(
        destination,
        entries,
        &ViewBinding::new("generic", &[]).expect("static binding"),
    )
}

pub(crate) fn publish_with_binding<I>(
    destination: impl AsRef<Path>,
    entries: I,
    binding: &ViewBinding,
) -> Result<ImmutableSourceView, TreeError>
where
    I: IntoIterator<Item = TreeEntry>,
{
    let destination = destination.as_ref();
    let parent_path = destination.parent().ok_or_else(|| TreeError::Io {
        reason: "source view has no parent".to_owned(),
    })?;
    let parent = DirectoryCapability::open_or_create(parent_path)
        .map_err(|error| cache_error_at(error, parent_path))?;
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(TreeError::NonCanonicalPath)?;
    let lock_name = format!(".{destination_name}.lock");
    let _lock = CapabilityLock::acquire(&parent, &lock_name)
        .map_err(|error| cache_error_at(error, &parent_path.join(&lock_name)))?;
    match parent.entry_metadata(destination_name) {
        Ok(stat) if stat.file_type().is_symlink() => return Err(invalid_marker(destination)),
        Ok(stat) if !stat.is_dir() => {
            return Err(TreeError::PublicationConflict {
                path: destination.to_path_buf(),
            });
        }
        Ok(_) => {
            let destination = parent
                .open_dir(destination_name)
                .map_err(|error| cache_error_at(error, destination))?;
            return validate_existing_view_cap(&destination, binding);
        }
        Err(cache_fs::CacheFsError::NotFound) => {}
        Err(error) => return Err(cache_error_at(error, destination)),
    }

    let mut builder = TreeBuilder::new();
    for entry in entries {
        builder.add(entry)?;
    }
    let (validated, total) = builder.finish();
    let tree_digest = tree_digest(&validated);
    let staging_name = format!(".{destination_name}.partial");
    match parent.entry_metadata(&staging_name) {
        Ok(stat) if stat.file_type().is_symlink() => {
            return Err(invalid_marker(&parent_path.join(&staging_name)));
        }
        Ok(stat) if !stat.is_dir() => {
            return Err(TreeError::PublicationConflict {
                path: parent_path.join(&staging_name),
            });
        }
        Ok(_) => parent
            .remove_tree_bounded(&staging_name, MAX_CLEANUP_DEPTH, MAX_CLEANUP_NODES)
            .map_err(|error| cache_error_at(error, &parent_path.join(&staging_name)))?,
        Err(cache_fs::CacheFsError::NotFound) => {}
        Err(error) => return Err(cache_error_at(error, &parent_path.join(&staging_name))),
    }
    let staging = parent
        .create_dir(&staging_name)
        .map_err(|error| cache_error_at(error, &parent_path.join(&staging_name)))?;
    let tree = staging
        .create_dir("tree")
        .map_err(|error| cache_error_at(error, &parent_path.join(&staging_name).join("tree")))?;
    for entry in &validated {
        let path = Path::new(&entry.path);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(TreeError::NonCanonicalPath)?;
        let file_parent = tree
            .open_or_create_path(path.parent().unwrap_or(Path::new("")))
            .map_err(cache_error)?;
        let mut file = file_parent.create_file_new(name).map_err(cache_error)?;
        file.write_all(&entry.bytes).map_err(io_error)?;
        #[cfg(unix)]
        if entry.executable {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(cap_std::fs::Permissions::from_std(
                fs::Permissions::from_mode(0o755),
            ))
            .map_err(io_error)?;
        }
        file.sync_all().map_err(io_error)?;
    }
    tree.sync_tree_bounded(MAX_PATH_DEPTH, MAX_CLEANUP_NODES)
        .map_err(|error| TreeError::Io {
            reason: format!("tree sync: {error}"),
        })?;
    let mut marker_file = staging
        .create_file_new("source.toml")
        .map_err(cache_error)?;
    let marker = SourceMarker::new(&tree_digest, validated.len(), total, binding)?;
    marker.write(&mut marker_file)?;
    marker_file.sync_all().map_err(io_error)?;
    staging.sync().map_err(|error| TreeError::Io {
        reason: format!("staging sync: {error}"),
    })?;
    parent
        .rename_noreplace(&staging_name, destination_name)
        .map_err(cache_error)?;
    parent.sync().map_err(|error| TreeError::Io {
        reason: format!("parent sync: {error}"),
    })?;
    let destination = parent.open_dir(destination_name).map_err(cache_error)?;
    validate_existing_view_cap(&destination, binding)
}

fn validate_path(path: &str) -> Result<(), TreeError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        || !path.is_ascii()
    {
        return Err(if !path.is_ascii() {
            TreeError::NonCanonicalPath
        } else {
            TreeError::UnsafePath
        });
    }
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() > MAX_PATH_DEPTH
        || components.iter().any(|component| {
            component.is_empty()
                || *component == "."
                || *component == ".."
                || component.eq_ignore_ascii_case(".git")
        })
    {
        return Err(TreeError::UnsafePath);
    }
    Ok(())
}

fn is_path_prefix(prefix: &str, path: &str) -> bool {
    path == prefix
        || (path.len() > prefix.len()
            && path.starts_with(prefix)
            && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceMarker {
    binding: ViewBinding,
    tree_digest: String,
    entries: usize,
    total_bytes: u64,
}

impl SourceMarker {
    fn new(
        digest: &str,
        entries: usize,
        total_bytes: u64,
        binding: &ViewBinding,
    ) -> Result<Self, TreeError> {
        Ok(Self {
            binding: binding.clone(),
            tree_digest: digest.to_owned(),
            entries,
            total_bytes,
        })
    }

    fn write(&self, file: &mut impl Write) -> Result<(), TreeError> {
        writeln!(file, "schema = {SOURCE_SCHEMA}").map_err(io_error)?;
        writeln!(file, "policy = {POLICY_REVISION}").map_err(io_error)?;
        writeln!(file, "binding_namespace = \"{}\"", self.binding.namespace).map_err(io_error)?;
        for (key, value) in &self.binding.facts {
            writeln!(file, "binding.{key} = \"{value}\"").map_err(io_error)?;
        }
        writeln!(file, "tree_digest = \"{}\"", self.tree_digest).map_err(io_error)?;
        writeln!(file, "entries = {}", self.entries).map_err(io_error)?;
        writeln!(file, "total_bytes = {}", self.total_bytes).map_err(io_error)?;
        Ok(())
    }

    fn parse(contents: &[u8], path: &Path) -> Result<Self, TreeError> {
        if contents.len() as u64 > MAX_MARKER_BYTES {
            return Err(invalid_marker(path));
        }
        let contents = String::from_utf8(contents.to_vec()).map_err(|_| invalid_marker(path))?;
        let mut fields = BTreeMap::new();
        let mut order = Vec::new();
        for line in contents.split_inclusive('\n') {
            let line = line
                .strip_suffix('\n')
                .ok_or_else(|| invalid_marker(path))?;
            let (key, value) = line.split_once(" = ").ok_or_else(|| invalid_marker(path))?;
            if fields.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(invalid_marker(path));
            }
            order.push(key.to_owned());
        }
        if fields.get("schema") != Some(&SOURCE_SCHEMA.to_string())
            || fields.get("policy") != Some(&POLICY_REVISION.to_string())
        {
            return Err(invalid_marker(path));
        }
        let mut expected_order = vec![
            "schema".to_owned(),
            "policy".to_owned(),
            "binding_namespace".to_owned(),
        ];
        let mut binding_keys = order
            .iter()
            .filter_map(|key| key.strip_prefix("binding.").map(str::to_owned))
            .collect::<Vec<_>>();
        let mut sorted_binding_keys = binding_keys.clone();
        sorted_binding_keys.sort();
        if binding_keys != sorted_binding_keys {
            return Err(invalid_marker(path));
        }
        expected_order.extend(binding_keys.drain(..).map(|key| format!("binding.{key}")));
        expected_order.extend(["tree_digest", "entries", "total_bytes"].map(str::to_owned));
        if order != expected_order {
            return Err(invalid_marker(path));
        }
        if !fields.keys().all(|key| {
            BASE_MARKER_KEYS.contains(&key.as_str())
                || key == "binding_namespace"
                || key.starts_with("binding.")
        }) {
            return Err(invalid_marker(path));
        }
        let quoted = |key: &str| {
            let value = fields.get(key).ok_or_else(|| invalid_marker(path))?;
            if value.len() < 2
                || !value.starts_with('"')
                || !value.ends_with('"')
                || value[1..value.len() - 1].contains('"')
            {
                return Err(invalid_marker(path));
            }
            Ok(value[1..value.len() - 1].to_owned())
        };
        let digest = quoted("tree_digest")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid_marker(path));
        }
        let entries: usize = fields
            .get("entries")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| invalid_marker(path))?;
        if entries.to_string() != *fields.get("entries").ok_or_else(|| invalid_marker(path))? {
            return Err(invalid_marker(path));
        }
        let total_bytes: u64 = fields
            .get("total_bytes")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| invalid_marker(path))?;
        if total_bytes.to_string()
            != *fields
                .get("total_bytes")
                .ok_or_else(|| invalid_marker(path))?
        {
            return Err(invalid_marker(path));
        }
        let namespace = quoted("binding_namespace")?;
        if !valid_marker_atom(&namespace) {
            return Err(invalid_marker(path));
        }
        let mut facts = BTreeMap::new();
        for key in fields.keys().filter_map(|key| key.strip_prefix("binding.")) {
            if !valid_marker_atom(key)
                || facts
                    .insert(key.to_owned(), quoted(&format!("binding.{key}"))?)
                    .is_some()
            {
                return Err(invalid_marker(path));
            }
        }
        Ok(Self {
            binding: ViewBinding { namespace, facts },
            tree_digest: digest,
            entries,
            total_bytes,
        })
    }
}

fn invalid_marker(path: &Path) -> TreeError {
    TreeError::InvalidMarker {
        path: path.to_path_buf(),
    }
}

fn valid_marker_atom(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'_'
                || byte == b'-'
                || byte == b'.'
        })
}

fn validate_existing_view_cap(
    destination: &DirectoryCapability,
    binding: &ViewBinding,
) -> Result<ImmutableSourceView, TreeError> {
    for item in destination.entries().map_err(cache_error)? {
        let item = item.map_err(io_error)?;
        let name = item.file_name();
        let name = name.to_str().ok_or(TreeError::NonCanonicalPath)?;
        let stat = destination.entry_metadata(name).map_err(cache_error)?;
        if stat.file_type().is_symlink() {
            return Err(invalid_marker(&destination.path().join(name)));
        }
        match name {
            "tree" if stat.is_dir() => {}
            "tree" => return Err(invalid_marker(&destination.path().join(name))),
            "source.toml" if stat.is_file() => {}
            _ => return Err(invalid_marker(&destination.path().join(name))),
        }
    }
    let tree = destination
        .open_dir("tree")
        .map_err(|_| invalid_marker(&destination.path().join("tree")))?;
    let marker_path = destination.path().join("source.toml");
    let marker_stat = destination
        .entry_metadata("source.toml")
        .map_err(cache_error)?;
    if marker_stat.file_type().is_symlink() || marker_stat.len() > MAX_MARKER_BYTES {
        return Err(invalid_marker(&marker_path));
    }
    let marker_file = destination
        .open_file_read("source.toml")
        .map_err(cache_error)?;
    let marker_contents =
        read_bounded_cap_file_with_limit(marker_file, marker_stat.len(), MAX_MARKER_BYTES)?;
    let marker = SourceMarker::parse(&marker_contents, &marker_path)?;
    if marker.binding != *binding {
        return Err(invalid_marker(&marker_path));
    }
    let mut builder = TreeBuilder::new();
    collect_files(tree.path(), tree.as_dir(), Path::new(""), 0, &mut builder)?;
    let (entries, total_bytes) = builder.finish();
    let digest = tree_digest(&entries);
    if digest != marker.tree_digest || entries.len() != marker.entries {
        return Err(invalid_marker(&marker_path));
    }
    if total_bytes != marker.total_bytes {
        return Err(invalid_marker(&marker_path));
    }
    let entry_facts = entries
        .iter()
        .map(|entry| {
            (
                entry.path.clone(),
                ValidatedEntry {
                    digest: blob_digest(&entry.bytes),
                    size: entry.bytes.len() as u64,
                    executable: entry.executable,
                },
            )
        })
        .collect();
    Ok(ImmutableSourceView {
        path: tree.path().to_owned(),
        directory: Arc::new(tree.as_dir().try_clone().map_err(io_error)?),
        entry_facts: Arc::new(entry_facts),
        tree_digest: marker.tree_digest,
        entries: marker.entries,
        total_bytes: marker.total_bytes,
    })
}

fn collect_files(
    root: &Path,
    current: &Dir,
    relative_dir: &Path,
    depth: usize,
    builder: &mut TreeBuilder,
) -> Result<(), TreeError> {
    if depth > MAX_PATH_DEPTH {
        return Err(TreeError::EntryLimit);
    }
    let mut saw_entry = false;
    for item in current.entries().map_err(io_error)? {
        let item = item.map_err(io_error)?;
        saw_entry = true;
        let name = item.file_name();
        let name = name.to_str().ok_or(TreeError::NonCanonicalPath)?;
        let relative_path = relative_dir.join(name);
        let path = root.join(&relative_path);
        let file_type = item.file_type().map_err(io_error)?;
        if file_type.is_symlink() {
            return Err(invalid_marker(&path));
        }
        if file_type.is_dir() {
            let child = current
                .open_dir_nofollow(name)
                .map_err(|_| invalid_marker(&path))?;
            collect_files(root, &child, &relative_path, depth + 1, builder)?;
        } else if file_type.is_file() {
            let relative = relative_path
                .to_str()
                .ok_or(TreeError::NonCanonicalPath)?
                .replace(std::path::MAIN_SEPARATOR, "/");
            let file = open_tree_file(current, name, &path)?;
            let stat = file.metadata().map_err(io_error)?;
            if !stat.is_file() {
                return Err(invalid_marker(&path));
            }
            builder.check_path(&relative)?;
            let executable = is_executable(&stat);
            if stat.len() > MAX_BLOB_BYTES {
                return Err(TreeError::BlobLimit);
            }
            if stat.len() > builder.remaining_bytes() {
                return Err(TreeError::TotalLimit);
            }
            let bytes = read_bounded_cap_file(file, stat.len())?;
            builder.add(TreeEntry::regular(relative, bytes).executable(executable))?;
        } else {
            return Err(invalid_marker(&path));
        }
    }
    if relative_dir != Path::new("") && !saw_entry {
        return Err(invalid_marker(&root.join(relative_dir)));
    }
    Ok(())
}

fn open_tree_file(
    directory: &Dir,
    name: &str,
    path: &Path,
) -> Result<cap_std::fs::File, TreeError> {
    let mut options = CapOpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    #[cfg(unix)]
    CapFsExtOpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let file = directory.open_with(name, &options).map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err(invalid_marker(path));
    }
    Ok(file)
}

fn read_bounded_cap_file(file: cap_std::fs::File, size: u64) -> Result<Vec<u8>, TreeError> {
    read_bounded_cap_file_with_limit(file, size, MAX_BLOB_BYTES)
}

fn read_bounded_cap_file_with_limit(
    file: cap_std::fs::File,
    size: u64,
    limit: u64,
) -> Result<Vec<u8>, TreeError> {
    if size > limit {
        return Err(TreeError::BlobLimit);
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > limit {
        return Err(TreeError::BlobLimit);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn is_executable(stat: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::PermissionsExt;
    stat.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_stat: &cap_std::fs::Metadata) -> bool {
    false
}

fn tree_digest(entries: &[TreeEntry]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"rsolve/source-tree/v1");
    digest.update(POLICY_REVISION.to_be_bytes());
    for entry in entries {
        digest.update((entry.path.len() as u64).to_be_bytes());
        digest.update(entry.path.as_bytes());
        digest.update((entry.bytes.len() as u64).to_be_bytes());
        digest.update(&entry.bytes);
        digest.update([u8::from(entry.executable)]);
    }
    hex(&digest.finalize())
}

fn blob_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), TreeError> {
    #[cfg(not(windows))]
    {
        File::open(path)
            .map_err(io_error)?
            .sync_all()
            .map_err(io_error)
    }
    #[cfg(windows)]
    {
        let _ = path;
        Ok(())
    }
}

fn io_error(error: io::Error) -> TreeError {
    TreeError::Io {
        reason: error.to_string(),
    }
}

fn cache_error(error: cache_fs::CacheFsError) -> TreeError {
    cache_error_at(error, Path::new(""))
}

fn cache_error_at(error: cache_fs::CacheFsError, path: &Path) -> TreeError {
    match error {
        cache_fs::CacheFsError::UnsafePath => TreeError::UnsafePath,
        cache_fs::CacheFsError::NonCanonicalPath => TreeError::NonCanonicalPath,
        cache_fs::CacheFsError::NotFound => TreeError::Io {
            reason: "cache filesystem entry is missing".to_owned(),
        },
        cache_fs::CacheFsError::Symlink => TreeError::InvalidMarker {
            path: path.to_owned(),
        },
        cache_fs::CacheFsError::Conflict => TreeError::PublicationConflict {
            path: path.to_owned(),
        },
        cache_fs::CacheFsError::Limit => TreeError::EntryLimit,
        cache_fs::CacheFsError::LockUnavailable => TreeError::LockUnavailable,
        cache_fs::CacheFsError::UnsupportedRename => TreeError::Io {
            reason: "atomic no-replace rename is unavailable on this platform".to_owned(),
        },
        cache_fs::CacheFsError::Io { reason } => TreeError::Io { reason },
    }
}

pub(crate) fn ensure_directory(path: &Path) -> Result<(), TreeError> {
    match fs::symlink_metadata(path) {
        Ok(stat) if stat.file_type().is_symlink() => Err(invalid_marker(path)),
        Ok(stat) if stat.is_dir() => Ok(()),
        Ok(_) => Err(TreeError::PublicationConflict {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| TreeError::Io {
                reason: "directory has no parent".to_owned(),
            })?;
            ensure_directory(parent)?;
            fs::create_dir(path).map_err(io_error)
        }
        Err(error) => Err(io_error(error)),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) struct AdvisoryLock {
    file: File,
}

impl AdvisoryLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, TreeError> {
        reject_lock_symlink(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(io_error)?;
        file.lock().map_err(|_| TreeError::LockUnavailable)?;
        Ok(Self { file })
    }

    pub(crate) fn acquire_shared(path: &Path) -> Result<Self, TreeError> {
        reject_lock_symlink(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(io_error)?;
        file.lock_shared().map_err(|_| TreeError::LockUnavailable)?;
        Ok(Self { file })
    }
}

fn reject_lock_symlink(path: &Path) -> Result<(), TreeError> {
    match fs::symlink_metadata(path) {
        Ok(stat) if stat.file_type().is_symlink() || !stat.is_file() => {
            Err(TreeError::InvalidMarker {
                path: path.to_path_buf(),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

impl Drop for AdvisoryLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests;
