//! Backend-neutral immutable source-tree validation and publication.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use cap_fs_ext::OpenOptionsExt as CapFsExtOpenOptionsExt;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SOURCE_SCHEMA: u32 = 1;
const MAX_ENTRIES: usize = 100_000;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_DEPTH: usize = 64;
const MAX_MARKER_BYTES: u64 = 16 * 1024;
const POLICY_REVISION: u32 = 1;
const MAX_CLEANUP_DEPTH: usize = MAX_PATH_DEPTH + 2;
const MAX_CLEANUP_NODES: usize = MAX_ENTRIES
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

    /// Opens a path relative to the directory capability validated for this
    /// view. Callers must apply any file-specific open policy to `options`.
    pub(crate) fn open_with(
        &self,
        path: impl AsRef<Path>,
        options: &CapOpenOptions,
    ) -> io::Result<cap_std::fs::File> {
        self.directory.open_with(path, options)
    }
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
    let parent = destination.parent().ok_or_else(|| TreeError::Io {
        reason: "source view has no parent".to_owned(),
    })?;
    ensure_directory(parent)?;
    let lock_path = parent.join(format!(
        ".{}.lock",
        destination.file_name().unwrap().to_string_lossy()
    ));
    let _lock = AdvisoryLock::acquire(&lock_path)?;
    match fs::symlink_metadata(destination) {
        Ok(stat) if stat.file_type().is_symlink() => {
            return Err(TreeError::InvalidMarker {
                path: destination.to_path_buf(),
            });
        }
        Ok(stat) if !stat.is_dir() => {
            return Err(TreeError::PublicationConflict {
                path: destination.to_path_buf(),
            });
        }
        Ok(_) => {
            return validate_existing_view(destination, binding);
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(io_error(error)),
        Err(_) => {}
    }

    let mut builder = TreeBuilder::new();
    for entry in entries {
        builder.add(entry)?;
    }
    let (validated, total) = builder.finish();
    let tree_digest = tree_digest(&validated);
    let staging = parent.join(format!(
        ".{}.partial",
        destination.file_name().unwrap().to_string_lossy()
    ));
    match fs::symlink_metadata(&staging) {
        Ok(stat) if stat.file_type().is_symlink() => {
            return Err(TreeError::InvalidMarker { path: staging });
        }
        Ok(stat) if !stat.is_dir() => {
            return Err(TreeError::PublicationConflict { path: staging });
        }
        Ok(_) => remove_tree_bounded(&staging)?,
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(io_error(error)),
        Err(_) => {}
    }
    ensure_directory(&staging)?;
    let tree = staging.join("tree");
    ensure_directory(&tree)?;
    for entry in &validated {
        let path = tree.join(&entry.path);
        if let Some(parent) = path.parent() {
            ensure_directory(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(io_error)?;
        file.write_all(&entry.bytes).map_err(io_error)?;
        #[cfg(unix)]
        if entry.executable {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).map_err(io_error)?;
        }
        file.sync_all().map_err(io_error)?;
    }
    sync_directories_bounded(&tree)?;
    let marker = staging.join("source.toml");
    let mut marker_file = File::create(&marker).map_err(io_error)?;
    let marker = SourceMarker::new(&tree_digest, validated.len(), total, binding)?;
    marker.write(&mut marker_file)?;
    marker_file.sync_all().map_err(io_error)?;
    sync_directory(&staging)?;
    fs::rename(&staging, destination).map_err(io_error)?;
    sync_directory(parent)?;
    validate_existing_view(destination, binding)
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

    fn write(&self, file: &mut File) -> Result<(), TreeError> {
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

    fn parse(path: &Path) -> Result<Self, TreeError> {
        let stat = fs::symlink_metadata(path).map_err(io_error)?;
        if stat.file_type().is_symlink() || stat.len() > MAX_MARKER_BYTES {
            return Err(invalid_marker(path));
        }
        let contents = String::from_utf8(
            read_bounded_file_with_limit(path, stat.len(), MAX_MARKER_BYTES)
                .map_err(|_| invalid_marker(path))?,
        )
        .map_err(|_| invalid_marker(path))?;
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

fn validate_existing_view(
    destination: &Path,
    binding: &ViewBinding,
) -> Result<ImmutableSourceView, TreeError> {
    let mut tree_path = None;
    for item in fs::read_dir(destination).map_err(io_error)? {
        let item = item.map_err(io_error)?;
        let path = item.path();
        let name = item.file_name();
        let stat = fs::symlink_metadata(&path).map_err(io_error)?;
        if stat.file_type().is_symlink() {
            return Err(invalid_marker(&path));
        }
        match name.to_str() {
            Some("tree") if stat.is_dir() => tree_path = Some(path),
            Some("source.toml") if stat.is_file() => {}
            _ => return Err(invalid_marker(&path)),
        }
    }
    let tree = tree_path.ok_or_else(|| invalid_marker(destination))?;
    let marker_path = destination.join("source.toml");
    if fs::symlink_metadata(&marker_path)
        .map_err(io_error)?
        .file_type()
        .is_symlink()
    {
        return Err(invalid_marker(&marker_path));
    }
    let marker_stat = fs::symlink_metadata(&marker_path).map_err(io_error)?;
    if marker_stat.len() > MAX_MARKER_BYTES {
        return Err(invalid_marker(&marker_path));
    }
    let marker = SourceMarker::parse(&marker_path)?;
    if marker.binding != *binding {
        return Err(invalid_marker(&marker_path));
    }
    let destination_dir =
        Dir::open_ambient_dir(destination, ambient_authority()).map_err(io_error)?;
    let directory = destination_dir
        .open_dir_nofollow("tree")
        .map_err(|_| invalid_marker(&tree))?;
    let mut builder = TreeBuilder::new();
    collect_files(&tree, &directory, Path::new(""), 0, &mut builder)?;
    let (entries, total_bytes) = builder.finish();
    let digest = tree_digest(&entries);
    if digest != marker.tree_digest || entries.len() != marker.entries {
        return Err(invalid_marker(&marker_path));
    }
    if total_bytes != marker.total_bytes {
        return Err(invalid_marker(&marker_path));
    }
    Ok(ImmutableSourceView {
        path: tree,
        directory: Arc::new(directory),
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
    if size > MAX_BLOB_BYTES {
        return Err(TreeError::BlobLimit);
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(MAX_BLOB_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_BLOB_BYTES {
        return Err(TreeError::BlobLimit);
    }
    Ok(bytes)
}

fn read_bounded_file_with_limit(path: &Path, size: u64, limit: u64) -> Result<Vec<u8>, TreeError> {
    if size > limit {
        return Err(TreeError::BlobLimit);
    }
    let file = File::open(path).map_err(io_error)?;
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

fn remove_tree_bounded(path: &Path) -> Result<(), TreeError> {
    fn visit(path: &Path, depth: usize, count: &mut usize) -> Result<(), TreeError> {
        if depth > MAX_CLEANUP_DEPTH {
            return Err(TreeError::EntryLimit);
        }
        *count = count.checked_add(1).ok_or(TreeError::EntryLimit)?;
        if *count > MAX_CLEANUP_NODES {
            return Err(TreeError::EntryLimit);
        }
        let stat = fs::symlink_metadata(path).map_err(io_error)?;
        if stat.file_type().is_symlink() {
            return Err(invalid_marker(path));
        }
        if stat.is_dir() {
            for item in fs::read_dir(path).map_err(io_error)? {
                visit(&item.map_err(io_error)?.path(), depth + 1, count)?;
            }
            fs::remove_dir(path).map_err(io_error)
        } else {
            fs::remove_file(path).map_err(io_error)
        }
    }
    visit(path, 0, &mut 0)
}

fn sync_directories_bounded(root: &Path) -> Result<(), TreeError> {
    fn sync(path: &Path, depth: usize, count: &mut usize) -> Result<(), TreeError> {
        if depth > MAX_PATH_DEPTH {
            return Err(TreeError::EntryLimit);
        }
        *count = count.checked_add(1).ok_or(TreeError::EntryLimit)?;
        if *count > MAX_CLEANUP_NODES {
            return Err(TreeError::EntryLimit);
        }
        let stat = fs::symlink_metadata(path).map_err(io_error)?;
        if stat.file_type().is_symlink() || !stat.is_dir() {
            return Err(invalid_marker(path));
        }
        for item in fs::read_dir(path).map_err(io_error)? {
            let child = item.map_err(io_error)?.path();
            let child_stat = fs::symlink_metadata(&child).map_err(io_error)?;
            if child_stat.file_type().is_symlink() {
                return Err(invalid_marker(&child));
            }
            if child_stat.is_dir() {
                sync(&child, depth + 1, count)?;
            }
        }
        sync_directory(path)
    }
    sync(root, 0, &mut 0)
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
