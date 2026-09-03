//! Backend-neutral capability filesystem primitives for cache publication.
//!
//! All operations after opening a root are relative to retained directory
//! handles. This module intentionally knows nothing about source-control
//! backends or source-tree validation policy.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub(crate) enum CacheFsError {
    #[error("cache filesystem path is unsafe")]
    UnsafePath,
    #[error("cache filesystem path is not canonical")]
    NonCanonicalPath,
    #[error("cache filesystem entry is a symlink")]
    Symlink,
    #[error("cache filesystem entry is missing")]
    NotFound,
    #[error("cache filesystem publication conflicts with an existing entry")]
    Conflict,
    #[error("cache filesystem operation exceeded its bound")]
    Limit,
    #[error("cache filesystem lock is unavailable")]
    LockUnavailable,
    #[error("cache filesystem no-replace rename is unavailable")]
    UnsupportedRename,
    #[error("cache filesystem I/O failed: {reason}")]
    Io { reason: String },
}

pub(crate) struct DirectoryCapability {
    dir: Dir,
    display_path: PathBuf,
}

impl DirectoryCapability {
    /// Opens an existing path one component at a time without following
    /// symlinks. This is the only ambient operation in this module.
    #[allow(dead_code)]
    pub(crate) fn open(path: &Path) -> Result<Self, CacheFsError> {
        #[cfg(windows)]
        {
            let dir = Dir::open_ambient_dir(path, cap_std::ambient_authority()).map_err(map_io)?;
            return Ok(Self {
                dir,
                display_path: path.to_owned(),
            });
        }
        #[cfg(not(windows))]
        {
            let (anchor, components): (&Path, Vec<String>) = if path.is_absolute() {
                (
                    Path::new("/"),
                    path.components()
                        .skip(1)
                        .map(component_name)
                        .collect::<Result<_, _>>()?,
                )
            } else {
                (
                    Path::new("."),
                    path.components()
                        .map(component_name)
                        .collect::<Result<_, _>>()?,
                )
            };
            let mut dir =
                Dir::open_ambient_dir(anchor, cap_std::ambient_authority()).map_err(io_error)?;
            for name in &components {
                dir = dir.open_dir_nofollow(name).map_err(map_io)?;
            }
            Ok(Self {
                dir,
                display_path: path.to_owned(),
            })
        }
    }

    pub(crate) fn open_or_create(path: &Path) -> Result<Self, CacheFsError> {
        #[cfg(windows)]
        {
            std::fs::create_dir_all(path).map_err(io_error)?;
            return Self::open(path);
        }
        #[cfg(not(windows))]
        {
            let (anchor, components): (&Path, Vec<String>) = if path.is_absolute() {
                (
                    Path::new("/"),
                    path.components()
                        .skip(1)
                        .map(component_name)
                        .collect::<Result<_, _>>()?,
                )
            } else {
                (
                    Path::new("."),
                    path.components()
                        .map(component_name)
                        .collect::<Result<_, _>>()?,
                )
            };
            let mut dir =
                Dir::open_ambient_dir(anchor, cap_std::ambient_authority()).map_err(io_error)?;
            let mut display_path = if path.is_absolute() {
                PathBuf::from("/")
            } else {
                PathBuf::from(".")
            };
            for name in &components {
                match dir.open_dir_nofollow(name) {
                    Ok(next) => dir = next,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        match dir.create_dir(name) {
                            Ok(()) => {}
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                            Err(error) => return Err(map_io(error)),
                        }
                        dir = dir.open_dir_nofollow(name).map_err(map_io)?;
                    }
                    Err(error) => return Err(map_io(error)),
                }
                display_path.push(name);
            }
            Ok(Self {
                dir,
                display_path: path.to_owned(),
            })
        }
    }

    pub(crate) fn from_dir(dir: Dir, display_path: PathBuf) -> Self {
        Self { dir, display_path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.display_path
    }

    pub(crate) fn open_dir(&self, name: &str) -> Result<Self, CacheFsError> {
        let dir = self.dir.open_dir_nofollow(name).map_err(map_io)?;
        Ok(Self {
            dir,
            display_path: self.display_path.join(name),
        })
    }

    pub(crate) fn create_dir(&self, name: &str) -> Result<Self, CacheFsError> {
        match self.dir.create_dir(name) {
            Ok(()) => self.open_dir(name),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => self.open_dir(name),
            Err(error) => Err(map_io(error)),
        }
    }

    pub(crate) fn open_or_create_path(&self, path: &Path) -> Result<Self, CacheFsError> {
        let mut current = Self::from_dir(
            self.dir.try_clone().map_err(io_error)?,
            self.display_path.clone(),
        );
        for component in path.components() {
            let name = component_name(component)?;
            current = current.create_dir(&name)?;
        }
        Ok(current)
    }

    pub(crate) fn entries(&self) -> Result<cap_std::fs::ReadDir, CacheFsError> {
        self.dir.entries().map_err(io_error)
    }

    pub(crate) fn entry_metadata(&self, name: &str) -> Result<cap_std::fs::Metadata, CacheFsError> {
        self.dir.symlink_metadata(name).map_err(map_io)
    }

    pub(crate) fn open_file_read(&self, name: &str) -> Result<cap_std::fs::File, CacheFsError> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        self.dir.open_with(name, &options).map_err(map_io)
    }

    pub(crate) fn create_file_new(&self, name: &str) -> Result<cap_std::fs::File, CacheFsError> {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        self.dir.open_with(name, &options).map_err(map_io)
    }

    pub(crate) fn remove_tree_bounded(
        &self,
        name: &str,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<(), CacheFsError> {
        self.remove_tree(name, 0, &mut 0, max_depth, max_nodes)
    }

    fn remove_tree(
        &self,
        name: &str,
        depth: usize,
        count: &mut usize,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<(), CacheFsError> {
        if depth > max_depth {
            return Err(CacheFsError::Limit);
        }
        *count = count.checked_add(1).ok_or(CacheFsError::Limit)?;
        if *count > max_nodes {
            return Err(CacheFsError::Limit);
        }
        let stat = self.entry_metadata(name)?;
        if stat.file_type().is_symlink() {
            return Err(CacheFsError::Symlink);
        }
        if stat.is_dir() {
            let child = self.open_dir(name)?;
            for item in child.entries()? {
                let item = item.map_err(io_error)?;
                let child_name = item
                    .file_name()
                    .to_str()
                    .ok_or(CacheFsError::NonCanonicalPath)?
                    .to_owned();
                child.remove_tree(&child_name, depth + 1, count, max_depth, max_nodes)?;
            }
            self.dir.remove_dir(name).map_err(map_io)
        } else {
            self.dir.remove_file(name).map_err(map_io)
        }
    }

    pub(crate) fn sync(&self) -> Result<(), CacheFsError> {
        #[cfg(unix)]
        {
            let dot = CString::new(".").expect("static string");
            // cap-std directory handles may be O_PATH handles on Linux. Open
            // a readable directory handle through that retained capability
            // before syncing it.
            let fd = unsafe {
                libc::openat(
                    std::os::fd::AsRawFd::as_raw_fd(&self.dir),
                    dot.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(map_io(io::Error::last_os_error()));
            }
            // SAFETY: fd was returned by openat and is owned by this scope.
            let result = unsafe { libc::fsync(fd) };
            // SAFETY: fd is no longer used after this point.
            unsafe { libc::close(fd) };
            if result == 0 {
                Ok(())
            } else {
                Err(map_io(io::Error::last_os_error()))
            }
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    pub(crate) fn sync_tree_bounded(
        &self,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<(), CacheFsError> {
        self.sync_tree(0, &mut 0, max_depth, max_nodes)
    }

    fn sync_tree(
        &self,
        depth: usize,
        count: &mut usize,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<(), CacheFsError> {
        if depth > max_depth {
            return Err(CacheFsError::Limit);
        }
        *count = count.checked_add(1).ok_or(CacheFsError::Limit)?;
        if *count > max_nodes {
            return Err(CacheFsError::Limit);
        }
        for item in self.entries()? {
            let item = item.map_err(io_error)?;
            let name = item
                .file_name()
                .to_str()
                .ok_or(CacheFsError::NonCanonicalPath)?
                .to_owned();
            let stat = self.entry_metadata(&name)?;
            if stat.file_type().is_symlink() {
                return Err(CacheFsError::Symlink);
            }
            if stat.is_dir() {
                self.open_dir(&name)?
                    .sync_tree(depth + 1, count, max_depth, max_nodes)?;
            }
        }
        self.sync()
    }

    /// Atomically rename without replacing an existing destination. Platforms
    /// without a primitive with these semantics fail closed.
    pub(crate) fn rename_noreplace(&self, from: &str, to: &str) -> Result<(), CacheFsError> {
        #[cfg(target_os = "linux")]
        {
            let from = CString::new(from).map_err(|_| CacheFsError::UnsafePath)?;
            let to = CString::new(to).map_err(|_| CacheFsError::UnsafePath)?;
            // SAFETY: names are NUL-free and the retained descriptor anchors
            // both the source and destination directory.
            let result = unsafe {
                libc::renameat2(
                    std::os::fd::AsRawFd::as_raw_fd(&self.dir),
                    from.as_ptr(),
                    std::os::fd::AsRawFd::as_raw_fd(&self.dir),
                    to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(map_io(io::Error::last_os_error()))
            }
        }
        #[cfg(target_os = "macos")]
        {
            let from = CString::new(from).map_err(|_| CacheFsError::UnsafePath)?;
            let to = CString::new(to).map_err(|_| CacheFsError::UnsafePath)?;
            // SAFETY: names are NUL-free and the retained descriptor anchors
            // both the source and destination directory.
            let result = unsafe {
                libc::renameatx_np(
                    std::os::fd::AsRawFd::as_raw_fd(&self.dir),
                    from.as_ptr(),
                    std::os::fd::AsRawFd::as_raw_fd(&self.dir),
                    to.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(map_io(io::Error::last_os_error()))
            }
        }
        #[cfg(windows)]
        {
            self.dir.rename(from, &self.dir, to).map_err(map_io)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = (from, to);
            Err(CacheFsError::UnsupportedRename)
        }
    }

    pub(crate) fn create_or_open_lock(&self, name: &str) -> Result<File, CacheFsError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        cap_fs_ext::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
        let file = self.dir.open_with(name, &options).map_err(map_io)?;
        let stat = file.metadata().map_err(io_error)?;
        if !stat.is_file() {
            return Err(CacheFsError::Conflict);
        }
        Ok(file.into_std())
    }

    pub(crate) fn as_dir(&self) -> &Dir {
        &self.dir
    }
}

pub(crate) struct CapabilityLock {
    file: File,
}

impl CapabilityLock {
    pub(crate) fn acquire(parent: &DirectoryCapability, name: &str) -> Result<Self, CacheFsError> {
        let file = parent.create_or_open_lock(name)?;
        file.lock().map_err(|_| CacheFsError::LockUnavailable)?;
        Ok(Self { file })
    }
}

impl Drop for CapabilityLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn component_name(component: Component<'_>) -> Result<String, CacheFsError> {
    match component {
        Component::CurDir => Ok(".".to_owned()),
        Component::Normal(name) => name
            .to_str()
            .map(str::to_owned)
            .ok_or(CacheFsError::NonCanonicalPath),
        Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
            Err(CacheFsError::UnsafePath)
        }
    }
}

fn map_io(error: io::Error) -> CacheFsError {
    match error.kind() {
        io::ErrorKind::AlreadyExists => CacheFsError::Conflict,
        #[cfg(unix)]
        _ if error.raw_os_error() == Some(libc::ELOOP) => CacheFsError::Symlink,
        io::ErrorKind::NotFound => CacheFsError::NotFound,
        _ => io_error(error),
    }
}

fn io_error(error: io::Error) -> CacheFsError {
    CacheFsError::Io {
        reason: error.to_string(),
    }
}
