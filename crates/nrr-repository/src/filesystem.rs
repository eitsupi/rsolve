use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::util::hex_lower;

use super::materialization::MaterializationError;

const GITIGNORE: &[u8] = b"*\n";
const GITIGNORE_NAME: &str = ".gitignore";

pub(super) fn directory_names(path: &Path) -> Result<HashSet<String>, MaterializationError> {
    let entries =
        fs::read_dir(path).map_err(|source| io_error("scan recovered repository", path, source))?;
    let mut names = HashSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read recovered repository", path, source))?;
        names.insert(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

pub(super) fn is_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
}

pub(super) fn transaction_conflict(path: &Path, reason: impl Into<String>) -> MaterializationError {
    MaterializationError::TransactionConflict {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

pub(super) fn ensure_gitignore(nrr: &Path) -> Result<(), MaterializationError> {
    let path = nrr.join(GITIGNORE_NAME);
    if path.exists() {
        if !is_regular_file(&path) {
            return Err(MaterializationError::InvalidInput {
                reason: format!("{} is not a regular file", path.display()),
            });
        }
        let existing =
            fs::read(&path).map_err(|source| io_error("read .nrr/.gitignore", &path, source))?;
        if existing != GITIGNORE {
            return Err(MaterializationError::InvalidInput {
                reason: format!("{} must contain exactly `*\\n`", path.display()),
            });
        }
        return Ok(());
    }
    fs::write(&path, GITIGNORE).map_err(|source| io_error("create .nrr/.gitignore", &path, source))
}

pub(super) fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

pub(super) fn ensure_directory(
    path: &Path,
    operation: &'static str,
) -> Result<(), MaterializationError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_dir() {
            return Err(MaterializationError::InvalidInput {
                reason: format!("{} is not a directory", path.display()),
            });
        }
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|source| io_error(operation, path, source))
}

pub(super) fn valid_filename_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub(super) fn hash_file(path: &Path) -> Result<String, MaterializationError> {
    let mut file =
        File::open(path).map_err(|source| io_error("open materialized artifact", path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("hash materialized artifact", path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

pub(super) fn copy_file(source: &Path, destination: &Path) -> Result<(), MaterializationError> {
    fs::copy(source, destination)
        .map_err(|error| io_error("copy cache object", destination, error))?;
    make_writable(destination)?;
    File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error("sync copied artifact", destination, error))
}

pub(super) fn clone_file(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        use std::os::raw::{c_int, c_ulong};
        let input = File::open(source)?;
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        const FICLONE: c_ulong = 0x4004_9409;
        unsafe extern "C" {
            fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        }
        let result = unsafe { ioctl(output.as_raw_fd(), FICLONE, input.as_raw_fd()) };
        if result != 0 {
            let error = io::Error::last_os_error();
            drop(output);
            let _ = fs::remove_file(destination);
            return Err(error);
        }
        output.sync_all()?;
        drop(output);
        make_writable_io(destination)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "reflink clone is unavailable on this target",
        ))
    }
}

fn make_writable(path: &Path) -> Result<(), MaterializationError> {
    make_writable_io(path)
        .map_err(|source| io_error("make materialized artifact writable", path, source))
}

fn make_writable_io(path: &Path) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(permissions.mode() | 0o200);
    }
    #[cfg(not(unix))]
    {
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
    }
    fs::set_permissions(path, permissions)
}

pub(super) fn clone_unsupported(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Unsupported
            | io::ErrorKind::CrossesDevices
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::PermissionDenied
    )
}

pub(crate) fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> MaterializationError {
    MaterializationError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
