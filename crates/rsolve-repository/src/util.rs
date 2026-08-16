use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::CacheError;

pub(super) fn open_file(
    path: &Path,
    create_new: bool,
    operation: &'static str,
) -> Result<File, CacheError> {
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

pub(super) fn make_read_only(path: &Path) -> Result<(), CacheError> {
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

pub(super) fn sync_directory(path: &Path) -> Result<(), CacheError> {
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

pub(super) fn unique_nonce() -> String {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{}", std::process::id(), time.as_nanos())
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}
