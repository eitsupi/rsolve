use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use flate2::read::GzDecoder;
use tar::Archive;

use super::CacheError;

pub(super) fn validate_source_archive(path: &Path) -> Result<(), CacheError> {
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
