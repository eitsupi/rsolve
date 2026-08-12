use std::io::{Read, Write};
use std::path::Path;

use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest as Sha2Digest, Sha256};

use super::CacheError;

pub(super) fn copy_compressed_input<W: Write>(
    reader: &mut dyn Read,
    output: &mut W,
    expected: Option<u64>,
    hard_limit: u64,
    partial: &Path,
    sha256: &mut Sha256,
    md5: &mut Md5,
) -> Result<u64, CacheError> {
    let limit = expected.unwrap_or(hard_limit);
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        // Once the bound is reached, read exactly one byte to distinguish an
        // exact boundary from an over-limit stream. Saturating arithmetic is
        // intentional so a declared u64::MAX size cannot wrap.
        let at_limit = size >= limit;
        let capacity = if at_limit {
            1
        } else {
            limit.saturating_sub(size).min(buffer.len() as u64) as usize
        };
        let read = reader
            .read(&mut buffer[..capacity])
            .map_err(|source| CacheError::Io {
                operation: "read artifact stream",
                path: partial.to_path_buf(),
                source,
            })?;
        if read == 0 {
            if let Some(expected) = expected
                && size != expected
            {
                return Err(CacheError::SizeMismatch {
                    expected,
                    actual: size,
                });
            }
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|source| CacheError::Io {
                operation: "write partial artifact",
                path: partial.to_path_buf(),
                source,
            })?;
        Md5Digest::update(&mut *md5, &buffer[..read]);
        Sha2Digest::update(&mut *sha256, &buffer[..read]);
        size = size.saturating_add(read as u64);
        if at_limit {
            return match expected {
                Some(expected) => Err(CacheError::SizeMismatch {
                    expected,
                    actual: size,
                }),
                None => Err(CacheError::InputTooLarge { limit: hard_limit }),
            };
        }
    }
    Ok(size)
}
