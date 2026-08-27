//! Filesystem identity helpers used at output boundaries.

use std::io;
use std::path::Path;

use same_file::Handle;

/// Identity of an existing filesystem object.
///
/// This wrapper deliberately delegates identity rules to the operating
/// system rather than trying to emulate case folding in strings. Symlink
/// policy remains the caller's responsibility (`validate_output_path`).
#[derive(Debug)]
pub(crate) struct ExistingPathIdentity(Handle);

impl ExistingPathIdentity {
    pub(crate) fn from_path(path: &Path) -> io::Result<Option<Self>> {
        match Handle::from_path(path) {
            Ok(handle) => Ok(Some(Self(handle))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl PartialEq for ExistingPathIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ExistingPathIdentity {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::ErrorKind;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rsolve-filesystem-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn missing_path_has_no_identity() {
        assert!(
            ExistingPathIdentity::from_path(&path("missing"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn distinct_files_have_distinct_identity() {
        let first = path("first");
        let second = path("second");
        fs::write(&first, b"a").unwrap();
        fs::write(&second, b"a").unwrap();
        assert_ne!(
            ExistingPathIdentity::from_path(&first).unwrap(),
            ExistingPathIdentity::from_path(&second).unwrap()
        );
        fs::remove_file(first).unwrap();
        fs::remove_file(second).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_aliases_have_equal_identity() {
        let first = path("hardlink-first");
        let second = path("hardlink-second");
        fs::write(&first, b"a").unwrap();
        fs::hard_link(&first, &second).unwrap();
        assert_eq!(
            ExistingPathIdentity::from_path(&first).unwrap(),
            ExistingPathIdentity::from_path(&second).unwrap()
        );
        fs::remove_file(first).unwrap();
        fs::remove_file(second).unwrap();
    }

    #[test]
    fn case_variant_creation_reflects_filesystem_behavior() {
        let first = path("case");
        let first_name = first.file_name().unwrap().to_str().unwrap();
        let second = first.with_file_name(first_name.to_ascii_uppercase());
        assert_ne!(first, second);
        fs::write(&first, b"a").unwrap();
        let result = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&second);
        match result {
            Ok(file) => {
                drop(file);
                assert_ne!(
                    ExistingPathIdentity::from_path(&first).unwrap(),
                    ExistingPathIdentity::from_path(&second).unwrap()
                );
                fs::remove_file(&second).unwrap();
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                assert_eq!(
                    ExistingPathIdentity::from_path(&first).unwrap(),
                    ExistingPathIdentity::from_path(&second).unwrap()
                );
            }
            Err(error) => panic!("unexpected case-variant create_new error: {error}"),
        }
        fs::remove_file(first).unwrap();
    }
}
