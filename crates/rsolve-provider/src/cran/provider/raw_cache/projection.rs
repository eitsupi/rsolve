//! Atomic, package-keyed projections derived from validated raw metadata.
//!
//! A projection is intentionally a storage primitive, not a metadata parser.
//! Source adapters validate their own records and provide the deterministic
//! surface summary; this container only binds the resulting rows to the raw
//! body and parser contract.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FORMAT: &str = "rsolve-cran-package-projection";
const VERSION: u32 = 1;
const HEADER: TableDefinition<&str, &[u8]> = TableDefinition::new("header");
const PACKAGES: TableDefinition<&str, &[u8]> = TableDefinition::new("packages");
static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectionSourceKind {
    Current,
    ArchiveHistory,
    Auxiliary,
}

impl ProjectionSourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::ArchiveHistory => "archive_history",
            Self::Auxiliary => "auxiliary",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectionContract {
    pub(crate) parser_schema: u32,
    pub(crate) compatibility_profile: u32,
    pub(crate) normalization_policy: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProjectionRecord {
    pub(crate) record_index: usize,
    pub(crate) package: Option<String>,
    pub(crate) fields: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProjectionBuild {
    pub(crate) records: Vec<ProjectionRecord>,
    pub(crate) surface_digest: String,
}

#[derive(Debug)]
pub(crate) enum ProjectionError {
    Build(String),
    Storage(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: String,
    version: u32,
    source_kind: String,
    raw_digest: String,
    parser_schema: u32,
    compatibility_profile: u32,
    normalization_policy: u32,
    package_count: usize,
    record_count: usize,
    surface_digest: String,
}

pub(crate) struct PackageProjection {
    database: ReadOnlyDatabase,
    header: Header,
}

impl PackageProjection {
    pub(crate) fn open_or_build<F>(
        path: &Path,
        raw_body: &[u8],
        source_kind: ProjectionSourceKind,
        contract: ProjectionContract,
        build: F,
    ) -> Result<Self, ProjectionError>
    where
        F: FnOnce() -> Result<ProjectionBuild, String>,
    {
        let raw_digest = hex_digest(Sha256::digest(raw_body));
        if let Ok(projection) = Self::open(path, &raw_digest, source_kind, &contract) {
            return Ok(projection);
        }
        let build = build().map_err(ProjectionError::Build)?;
        Self::write(path, raw_digest, source_kind, contract, build)
            .map_err(ProjectionError::Storage)?;
        Self::open(
            path,
            &hex_digest(Sha256::digest(raw_body)),
            source_kind,
            &contract,
        )
        .map_err(ProjectionError::Storage)
    }

    pub(crate) fn open(
        path: &Path,
        raw_digest: &str,
        source_kind: ProjectionSourceKind,
        contract: &ProjectionContract,
    ) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("invalid package projection path: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err("package projection is not a regular file".into());
        }
        let database = ReadOnlyDatabase::open(path)
            .map_err(|error| format!("invalid package projection database: {error}"))?;
        let read = database
            .begin_read()
            .map_err(|error| format!("invalid package projection transaction: {error}"))?;
        let table = read
            .open_table(HEADER)
            .map_err(|error| format!("invalid package projection header: {error}"))?;
        let value = table
            .get("header")
            .map_err(|error| format!("invalid package projection header: {error}"))?
            .ok_or_else(|| "package projection header is missing".to_owned())?;
        let header = postcard::from_bytes::<Header>(value.value())
            .map_err(|error| format!("invalid package projection header: {error}"))?;
        if header.format != FORMAT
            || header.version != VERSION
            || header.source_kind != source_kind.as_str()
            || header.raw_digest != raw_digest
            || header.parser_schema != contract.parser_schema
            || header.compatibility_profile != contract.compatibility_profile
            || header.normalization_policy != contract.normalization_policy
        {
            return Err("package projection contract does not match raw source".into());
        }
        drop(table);
        drop(read);
        Ok(Self { database, header })
    }

    pub(crate) fn lookup_package(&self, package: &str) -> Result<Vec<ProjectionRecord>, String> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| error.to_string())?;
        let table = read
            .open_table(PACKAGES)
            .map_err(|error| error.to_string())?;
        table
            .get(package)
            .map_err(|error| error.to_string())?
            .map(|value| postcard::from_bytes(value.value()).map_err(|error| error.to_string()))
            .transpose()
            .map(|records| records.unwrap_or_default())
    }

    pub(crate) fn package_names(&self) -> Result<Vec<String>, String> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| error.to_string())?;
        let table = read
            .open_table(PACKAGES)
            .map_err(|error| error.to_string())?;
        let mut names = Vec::new();
        for item in table.iter().map_err(|error| error.to_string())? {
            let (key, _) = item.map_err(|error| error.to_string())?;
            if !key.value().is_empty() {
                names.push(key.value().to_owned());
            }
        }
        Ok(names)
    }

    pub(crate) fn package_count(&self) -> usize {
        self.header.package_count
    }

    pub(crate) fn surface_digest(&self) -> &str {
        &self.header.surface_digest
    }

    fn write(
        path: &Path,
        raw_digest: String,
        source_kind: ProjectionSourceKind,
        contract: ProjectionContract,
        build: ProjectionBuild,
    ) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "package projection path has no parent".to_owned())?;
        ensure_regular_directory(parent)?;
        let (temporary, _temporary_file) = temporary_path(path)?;
        drop(_temporary_file);
        let _cleanup = TemporaryPath(temporary.clone());
        let mut database = Database::create(&temporary).map_err(|error| error.to_string())?;
        let record_count = build.records.len();
        let header = Header {
            format: FORMAT.into(),
            version: VERSION,
            source_kind: source_kind.as_str().into(),
            raw_digest,
            parser_schema: contract.parser_schema,
            compatibility_profile: contract.compatibility_profile,
            normalization_policy: contract.normalization_policy,
            package_count: 0,
            record_count,
            surface_digest: build.surface_digest,
        };
        let mut grouped = BTreeMap::<String, Vec<ProjectionRecord>>::new();
        for record in build.records {
            grouped
                .entry(record.package.clone().unwrap_or_default())
                .or_default()
                .push(record);
        }
        let package_count = grouped.keys().filter(|package| !package.is_empty()).count();
        let mut header = header;
        header.package_count = package_count;
        {
            let tx = database.begin_write().map_err(|error| error.to_string())?;
            {
                let mut table = tx.open_table(HEADER).map_err(|error| error.to_string())?;
                let encoded = postcard::to_stdvec(&header).map_err(|error| error.to_string())?;
                table
                    .insert("header", encoded.as_slice())
                    .map_err(|error| error.to_string())?;
            }
            {
                let mut table = tx.open_table(PACKAGES).map_err(|error| error.to_string())?;
                for (package, records) in grouped {
                    let encoded =
                        postcard::to_stdvec(&records).map_err(|error| error.to_string())?;
                    table
                        .insert(package.as_str(), encoded.as_slice())
                        .map_err(|error| error.to_string())?;
                }
            }
            tx.commit().map_err(|error| error.to_string())?;
        }
        database.compact().map_err(|error| error.to_string())?;
        drop(database);
        File::open(&temporary)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;
        crate::snapshot::replace_file(&temporary, path).map_err(|error| error.to_string())?;
        sync_parent(parent)
    }
}

struct TemporaryPath(PathBuf);

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn temporary_path(path: &Path) -> Result<(PathBuf, File), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "package projection path has no parent".to_owned())?;
    let stem = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "package projection path has no file name".to_owned())?;
    let pid = std::process::id();
    for _ in 0..128 {
        let sequence = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = parent.join(format!(".{stem}-{pid}-{sequence}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("unable to allocate package projection temporary file".into())
}

fn sync_parent(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn ensure_regular_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err("package projection parent is not a regular directory".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| "package projection parent has no parent".to_owned())?;
            ensure_regular_directory(parent)?;
            fs::create_dir(path).map_err(|error| error.to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    fn contract() -> ProjectionContract {
        ProjectionContract {
            parser_schema: 1,
            compatibility_profile: 2,
            normalization_policy: 3,
        }
    }

    fn build(raw: &str) -> ProjectionBuild {
        ProjectionBuild {
            records: vec![ProjectionRecord {
                record_index: 0,
                package: Some("pkg".into()),
                fields: vec![("Version".into(), raw.into())],
            }],
            surface_digest: format!("surface-{raw}"),
        }
    }

    #[test]
    fn warm_reopen_looks_up_packages_without_rebuilding() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("current.redb");
        let calls = Rc::new(Cell::new(0));
        let first_calls = Rc::clone(&calls);
        let projection = PackageProjection::open_or_build(
            &path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            || {
                first_calls.set(first_calls.get() + 1);
                Ok(build("1.0"))
            },
        )
        .unwrap();
        assert_eq!(
            projection.lookup_package("pkg").unwrap()[0].fields[0].1,
            "1.0"
        );
        drop(projection);

        let second_calls = Rc::clone(&calls);
        let projection = PackageProjection::open_or_build(
            &path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            || {
                second_calls.set(second_calls.get() + 1);
                Ok(build("unexpected"))
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(projection.package_count(), 1);
        assert_eq!(projection.surface_digest(), "surface-1.0");
    }

    #[test]
    fn corrupt_or_mismatched_projection_rebuilds_from_the_same_raw_body() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("current.redb");
        let calls = Rc::new(Cell::new(0));
        let make = |value: &'static str| {
            let calls = Rc::clone(&calls);
            move || {
                calls.set(calls.get() + 1);
                Ok(build(value))
            }
        };
        PackageProjection::open_or_build(
            &path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            make("1.0"),
        )
        .unwrap();
        std::fs::write(&path, b"corrupt").unwrap();
        let projection = PackageProjection::open_or_build(
            &path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            make("1.1"),
        )
        .unwrap();
        assert_eq!(
            projection.lookup_package("pkg").unwrap()[0].fields[0].1,
            "1.1"
        );
        assert_eq!(calls.get(), 2);

        let projection = PackageProjection::open_or_build(
            &path,
            b"raw",
            ProjectionSourceKind::Current,
            ProjectionContract {
                parser_schema: 9,
                ..contract()
            },
            make("1.2"),
        )
        .unwrap();
        assert_eq!(
            projection.lookup_package("pkg").unwrap()[0].fields[0].1,
            "1.2"
        );
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn changed_raw_body_rebuilds_the_projection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("current.redb");
        PackageProjection::open_or_build(
            &path,
            b"raw-one",
            ProjectionSourceKind::Current,
            contract(),
            || Ok(build("1.0")),
        )
        .unwrap();
        let projection = PackageProjection::open_or_build(
            &path,
            b"raw-two",
            ProjectionSourceKind::Current,
            contract(),
            || Ok(build("2.0")),
        )
        .unwrap();
        assert_eq!(
            projection.lookup_package("pkg").unwrap()[0].fields[0].1,
            "2.0"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_rejects_a_symlinked_projection_parent() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let namespace = directory.path().join("namespace");
        std::os::unix::fs::symlink(outside.path(), &namespace).unwrap();
        let path = namespace.join("current.redb");
        let result = PackageProjection::open_or_build(
            &path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            || Ok(build("1.0")),
        );
        let Err(error) = result else {
            panic!("a symlinked projection parent must fail closed");
        };
        assert!(matches!(
            error,
            ProjectionError::Storage(message) if message.contains("parent")
        ));
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }
}
