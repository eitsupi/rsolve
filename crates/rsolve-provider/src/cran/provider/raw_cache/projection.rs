//! Atomic, package-keyed projections derived from validated raw metadata.
//!
//! A projection is intentionally a storage primitive, not a metadata parser.
//! Source adapters validate their own records and provide the deterministic
//! surface summary; this container only binds the resulting rows to the raw
//! body and parser contract.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::cell::Cell;

const FORMAT: &str = "rsolve-cran-package-projection";
const VERSION: u32 = 2;
const HEADER: TableDefinition<&str, &[u8]> = TableDefinition::new("header");
const PACKAGES: TableDefinition<&str, &[u8]> = TableDefinition::new("packages");
const PACKAGE_COUNTS: TableDefinition<&str, u64> = TableDefinition::new("package_counts");
static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    static VISIT_PACKAGE_RECORDS_COUNT: Cell<usize> = const { Cell::new(0) };
    static VISIT_SELECTED_PACKAGE_RECORDS_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_visit_package_records_count() {
    VISIT_PACKAGE_RECORDS_COUNT.with(|counter| counter.set(0));
}

#[cfg(test)]
pub(crate) fn visit_package_records_count() -> usize {
    VISIT_PACKAGE_RECORDS_COUNT.with(Cell::get)
}

#[cfg(test)]
pub(crate) fn reset_visit_selected_package_records_count() {
    VISIT_SELECTED_PACKAGE_RECORDS_COUNT.with(|counter| counter.set(0));
}

#[cfg(test)]
pub(crate) fn visit_selected_package_records_count() -> usize {
    VISIT_SELECTED_PACKAGE_RECORDS_COUNT.with(Cell::get)
}

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

#[derive(Clone, Debug)]
pub(crate) struct ProjectionBuild {
    pub(crate) packages: Vec<ProjectionPackage>,
    pub(crate) summary: Vec<u8>,
    pub(crate) surface_digest: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ProjectionPackage {
    pub(crate) package: String,
    pub(crate) record_count: usize,
    pub(crate) payload: Vec<u8>,
}

pub(crate) struct ProjectionPayload {
    pub(crate) bytes: Vec<u8>,
    pub(crate) record_count: usize,
}

#[derive(Debug)]
pub(crate) enum ProjectionLookupError {
    Storage(String),
    Invalid(String),
}

pub(crate) enum ProjectionVisitError<E> {
    Storage(String),
    Invalid(String),
    Visitor(E),
}

impl std::fmt::Display for ProjectionLookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(message) | Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ProjectionError {
    Build(String),
    Storage(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectionOpenOutcome {
    Reused,
    Built,
    Rebuilt,
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
    summary: Vec<u8>,
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
        Self::open_or_build_validated(path, raw_body, source_kind, contract, build, |_| Ok(()))
    }

    pub(crate) fn open_or_build_with_outcome<F>(
        path: &Path,
        raw_body: &[u8],
        source_kind: ProjectionSourceKind,
        contract: ProjectionContract,
        build: F,
    ) -> Result<(Self, ProjectionOpenOutcome), ProjectionError>
    where
        F: FnOnce() -> Result<ProjectionBuild, String>,
    {
        Self::open_or_build_validated_with_outcome(
            path,
            raw_body,
            source_kind,
            contract,
            build,
            |_| Ok(()),
        )
    }

    pub(crate) fn open_or_build_validated<F, V>(
        path: &Path,
        raw_body: &[u8],
        source_kind: ProjectionSourceKind,
        contract: ProjectionContract,
        build: F,
        validate: V,
    ) -> Result<Self, ProjectionError>
    where
        F: FnOnce() -> Result<ProjectionBuild, String>,
        V: Fn(&Self) -> Result<(), String>,
    {
        Self::open_or_build_validated_with_outcome(
            path,
            raw_body,
            source_kind,
            contract,
            build,
            validate,
        )
        .map(|(projection, _)| projection)
    }

    pub(crate) fn open_or_build_validated_with_outcome<F, V>(
        path: &Path,
        raw_body: &[u8],
        source_kind: ProjectionSourceKind,
        contract: ProjectionContract,
        build: F,
        validate: V,
    ) -> Result<(Self, ProjectionOpenOutcome), ProjectionError>
    where
        F: FnOnce() -> Result<ProjectionBuild, String>,
        V: Fn(&Self) -> Result<(), String>,
    {
        let raw_digest = hex_digest(Sha256::digest(raw_body));
        if let Ok(projection) = Self::open(path, &raw_digest, source_kind, &contract)
            && validate(&projection).is_ok()
        {
            return Ok((projection, ProjectionOpenOutcome::Reused));
        }
        let outcome = if path.exists() {
            ProjectionOpenOutcome::Rebuilt
        } else {
            ProjectionOpenOutcome::Built
        };
        Self::rebuild_validated(path, raw_body, source_kind, contract, build, validate)
            .map(|projection| (projection, outcome))
    }

    pub(crate) fn rebuild_validated<F, V>(
        path: &Path,
        raw_body: &[u8],
        source_kind: ProjectionSourceKind,
        contract: ProjectionContract,
        build: F,
        validate: V,
    ) -> Result<Self, ProjectionError>
    where
        F: FnOnce() -> Result<ProjectionBuild, String>,
        V: Fn(&Self) -> Result<(), String>,
    {
        let raw_digest = hex_digest(Sha256::digest(raw_body));
        let build = build().map_err(ProjectionError::Build)?;
        let counts = build.validate().map_err(ProjectionError::Build)?;
        Self::write(path, raw_digest, source_kind, contract, build, counts)
            .map_err(ProjectionError::Storage)?;
        let projection = Self::open(
            path,
            &hex_digest(Sha256::digest(raw_body)),
            source_kind,
            &contract,
        )
        .map_err(ProjectionError::Storage)?;
        validate(&projection).map_err(ProjectionError::Build)?;
        Ok(projection)
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
        let header_table = read
            .open_table(HEADER)
            .map_err(|error| format!("invalid package projection header: {error}"))?;
        let value = header_table
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
        let _packages = read
            .open_table(PACKAGES)
            .map_err(|error| format!("invalid package projection records: {error}"))?;
        let _counts = read
            .open_table(PACKAGE_COUNTS)
            .map_err(|error| format!("invalid package projection counts: {error}"))?;
        drop(header_table);
        drop(_packages);
        drop(_counts);
        drop(read);
        Ok(Self { database, header })
    }

    pub(crate) fn lookup_package(
        &self,
        package: &str,
    ) -> Result<Option<ProjectionPayload>, ProjectionLookupError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| ProjectionLookupError::Storage(error.to_string()))?;
        let packages = read
            .open_table(PACKAGES)
            .map_err(|error| ProjectionLookupError::Storage(error.to_string()))?;
        let counts = read
            .open_table(PACKAGE_COUNTS)
            .map_err(|error| ProjectionLookupError::Storage(error.to_string()))?;
        let payload = packages
            .get(package)
            .map_err(|error| ProjectionLookupError::Storage(error.to_string()))?
            .map(|value| value.value().to_vec());
        let count = counts
            .get(package)
            .map_err(|error| ProjectionLookupError::Storage(error.to_string()))?;
        match (payload, count) {
            (None, None) => Ok(None),
            (Some(_), None) | (None, Some(_)) => Err(ProjectionLookupError::Invalid(
                "package projection payload/count entry mismatch".into(),
            )),
            (Some(bytes), Some(count)) => {
                if bytes.is_empty() || count.value() == 0 {
                    return Err(ProjectionLookupError::Invalid(
                        "invalid package projection payload/count entry".into(),
                    ));
                }
                let record_count = usize::try_from(count.value()).map_err(|_| {
                    ProjectionLookupError::Invalid(
                        "package projection record count exceeds usize".into(),
                    )
                })?;
                Ok(Some(ProjectionPayload {
                    bytes,
                    record_count,
                }))
            }
        }
    }

    /// Visit selected package payloads in one read transaction. Source
    /// adapters use this for qualification scans that need a package-keyed
    /// projection without regressing to one transaction per package.
    pub(crate) fn visit_selected_packages<F, E>(
        &self,
        packages: &[&str],
        mut visitor: F,
    ) -> Result<(), ProjectionVisitError<E>>
    where
        F: FnMut(&str, Option<ProjectionPayload>) -> Result<(), E>,
    {
        #[cfg(test)]
        VISIT_SELECTED_PACKAGE_RECORDS_COUNT.with(|counter| counter.set(counter.get() + 1));
        let read = self
            .database
            .begin_read()
            .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?;
        let payloads = read
            .open_table(PACKAGES)
            .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?;
        let counts = read
            .open_table(PACKAGE_COUNTS)
            .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?;
        for package in packages {
            let payload = payloads
                .get(*package)
                .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?
                .map(|value| value.value().to_vec());
            let count = counts
                .get(*package)
                .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?;
            let payload = match (payload, count) {
                (None, None) => None,
                (Some(_), None) | (None, Some(_)) => {
                    return Err(ProjectionVisitError::Invalid(
                        "package projection payload/count entry mismatch".into(),
                    ));
                }
                (Some(bytes), Some(count)) => {
                    if bytes.is_empty() || count.value() == 0 {
                        return Err(ProjectionVisitError::Invalid(
                            "invalid package projection payload/count entry".into(),
                        ));
                    }
                    let record_count = usize::try_from(count.value()).map_err(|_| {
                        ProjectionVisitError::Invalid(
                            "package projection record count exceeds usize".into(),
                        )
                    })?;
                    Some(ProjectionPayload {
                        bytes,
                        record_count,
                    })
                }
            };
            visitor(package, payload).map_err(ProjectionVisitError::Visitor)?;
        }
        Ok(())
    }

    pub(crate) fn visit_packages<F>(&self, mut visitor: F) -> Result<(), String>
    where
        F: FnMut(&str, &[u8], usize) -> Result<(), String>,
    {
        self.visit_packages_with_error(|package, payload, record_count| {
            visitor(package, payload, record_count)
        })
        .map_err(|error| match error {
            ProjectionVisitError::Storage(error)
            | ProjectionVisitError::Invalid(error)
            | ProjectionVisitError::Visitor(error) => error,
        })
    }

    pub(crate) fn visit_packages_with_error<F, E>(
        &self,
        mut visitor: F,
    ) -> Result<(), ProjectionVisitError<E>>
    where
        F: FnMut(&str, &[u8], usize) -> Result<(), E>,
    {
        #[cfg(test)]
        VISIT_PACKAGE_RECORDS_COUNT.with(|counter| counter.set(counter.get() + 1));
        let read = self
            .database
            .begin_read()
            .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?;
        let packages = read
            .open_table(PACKAGES)
            .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?;
        let counts = read
            .open_table(PACKAGE_COUNTS)
            .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?;
        let mut package_count = 0usize;
        let mut record_count = 0usize;
        for item in packages
            .iter()
            .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?
        {
            let (key, value) =
                item.map_err(|error| ProjectionVisitError::Storage(error.to_string()))?;
            if key.value().is_empty() || value.value().is_empty() {
                return Err(ProjectionVisitError::Invalid(
                    "invalid package projection payload entry".into(),
                ));
            }
            let Some(count) = counts
                .get(key.value())
                .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?
            else {
                return Err(ProjectionVisitError::Invalid(
                    "package projection payload has no count entry".into(),
                ));
            };
            if count.value() == 0 {
                return Err(ProjectionVisitError::Invalid(
                    "invalid package projection count entry".into(),
                ));
            }
            let count = usize::try_from(count.value()).map_err(|_| {
                ProjectionVisitError::Invalid(
                    "package projection record count exceeds usize".to_owned(),
                )
            })?;
            package_count = package_count.checked_add(1).ok_or_else(|| {
                ProjectionVisitError::Invalid(
                    "package projection package count overflow".to_owned(),
                )
            })?;
            record_count = record_count.checked_add(count).ok_or_else(|| {
                ProjectionVisitError::Invalid("package projection record count overflow".to_owned())
            })?;
            visitor(key.value(), value.value(), count).map_err(ProjectionVisitError::Visitor)?;
        }
        for item in counts
            .iter()
            .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?
        {
            let (key, count) =
                item.map_err(|error| ProjectionVisitError::Storage(error.to_string()))?;
            if key.value().is_empty() || count.value() == 0 {
                return Err(ProjectionVisitError::Invalid(
                    "invalid package projection count entry".into(),
                ));
            }
            if packages
                .get(key.value())
                .map_err(|error| ProjectionVisitError::Storage(error.to_string()))?
                .is_none()
            {
                return Err(ProjectionVisitError::Invalid(
                    "package projection count has no payload".into(),
                ));
            }
        }
        if package_count != self.header.package_count || record_count != self.header.record_count {
            return Err(ProjectionVisitError::Invalid(
                "package projection counts do not match its header".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn package_count(&self) -> usize {
        self.header.package_count
    }

    pub(crate) fn record_count(&self) -> usize {
        self.header.record_count
    }

    pub(crate) fn surface_digest(&self) -> &str {
        &self.header.surface_digest
    }

    pub(crate) fn summary(&self) -> &[u8] {
        &self.header.summary
    }

    fn write(
        path: &Path,
        raw_digest: String,
        source_kind: ProjectionSourceKind,
        contract: ProjectionContract,
        build: ProjectionBuild,
        (package_count, record_count): (usize, usize),
    ) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "package projection path has no parent".to_owned())?;
        ensure_regular_directory(parent)?;
        let (temporary, _temporary_file) = temporary_path(path)?;
        drop(_temporary_file);
        let _cleanup = TemporaryPath(temporary.clone());
        let mut database = Database::create(&temporary).map_err(|error| error.to_string())?;
        let header = Header {
            format: FORMAT.into(),
            version: VERSION,
            source_kind: source_kind.as_str().into(),
            raw_digest,
            parser_schema: contract.parser_schema,
            compatibility_profile: contract.compatibility_profile,
            normalization_policy: contract.normalization_policy,
            package_count,
            record_count,
            summary: build.summary,
            surface_digest: build.surface_digest,
        };
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
                for package in &build.packages {
                    table
                        .insert(package.package.as_str(), package.payload.as_slice())
                        .map_err(|error| error.to_string())?;
                }
            }
            {
                let mut table = tx
                    .open_table(PACKAGE_COUNTS)
                    .map_err(|error| error.to_string())?;
                for package in &build.packages {
                    let record_count = u64::try_from(package.record_count)
                        .map_err(|_| "package projection record count exceeds u64".to_owned())?;
                    table
                        .insert(package.package.as_str(), record_count)
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

impl ProjectionBuild {
    fn validate(&self) -> Result<(usize, usize), String> {
        let mut package_keys = BTreeSet::new();
        let mut record_count = 0usize;
        for package in &self.packages {
            if package.package.is_empty() {
                return Err("package projection contains an empty package key".into());
            }
            if !package_keys.insert(package.package.as_str()) {
                return Err(format!(
                    "package projection contains duplicate package key {}",
                    package.package
                ));
            }
            if package.record_count == 0 {
                return Err(format!(
                    "package projection contains an empty payload for {}",
                    package.package
                ));
            }
            if package.payload.is_empty() {
                return Err(format!(
                    "package projection contains an empty payload for {}",
                    package.package
                ));
            }
            record_count = record_count
                .checked_add(package.record_count)
                .ok_or_else(|| "package projection record count overflow".to_owned())?;
        }
        Ok((package_keys.len(), record_count))
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
pub(crate) fn overwrite_projection_summary(path: &Path, summary: Vec<u8>) {
    let database = Database::open(path).unwrap();
    let tx = database.begin_write().unwrap();
    {
        let mut table = tx.open_table(HEADER).unwrap();
        let value = table.get("header").unwrap().unwrap().value().to_vec();
        let mut header: Header = postcard::from_bytes(&value).unwrap();
        header.summary = summary;
        let encoded = postcard::to_stdvec(&header).unwrap();
        table.insert("header", encoded.as_slice()).unwrap();
    }
    tx.commit().unwrap();
}

#[cfg(test)]
pub(crate) fn overwrite_projection_package(path: &Path, package: &str, payload: Vec<u8>) {
    let database = Database::open(path).unwrap();
    let tx = database.begin_write().unwrap();
    {
        let mut table = tx.open_table(PACKAGES).unwrap();
        table.insert(package, payload.as_slice()).unwrap();
    }
    tx.commit().unwrap();
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
            packages: vec![ProjectionPackage {
                package: "pkg".into(),
                record_count: 1,
                payload: postcard::to_stdvec(&raw).unwrap(),
            }],
            summary: raw.as_bytes().to_vec(),
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
            postcard::from_bytes::<String>(
                &projection.lookup_package("pkg").unwrap().unwrap().bytes
            )
            .unwrap(),
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
        assert_eq!(projection.summary(), b"1.0");
    }

    #[test]
    fn package_record_visitor_reads_all_keys_in_one_ordered_pass() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("current.redb");
        let projection = PackageProjection::open_or_build(
            &path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            || {
                Ok(ProjectionBuild {
                    packages: vec![
                        ProjectionPackage {
                            package: "b".into(),
                            record_count: 1,
                            payload: vec![1],
                        },
                        ProjectionPackage {
                            package: "a".into(),
                            record_count: 1,
                            payload: vec![0],
                        },
                    ],
                    summary: vec![9],
                    surface_digest: "surface".into(),
                })
            },
        )
        .unwrap();
        reset_visit_package_records_count();
        let mut keys = Vec::new();
        projection
            .visit_packages(|package, payload, record_count| {
                keys.push((package.to_owned(), payload[0]));
                assert_eq!(record_count, 1);
                Ok(())
            })
            .unwrap();
        assert_eq!(visit_package_records_count(), 1);
        assert_eq!(keys, [("a".into(), 0), ("b".into(), 1)]);
    }

    #[test]
    fn warm_open_defers_extra_count_validation_until_full_visit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("current.redb");
        let projection = PackageProjection::open_or_build(
            &path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            || Ok(build("1.0")),
        )
        .unwrap();
        drop(projection);
        let database = Database::open(&path).unwrap();
        {
            let tx = database.begin_write().unwrap();
            {
                let mut counts = tx.open_table(PACKAGE_COUNTS).unwrap();
                counts.insert("orphan", 1).unwrap();
            }
            tx.commit().unwrap();
        }
        drop(database);
        let projection = PackageProjection::open(
            &path,
            &hex_digest(Sha256::digest(b"raw")),
            ProjectionSourceKind::Current,
            &contract(),
        )
        .unwrap();
        let error = projection.visit_packages(|_, _, _| Ok(())).unwrap_err();
        assert!(error.contains("no payload"));
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
            postcard::from_bytes::<String>(
                &projection.lookup_package("pkg").unwrap().unwrap().bytes
            )
            .unwrap(),
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
            postcard::from_bytes::<String>(
                &projection.lookup_package("pkg").unwrap().unwrap().bytes
            )
            .unwrap(),
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
            postcard::from_bytes::<String>(
                &projection.lookup_package("pkg").unwrap().unwrap().bytes
            )
            .unwrap(),
            "2.0"
        );
    }

    #[test]
    fn build_rejects_duplicate_and_empty_package_keys() {
        let directory = tempfile::tempdir().unwrap();
        let duplicate_path = directory.path().join("duplicate.redb");
        let duplicate = PackageProjection::open_or_build(
            &duplicate_path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            || {
                Ok(ProjectionBuild {
                    packages: vec![
                        ProjectionPackage {
                            package: "pkg".into(),
                            record_count: 1,
                            payload: vec![1],
                        },
                        ProjectionPackage {
                            package: "pkg".into(),
                            record_count: 1,
                            payload: vec![2],
                        },
                    ],
                    summary: Vec::new(),
                    surface_digest: "surface".into(),
                })
            },
        );
        assert!(
            matches!(duplicate, Err(ProjectionError::Build(message)) if message.contains("duplicate"))
        );

        let empty_path = directory.path().join("empty.redb");
        let empty = PackageProjection::open_or_build(
            &empty_path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            || {
                Ok(ProjectionBuild {
                    packages: vec![ProjectionPackage {
                        package: String::new(),
                        record_count: 1,
                        payload: vec![1],
                    }],
                    summary: Vec::new(),
                    surface_digest: "surface".into(),
                })
            },
        );
        assert!(
            matches!(empty, Err(ProjectionError::Build(message)) if message.contains("empty package"))
        );

        let empty_payload_path = directory.path().join("empty-payload.redb");
        let empty_payload = PackageProjection::open_or_build(
            &empty_payload_path,
            b"raw",
            ProjectionSourceKind::Current,
            contract(),
            || {
                Ok(ProjectionBuild {
                    packages: vec![ProjectionPackage {
                        package: "pkg".into(),
                        record_count: 1,
                        payload: Vec::new(),
                    }],
                    summary: Vec::new(),
                    surface_digest: "surface".into(),
                })
            },
        );
        assert!(matches!(
            empty_payload,
            Err(ProjectionError::Build(message)) if message.contains("empty payload")
        ));
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
