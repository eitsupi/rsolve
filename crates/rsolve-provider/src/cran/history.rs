//! Decode CRAN's `Meta/archive.rds` enumeration without treating it as package metadata.

use std::error::Error;
use std::fmt;

use rd_rds::{RObject, RStr, RValue, file::ReadOptions};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::archive_index::provider_rds_read_options;
use rsolve_core::{PackageName, RPackageVersion};

/// One historical source archive advertised by `Meta/archive.rds`.
///
/// This is deliberately limited to file enumeration.  Package version and
/// dependency metadata are read from the archive's DESCRIPTION instead.
/// The path is relative to CRAN's source archive root; it is not a generic
/// repository artifact path and does not describe binary layouts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveEntry {
    package: PackageName,
    version: RPackageVersion,
    source_archive_relative_path: Box<str>,
    size: u64,
    mtime: i64,
}

/// A package-local row that cannot contribute a candidate to the provider
/// history projection. The raw path is retained so callers can report the
/// exact upstream row without manufacturing a Package/Version identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveHistoryRejection {
    package_hint: PackageName,
    raw_path: Box<str>,
    row: usize,
    version: Option<RPackageVersion>,
    reason: Box<str>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ArchivePackagePayload {
    pub(crate) entries: Vec<ArchiveEntry>,
    pub(crate) rejections: Vec<ArchiveHistoryRejection>,
}

#[derive(Deserialize, Serialize)]
struct ArchiveEntryWire {
    package: String,
    version: String,
    source_archive_relative_path: String,
    size: u64,
    mtime: i64,
}

#[derive(Deserialize, Serialize)]
struct ArchiveHistoryRejectionWire {
    package_hint: String,
    raw_path: String,
    row: usize,
    version: Option<String>,
    reason: String,
}

#[derive(Deserialize, Serialize)]
struct ArchivePackagePayloadWire {
    entries: Vec<ArchiveEntryWire>,
    rejections: Vec<ArchiveHistoryRejectionWire>,
}

impl Serialize for ArchivePackagePayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ArchivePackagePayloadWire {
            entries: self
                .entries
                .iter()
                .map(|entry| ArchiveEntryWire {
                    package: entry.package.to_string(),
                    version: entry.version.to_string(),
                    source_archive_relative_path: entry.source_archive_relative_path.to_string(),
                    size: entry.size,
                    mtime: entry.mtime,
                })
                .collect(),
            rejections: self
                .rejections
                .iter()
                .map(|rejection| ArchiveHistoryRejectionWire {
                    package_hint: rejection.package_hint.to_string(),
                    raw_path: rejection.raw_path.to_string(),
                    row: rejection.row,
                    version: rejection.version.as_ref().map(ToString::to_string),
                    reason: rejection.reason.to_string(),
                })
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ArchivePackagePayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ArchivePackagePayloadWire::deserialize(deserializer)?;
        let entries = wire
            .entries
            .into_iter()
            .map(|entry| {
                Ok(ArchiveEntry {
                    package: PackageName::new(&entry.package).map_err(serde::de::Error::custom)?,
                    version: RPackageVersion::parse(&entry.version)
                        .map_err(serde::de::Error::custom)?,
                    source_archive_relative_path: entry.source_archive_relative_path.into(),
                    size: entry.size,
                    mtime: entry.mtime,
                })
            })
            .collect::<Result<_, D::Error>>()?;
        let rejections = wire
            .rejections
            .into_iter()
            .map(|rejection| {
                Ok(ArchiveHistoryRejection {
                    package_hint: PackageName::new(&rejection.package_hint)
                        .map_err(serde::de::Error::custom)?,
                    raw_path: rejection.raw_path.into(),
                    row: rejection.row,
                    version: rejection
                        .version
                        .as_deref()
                        .map(RPackageVersion::parse)
                        .transpose()
                        .map_err(serde::de::Error::custom)?,
                    reason: rejection.reason.into(),
                })
            })
            .collect::<Result<_, D::Error>>()?;
        Ok(Self {
            entries,
            rejections,
        })
    }
}

impl ArchivePackagePayload {
    pub(crate) fn validate_for_package(self, package: &PackageName) -> Result<Self, String> {
        for entry in &self.entries {
            if entry.package() != package {
                return Err(format!(
                    "archive projection package binding mismatch for {package}"
                ));
            }
            if entry.mtime < 0 {
                return Err("archive projection entry has a negative mtime".into());
            }
            let (path_package, path_version, normalized_path) =
                parse_archive_path(entry.source_archive_relative_path())
                    .map_err(|error| format!("invalid archive projection entry: {error}"))?;
            if &path_package != entry.package()
                || &path_version != entry.version()
                || normalized_path.as_ref() != entry.source_archive_relative_path()
            {
                return Err(format!(
                    "archive projection entry does not match its package, version, or path: {}",
                    entry.source_archive_relative_path()
                ));
            }
        }
        if self
            .rejections
            .iter()
            .any(|rejection| rejection.package_hint() != package)
        {
            return Err(format!(
                "archive projection package binding mismatch for {package}"
            ));
        }
        Ok(self)
    }
}

impl ArchiveHistoryRejection {
    pub(crate) fn package_hint(&self) -> &PackageName {
        &self.package_hint
    }

    #[cfg(test)]
    pub(crate) fn raw_path(&self) -> &str {
        &self.raw_path
    }

    #[cfg(test)]
    pub(crate) fn row(&self) -> usize {
        self.row
    }

    #[cfg(test)]
    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }

    pub(crate) fn diagnostic(&self) -> String {
        format!(
            "archive history package {} row {} path {:?}: {}",
            self.package_hint, self.row, self.raw_path, self.reason
        )
    }

    pub(crate) fn version(&self) -> Option<&RPackageVersion> {
        self.version.as_ref()
    }
}

/// Provider-only result of decoding archive history. Structural failures are
/// still returned as errors; only rows that can be attributed to a named
/// package are isolated as release-local rejections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveHistoryProjection {
    pub(crate) entries: Vec<ArchiveEntry>,
    pub(crate) rejections: Vec<ArchiveHistoryRejection>,
}

impl ArchiveEntry {
    #[cfg(test)]
    pub(crate) fn for_test(package: &str, version: &str, path: &str, size: u64) -> Self {
        Self {
            package: PackageName::new(package).unwrap(),
            version: RPackageVersion::parse(version).unwrap(),
            source_archive_relative_path: path.into(),
            size,
            mtime: 0,
        }
    }

    pub fn package(&self) -> &PackageName {
        &self.package
    }

    pub fn version(&self) -> &RPackageVersion {
        &self.version
    }

    /// Returns the package-relative source archive path.
    pub fn source_archive_relative_path(&self) -> &str {
        &self.source_archive_relative_path
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn mtime(&self) -> i64 {
        self.mtime
    }
}

/// A malformed or unsupported `Meta/archive.rds` enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranHistoryError {
    Decode(String),
    RootType(&'static str),
    MissingNames,
    NameLength,
    NotDataFrame,
    InvalidColumns,
    MissingRowNames,
    RowNameLength,
    InvalidString { field: &'static str, row: usize },
    InvalidColumnType { field: &'static str },
    InvalidPackage { value: String },
    InvalidArchivePath { value: String },
    InvalidSize { row: usize },
    InvalidMtime { row: usize },
}

impl fmt::Display for CranHistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "invalid archive history RDS: {error}"),
            Self::RootType(expected) => write!(f, "archive history RDS root is not {expected}"),
            Self::MissingNames => f.write_str("archive history RDS list has no names"),
            Self::NameLength => f.write_str("archive history list names have the wrong length"),
            Self::NotDataFrame => f.write_str("archive history item is not a data.frame"),
            Self::InvalidColumns => f.write_str("archive history data.frame has invalid columns"),
            Self::MissingRowNames => f.write_str("archive history data.frame has no row.names"),
            Self::RowNameLength => f.write_str("archive history row.names have the wrong length"),
            Self::InvalidString { field, row } => {
                write!(
                    f,
                    "archive history {field} value at row {row} is not a string"
                )
            }
            Self::InvalidColumnType { field } => {
                write!(f, "archive history {field} column has an unsupported type")
            }
            Self::InvalidPackage { value } => write!(f, "invalid archive package name {value:?}"),
            Self::InvalidArchivePath { value } => {
                write!(f, "invalid archive path {value:?}")
            }
            Self::InvalidSize { row } => write!(f, "invalid archive size at row {row}"),
            Self::InvalidMtime { row } => write!(f, "invalid archive mtime at row {row}"),
        }
    }
}

impl Error for CranHistoryError {}

/// Decode a `Meta/archive.rds` named list or a `file.info`-shaped data frame.
pub fn enumerate_archive_rds(input: &[u8]) -> Result<Vec<ArchiveEntry>, CranHistoryError> {
    enumerate_archive_rds_with_options(input, &ReadOptions::default())
}

pub(crate) fn enumerate_archive_rds_with_options(
    input: &[u8],
    options: &ReadOptions,
) -> Result<Vec<ArchiveEntry>, CranHistoryError> {
    let object = rd_rds::file::from_bytes_with_options(input, options)
        .map_err(|error| CranHistoryError::Decode(error.to_string()))?;
    Ok(enumerate_object(&object, false)?.entries)
}

pub(crate) fn enumerate_archive_rds_for_provider(
    input: &[u8],
) -> Result<ArchiveHistoryProjection, CranHistoryError> {
    let object = rd_rds::file::from_bytes_with_options(input, &provider_rds_read_options())
        .map_err(|error| CranHistoryError::Decode(error.to_string()))?;
    enumerate_object(&object, true)
}

fn enumerate_object(
    object: &RObject,
    quarantine_nested_foreign_releases: bool,
) -> Result<ArchiveHistoryProjection, CranHistoryError> {
    let RValue::List(items) = object.value() else {
        return Err(CranHistoryError::RootType("a named list or data.frame"));
    };
    let Some(names) = object.names() else {
        return Err(CranHistoryError::MissingNames);
    };
    if names.len() != items.len() {
        return Err(CranHistoryError::NameLength);
    }

    if is_data_frame(object) {
        return enumerate_frame(object, None, quarantine_nested_foreign_releases);
    }

    let mut projection = ArchiveHistoryProjection {
        entries: Vec::new(),
        rejections: Vec::new(),
    };
    for (index, item) in items.iter().enumerate() {
        let package_name =
            names
                .get(index)
                .and_then(string_value)
                .ok_or(CranHistoryError::InvalidString {
                    field: "names",
                    row: index,
                })?;
        let package =
            PackageName::new(&package_name).map_err(|_| CranHistoryError::InvalidPackage {
                value: package_name.to_string(),
            })?;
        let frame = enumerate_frame(item, Some(&package), quarantine_nested_foreign_releases)?;
        projection.entries.extend(frame.entries);
        projection.rejections.extend(frame.rejections);
    }
    Ok(projection)
}

fn enumerate_frame(
    object: &RObject,
    package_hint: Option<&PackageName>,
    quarantine_nested_foreign_releases: bool,
) -> Result<ArchiveHistoryProjection, CranHistoryError> {
    if !is_data_frame(object) {
        return Err(CranHistoryError::NotDataFrame);
    }
    let RValue::List(columns) = object.value() else {
        return Err(CranHistoryError::RootType("a file.info data.frame"));
    };
    let names = object.names().ok_or(CranHistoryError::MissingNames)?;
    let expected = [
        "size", "isdir", "mode", "mtime", "ctime", "atime", "uid", "gid", "uname", "grname",
    ];
    if names.len() != expected.len()
        || names.iter().zip(expected).any(|(name, expected)| {
            string_value(name).is_none_or(|name| !name.eq_ignore_ascii_case(expected))
        })
    {
        return Err(CranHistoryError::InvalidColumns);
    }
    if columns.len() != expected.len() {
        return Err(CranHistoryError::InvalidColumns);
    }
    let files = object
        .attributes()
        .get("row.names")
        .ok_or(CranHistoryError::MissingRowNames)?;
    let files = string_column(files, "row.names")?;
    let sizes = &columns[0];
    let mtimes = &columns[3];
    let sizes = numeric_column(sizes, "Size")?;
    let mtimes = numeric_column(mtimes, "mtime")?;
    if files.len() != sizes.len() {
        return Err(CranHistoryError::RowNameLength);
    }
    if files.len() != mtimes.len() {
        return Err(CranHistoryError::RowNameLength);
    }

    let mut projection = ArchiveHistoryProjection {
        entries: Vec::new(),
        rejections: Vec::new(),
    };
    for (row, path) in files.into_iter().enumerate() {
        let parsed = match parse_archive_path(&path) {
            Ok(parsed) => parsed,
            Err(error) => {
                if let Some(rejection) = package_local_rejection(
                    quarantine_nested_foreign_releases,
                    package_hint,
                    &path,
                    row,
                    &error,
                ) {
                    projection.rejections.push(rejection);
                    continue;
                }
                return Err(error);
            }
        };
        let (path_package, version, source_archive_relative_path) = parsed;
        if package_hint.is_some_and(|package| package != &path_package) {
            let error = CranHistoryError::InvalidPackage {
                value: path.clone(),
            };
            if let Some(rejection) = package_local_rejection(
                quarantine_nested_foreign_releases,
                package_hint,
                &path,
                row,
                &error,
            ) {
                projection.rejections.push(rejection);
                continue;
            }
            return Err(error);
        }
        let package = package_hint.cloned().unwrap_or(path_package);
        let size = sizes[row].ok_or(CranHistoryError::InvalidSize { row })?;
        if !size.is_finite() || size < 0.0 || size.fract() != 0.0 {
            return Err(CranHistoryError::InvalidSize { row });
        }
        let mtime = mtimes[row].ok_or(CranHistoryError::InvalidMtime { row })?;
        if !mtime.is_finite() || mtime < 0.0 {
            return Err(CranHistoryError::InvalidMtime { row });
        }
        projection.entries.push(ArchiveEntry {
            package,
            version,
            source_archive_relative_path,
            size: size as u64,
            mtime: mtime as i64,
        });
    }
    Ok(projection)
}

fn is_data_frame(object: &RObject) -> bool {
    object.class().is_some_and(|classes| {
        classes
            .iter()
            .filter_map(string_value)
            .any(|class| class == "data.frame")
    })
}

fn string_column(object: &RObject, field: &'static str) -> Result<Vec<String>, CranHistoryError> {
    let RValue::Character(values) = object.value() else {
        return Err(CranHistoryError::InvalidColumnType { field });
    };
    values
        .iter()
        .enumerate()
        .map(|(row, value)| {
            string_value(value).ok_or(CranHistoryError::InvalidString { field, row })
        })
        .collect()
}

fn numeric_column(
    object: &RObject,
    field: &'static str,
) -> Result<Vec<Option<f64>>, CranHistoryError> {
    match object.value() {
        RValue::Integer(values) => Ok(values.iter().map(|value| value.map(f64::from)).collect()),
        RValue::Real(values) => Ok(values.clone()),
        _ => Err(CranHistoryError::InvalidColumnType { field }),
    }
}

fn string_value(value: &RStr) -> Option<String> {
    value.as_str()?.ok().map(|value| value.into_owned())
}

fn parse_archive_path(
    path: &str,
) -> Result<(PackageName, RPackageVersion, Box<str>), CranHistoryError> {
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.iter().any(|segment| {
        segment.is_empty()
            || *segment == "."
            || *segment == ".."
            || segment.contains('\\')
            || segment.contains('?')
            || segment.contains('#')
            || segment.contains('%')
    }) {
        return Err(CranHistoryError::InvalidArchivePath {
            value: path.to_owned(),
        });
    }
    let (package_segment, filename) = match segments.as_slice() {
        [package, filename] => (*package, *filename),
        ["src", "contrib", "Archive", package, filename] => (*package, *filename),
        ["src", "contrib", "Archive", package, nested @ .., filename] if !nested.is_empty() => {
            (*package, *filename)
        }
        [package, nested @ .., filename] if !nested.is_empty() => (*package, *filename),
        _ => {
            return Err(CranHistoryError::InvalidArchivePath {
                value: path.to_owned(),
            });
        }
    };
    let package =
        PackageName::new(package_segment).map_err(|_| CranHistoryError::InvalidArchivePath {
            value: path.to_owned(),
        })?;
    let stem =
        filename
            .strip_suffix(".tar.gz")
            .ok_or_else(|| CranHistoryError::InvalidArchivePath {
                value: path.to_owned(),
            })?;
    let (filename_package, version) =
        stem.split_once('_')
            .ok_or_else(|| CranHistoryError::InvalidArchivePath {
                value: path.to_owned(),
            })?;
    if filename_package != package.as_str() {
        return Err(CranHistoryError::InvalidArchivePath {
            value: path.to_owned(),
        });
    }
    let version =
        RPackageVersion::parse(version).map_err(|_| CranHistoryError::InvalidArchivePath {
            value: path.to_owned(),
        })?;
    let normalized_path = if segments.starts_with(&["src", "contrib", "Archive"]) {
        segments[3..].join("/").into_boxed_str()
    } else {
        segments.join("/").into_boxed_str()
    };
    Ok((package, version, normalized_path))
}

fn package_local_rejection(
    provider_mode: bool,
    package_hint: Option<&PackageName>,
    path: &str,
    row: usize,
    error: &CranHistoryError,
) -> Option<ArchiveHistoryRejection> {
    if !provider_mode {
        return None;
    }
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.iter().any(|segment| {
        segment.is_empty()
            || *segment == "."
            || *segment == ".."
            || segment.contains('\\')
            || segment.contains('?')
            || segment.contains('#')
            || segment.contains('%')
    }) {
        return None;
    }
    let (path_package, filename, nested) = match segments.as_slice() {
        ["src", "contrib", "Archive", package, filename] => (*package, *filename, false),
        ["src", "contrib", "Archive", package, nested @ .., filename] if !nested.is_empty() => {
            (*package, *filename, true)
        }
        [package, filename] => (*package, *filename, false),
        [package, nested @ .., filename] if !nested.is_empty() => (*package, *filename, true),
        _ => return None,
    };
    let stem = filename.strip_suffix(".tar.gz")?;
    let (filename_package, version) = stem.split_once('_')?;
    if PackageName::new(path_package).is_err() || PackageName::new(filename_package).is_err() {
        return None;
    }
    let package_hint = package_hint
        .cloned()
        .or_else(|| PackageName::new(path_package).ok())?;
    let is_foreign_nested =
        nested && path_package != filename_package && path_package == package_hint.as_str();
    let is_invalid_version = path_package == package_hint.as_str()
        && filename_package == package_hint.as_str()
        && RPackageVersion::parse(version).is_err();
    if (!is_foreign_nested && !is_invalid_version)
        || !matches!(
            error,
            CranHistoryError::InvalidArchivePath { .. } | CranHistoryError::InvalidPackage { .. }
        )
    {
        return None;
    }
    Some(ArchiveHistoryRejection {
        package_hint: package_hint.clone(),
        raw_path: path.to_owned().into_boxed_str(),
        row,
        version: RPackageVersion::parse(version).ok(),
        reason: error.to_string().into_boxed_str(),
    })
}
