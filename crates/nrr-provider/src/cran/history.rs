//! Decode CRAN's `Meta/archive.rds` enumeration without treating it as package metadata.

use std::error::Error;
use std::fmt;

use nrr_core::PackageName;
use rd_rds::{RObject, RStr, RValue, file::ReadOptions};

/// One historical source archive advertised by `Meta/archive.rds`.
///
/// This is deliberately limited to file enumeration.  Package version and
/// dependency metadata are read from the archive's `DESCRIPTION` instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveEntry {
    pub package: PackageName,
    pub path: Box<str>,
    pub size: u64,
    pub mtime: i64,
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
            Self::InvalidSize { row } => write!(f, "invalid archive size at row {row}"),
            Self::InvalidMtime { row } => write!(f, "invalid archive mtime at row {row}"),
        }
    }
}

impl Error for CranHistoryError {}

/// Decode a `Meta/archive.rds` named list or a `file.info`-shaped data frame.
pub fn enumerate_archive_rds(input: &[u8]) -> Result<Vec<ArchiveEntry>, CranHistoryError> {
    let object = rd_rds::file::from_bytes_with_options(input, &ReadOptions::default())
        .map_err(|error| CranHistoryError::Decode(error.to_string()))?;
    enumerate_object(&object)
}

fn enumerate_object(object: &RObject) -> Result<Vec<ArchiveEntry>, CranHistoryError> {
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
        return enumerate_frame(object, None);
    }

    let mut entries = Vec::new();
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
        entries.extend(enumerate_frame(item, Some(&package))?);
    }
    Ok(entries)
}

fn enumerate_frame(
    object: &RObject,
    package_hint: Option<&PackageName>,
) -> Result<Vec<ArchiveEntry>, CranHistoryError> {
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

    files
        .into_iter()
        .enumerate()
        .map(|(row, path)| {
            let path_package =
                package_from_path(&path).ok_or_else(|| CranHistoryError::InvalidPackage {
                    value: path.clone(),
                })?;
            if package_hint.is_some_and(|package| package != &path_package) {
                return Err(CranHistoryError::InvalidPackage {
                    value: path.clone(),
                });
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
            Ok(ArchiveEntry {
                package,
                path: path.into_boxed_str(),
                size: size as u64,
                mtime: mtime as i64,
            })
        })
        .collect()
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

fn package_from_path(path: &str) -> Option<PackageName> {
    let filename = path.rsplit('/').next()?;
    let package = filename.split_once('_')?.0;
    PackageName::new(package).ok()
}
