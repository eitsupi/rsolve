//! Backend-neutral DCF and R DESCRIPTION parsing primitives.
//!
//! CRAN and source-control adapters reuse this module for syntax and package
//! metadata semantics. Release identity and distribution evidence are kept at
//! each adapter boundary.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::str::Utf8Error;

use rsolve_core::{
    DeclaredDependency, DependencyKind, DependencySourceConstraint, PackageName, RPackageVersion,
    RelationOp, ReleaseMetadata, ReleasePublication, VersionConstraint,
};

/// A syntax error found while reading a DCF document.
#[derive(Debug)]
pub enum DcfError {
    /// The input was not valid UTF-8.
    InvalidUtf8 { offset: usize, source: Utf8Error },
    /// A continuation line appeared before a field in its record.
    ContinuationBeforeField { line: usize },
    /// A non-empty, non-comment line did not contain a colon.
    MissingColon { line: usize },
    /// A field had no name before its colon.
    EmptyFieldName { line: usize },
    /// A bare carriage return was used as a line ending.
    InvalidLineEnding { line: usize },
    /// The recoverable DCF parser rejected already validated input.
    ParserRejected(String),
}

impl fmt::Display for DcfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 { offset, .. } => write!(f, "invalid UTF-8 at byte offset {offset}"),
            Self::ContinuationBeforeField { line } => {
                write!(f, "continuation line before a field at line {line}")
            }
            Self::MissingColon { line } => write!(f, "field line has no colon at line {line}"),
            Self::EmptyFieldName { line } => write!(f, "empty field name at line {line}"),
            Self::InvalidLineEnding { line } => {
                write!(
                    f,
                    "unsupported bare carriage-return line ending at line {line}"
                )
            }
            Self::ParserRejected(message) => write!(f, "DCF parser rejected input: {message}"),
        }
    }
}

impl std::error::Error for DcfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8 { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcfField {
    name: String,
    value: String,
}

impl DcfField {
    /// Returns the field name exactly as it appeared in the input.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the logical unfolded field value.
    ///
    /// Continuation boundaries become a single newline and continuation
    /// indentation is removed. Other valid UTF-8 value bytes are retained.
    pub fn value(&self) -> &str {
        &self.value
    }

    pub(crate) fn into_parts(self) -> (String, String) {
        (self.name, self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcfRecord {
    fields: Vec<DcfField>,
}

impl DcfRecord {
    /// Returns fields in their original source order.
    pub fn fields(&self) -> &[DcfField] {
        &self.fields
    }

    /// Looks up the first field with an ASCII case-insensitive name.
    pub fn field(&self, name: &str) -> Option<&DcfField> {
        self.fields
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(name))
    }

    /// Returns all fields with an ASCII case-insensitive name.
    pub fn fields_named(&self, name: &str) -> impl Iterator<Item = &DcfField> {
        self.fields
            .iter()
            .filter(move |field| field.name.eq_ignore_ascii_case(name))
    }

    pub(crate) fn into_fields(self) -> Vec<DcfField> {
        self.fields
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcfDocument {
    records: Vec<DcfRecord>,
}

impl DcfDocument {
    /// Parses UTF-8 DCF bytes as zero or more records.
    ///
    /// Both LF and CRLF line endings are accepted. EOF terminates the final
    /// record, just as R's `read.dcf()` does.
    pub fn parse(input: &[u8]) -> Result<Self, DcfError> {
        let input = std::str::from_utf8(input).map_err(|source| DcfError::InvalidUtf8 {
            offset: source.valid_up_to(),
            source,
        })?;
        let normalized = normalize_line_endings(input)?;
        validate_lines(&normalized)?;
        let paragraphs = deb822_fast::borrowed::parse_borrowed(&normalized)
            .map_err(|error| DcfError::ParserRejected(error.to_string()))?;
        let records = paragraphs
            .into_iter()
            .map(|paragraph| DcfRecord {
                fields: paragraph
                    .iter()
                    .map(|field| DcfField {
                        name: field.name().to_owned(),
                        value: field.join(),
                    })
                    .collect(),
            })
            .collect();
        Ok(Self { records })
    }

    /// Parses a UTF-8 string as DCF.
    pub fn parse_str(input: &str) -> Result<Self, DcfError> {
        Self::parse(input.as_bytes())
    }

    /// Returns records in their original source order.
    pub fn records(&self) -> &[DcfRecord] {
        &self.records
    }

    /// Returns the number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether the document has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(crate) fn into_records(self) -> Vec<DcfRecord> {
        self.records
    }
}

/// Parsed DESCRIPTION semantics without release identity or distributions.
#[derive(Debug)]
pub(crate) struct ParsedDescription {
    pub(crate) package: PackageName,
    pub(crate) version: RPackageVersion,
    pub(crate) metadata: ReleaseMetadata,
    pub(crate) publication: Option<ReleasePublication>,
    pub(crate) dependencies: Vec<DeclaredDependency>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum DescriptionError {
    MissingField(&'static str),
    DuplicateField(String),
    InvalidPackageName(rsolve_core::PackageNameError),
    InvalidVersion(rsolve_core::RPackageVersionError),
    InvalidMetadata(rsolve_core::ReleaseMetadataError),
    InvalidPublicationDate {
        value: String,
        diagnostic: String,
    },
    InvalidDependency(String),
    Dependency {
        field: &'static str,
        entry: String,
        source: DependencyParseError,
    },
}

pub(crate) struct ParsedDependency {
    pub(crate) name: PackageName,
    pub(crate) constraint: VersionConstraint,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DependencyParseError {
    EmptyEntry,
    InvalidPackageName(rsolve_core::PackageNameError),
    InvalidConstraintSyntax,
    MissingConstraintVersion,
    InvalidVersion(rsolve_core::RPackageVersionError),
}

impl fmt::Display for DependencyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEntry => f.write_str("dependency entry is empty"),
            Self::InvalidPackageName(error) => error.fmt(f),
            Self::InvalidConstraintSyntax => f.write_str("invalid version constraint syntax"),
            Self::MissingConstraintVersion => f.write_str("version constraint has no version"),
            Self::InvalidVersion(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DependencyParseError {}

pub(crate) fn parse_dependency_entry(
    input: &str,
) -> Result<ParsedDependency, DependencyParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(DependencyParseError::EmptyEntry);
    }
    let (name_text, constraint) = match input.find('(') {
        Some(open) => {
            if !input.ends_with(')') {
                return Err(DependencyParseError::InvalidConstraintSyntax);
            }
            let expression = &input[open + 1..input.len() - 1];
            if expression.contains(['(', ')']) {
                return Err(DependencyParseError::InvalidConstraintSyntax);
            }
            (input[..open].trim(), Some(parse_constraint(expression)?))
        }
        None => {
            if input.contains(')') {
                return Err(DependencyParseError::InvalidConstraintSyntax);
            }
            (input, None)
        }
    };
    let name = PackageName::new(name_text).map_err(DependencyParseError::InvalidPackageName)?;
    Ok(ParsedDependency {
        name,
        constraint: constraint.unwrap_or_else(VersionConstraint::unconstrained),
    })
}

fn parse_constraint(input: &str) -> Result<VersionConstraint, DependencyParseError> {
    let operators = [
        (">=", RelationOp::Ge),
        ("<=", RelationOp::Le),
        ("==", RelationOp::Eq),
        ("!=", RelationOp::Ne),
        (">", RelationOp::Gt),
        ("<", RelationOp::Lt),
    ];
    let (operator, op) = operators
        .iter()
        .find(|(operator, _)| input.starts_with(operator))
        .ok_or(DependencyParseError::InvalidConstraintSyntax)?;
    let version_text = input[operator.len()..].trim();
    if version_text.is_empty() {
        return Err(DependencyParseError::MissingConstraintVersion);
    }
    let version =
        RPackageVersion::parse(version_text).map_err(DependencyParseError::InvalidVersion)?;
    Ok(VersionConstraint::from_clause(*op, version))
}

impl fmt::Display for DescriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required field {field}"),
            Self::DuplicateField(field) => write!(f, "duplicate field {field}"),
            Self::InvalidPackageName(reason) => write!(f, "invalid package name: {reason}"),
            Self::InvalidVersion(reason) => write!(f, "invalid version: {reason}"),
            Self::InvalidMetadata(reason) => write!(f, "invalid metadata: {reason}"),
            Self::InvalidPublicationDate { value, diagnostic } => {
                write!(f, "invalid Published value {value:?}: {diagnostic}")
            }
            Self::InvalidDependency(reason) => write!(f, "invalid dependency: {reason}"),
            Self::Dependency {
                field,
                entry,
                source,
            } => write!(f, "invalid {field} entry {entry:?}: {source}"),
        }
    }
}

impl std::error::Error for DescriptionError {}

pub(crate) fn parse_description_fields(
    fields: &[(&str, &str)],
) -> Result<ParsedDescription, DescriptionError> {
    reject_duplicate_fields(fields)?;
    let version = RPackageVersion::parse(required_field(fields, "Version")?.trim())
        .map_err(DescriptionError::InvalidVersion)?;
    let package = PackageName::new(required_field(fields, "Package")?.trim())
        .map_err(DescriptionError::InvalidPackageName)?;
    let publication = field(fields, "Published")
        .map(parse_publication_date)
        .transpose()?;
    let mut dependencies = Vec::new();
    for (field_name, kind) in [
        ("Depends", DependencyKind::Depends),
        ("Imports", DependencyKind::Imports),
        ("LinkingTo", DependencyKind::LinkingTo),
        ("Suggests", DependencyKind::Suggests),
        ("Enhances", DependencyKind::Enhances),
    ] {
        if let Some(value) = field(fields, field_name) {
            for entry in value.split_terminator(',') {
                let dependency = parse_dependency_entry(entry).map_err(|source| {
                    DescriptionError::Dependency {
                        field: field_name,
                        entry: entry.trim().to_owned(),
                        source,
                    }
                })?;
                dependencies.push(
                    DeclaredDependency::from_parts(
                        kind,
                        dependency.name,
                        DependencySourceConstraint::Any,
                        dependency.constraint,
                    )
                    .map_err(|error| DescriptionError::InvalidDependency(error.to_string()))?,
                );
            }
        }
    }
    let metadata = ReleaseMetadata::new(
        fields
            .iter()
            .filter(|(name, _)| !is_reserved_field(name))
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
    )
    .map_err(DescriptionError::InvalidMetadata)?;
    Ok(ParsedDescription {
        package,
        version,
        metadata,
        publication,
        dependencies,
    })
}

fn normalize_line_endings(input: &str) -> Result<Cow<'_, str>, DcfError> {
    if !input.as_bytes().contains(&b'\r') && (input.is_empty() || input.ends_with('\n')) {
        return Ok(Cow::Borrowed(input));
    }
    let mut normalized = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut line = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                if bytes.get(index + 1) != Some(&b'\n') {
                    return Err(DcfError::InvalidLineEnding { line });
                }
                normalized.push('\n');
                index += 2;
                line += 1;
            }
            b'\n' => {
                normalized.push('\n');
                index += 1;
                line += 1;
            }
            _ => {
                let Some(character) = input[index..].chars().next() else {
                    return Err(DcfError::ParserRejected(
                        "input ended at an invalid UTF-8 character boundary".to_owned(),
                    ));
                };
                normalized.push(character);
                index += character.len_utf8();
            }
        }
    }
    if !normalized.is_empty() && !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    Ok(Cow::Owned(normalized))
}

fn validate_lines(input: &str) -> Result<(), DcfError> {
    let mut has_field = false;
    for (line_index, line) in input.split('\n').enumerate() {
        let line_number = line_index + 1;
        if line.is_empty() {
            has_field = false;
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if !has_field {
                return Err(DcfError::ContinuationBeforeField { line: line_number });
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let Some(colon) = line.find(':') else {
            return Err(DcfError::MissingColon { line: line_number });
        };
        if colon == 0 {
            return Err(DcfError::EmptyFieldName { line: line_number });
        }
        has_field = true;
    }
    Ok(())
}

fn required_field<'a>(
    fields: &'a [(&str, &str)],
    name: &'static str,
) -> Result<&'a str, DescriptionError> {
    field(fields, name).ok_or(DescriptionError::MissingField(name))
}

fn field<'a>(fields: &'a [(&str, &str)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field_name, _)| field_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| *value)
}

fn reject_duplicate_fields(fields: &[(&str, &str)]) -> Result<(), DescriptionError> {
    let mut names = BTreeSet::new();
    for (name, _) in fields {
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(DescriptionError::DuplicateField((*name).to_owned()));
        }
    }
    Ok(())
}

fn is_reserved_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "package"
            | "version"
            | "depends"
            | "imports"
            | "linkingto"
            | "suggests"
            | "enhances"
            | "md5sum"
            | "published"
    )
}

fn parse_publication_date(value: &str) -> Result<ReleasePublication, DescriptionError> {
    let value = value.trim();
    let date = if value.len() == 10 {
        rsolve_core::PublicationDate::parse(value).map_err(|error| {
            DescriptionError::InvalidPublicationDate {
                value: value.to_owned(),
                diagnostic: error.to_string(),
            }
        })?
    } else {
        let (format, has_utc_suffix) = match value.len() {
            19 => ("%Y-%m-%d %H:%M:%S", false),
            23 => ("%Y-%m-%d %H:%M:%S UTC", true),
            _ => {
                return Err(DescriptionError::InvalidPublicationDate {
                    value: value.to_owned(),
                    diagnostic: "Published datetime must use an accepted full-string spelling"
                        .into(),
                });
            }
        };
        if has_utc_suffix && !value.ends_with(" UTC") {
            return Err(DescriptionError::InvalidPublicationDate {
                value: value.to_owned(),
                diagnostic: "Published datetime must end with uppercase UTC".into(),
            });
        }
        let datetime = jiff::civil::DateTime::strptime(format, value).map_err(|error| {
            DescriptionError::InvalidPublicationDate {
                value: value.to_owned(),
                diagnostic: error.to_string(),
            }
        })?;
        let canonical = datetime.strftime(format).to_string();
        if canonical != value {
            return Err(DescriptionError::InvalidPublicationDate {
                value: value.to_owned(),
                diagnostic: "Published datetime is not canonical".into(),
            });
        }
        let date = datetime.date().strftime("%Y-%m-%d").to_string();
        rsolve_core::PublicationDate::parse(&date).map_err(|error| {
            DescriptionError::InvalidPublicationDate {
                value: value.to_owned(),
                diagnostic: error.to_string(),
            }
        })?
    };
    Ok(ReleasePublication::new(date))
}
