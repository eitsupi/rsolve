//! Lossless-enough DCF syntax parsing for PACKAGES and DESCRIPTION files.
//!
//! The parser deliberately owns the small nrr-facing representation rather
//! than exposing the parser crate's paragraph and field types. DCF field names
//! are retained with their original spelling and fields remain in source
//! order. Lookup uses ASCII case-insensitive comparison because DCF field
//! names are conventionally ASCII identifiers.
//!
//! The only transformations are DCF syntax transformations: horizontal space
//! immediately after a field colon is consumed as the field/value delimiter,
//! continuation indentation is removed, each continuation boundary becomes a
//! single `\n`, and CR bytes belonging to CRLF line endings are removed. All
//! other valid UTF-8 value bytes are retained.

use std::fmt;
use std::str::Utf8Error;

/// A syntax error found while reading a DCF document.
#[derive(Debug)]
pub enum DcfError {
    /// The input was not valid UTF-8.
    InvalidUtf8 {
        /// Byte offset at which decoding stopped.
        offset: usize,
        /// The underlying UTF-8 decoding error.
        source: Utf8Error,
    },
    /// A continuation line appeared before a field in its record.
    ContinuationBeforeField { line: usize },
    /// A non-empty, non-comment line did not contain a colon.
    MissingColon { line: usize },
    /// A field had no name before its colon.
    EmptyFieldName { line: usize },
    /// A bare carriage return was used as a line ending.
    InvalidLineEnding { line: usize },
    /// The input ended in the middle of a record line.
    TruncatedFinalRecord,
    /// The recoverable DCF parser rejected already validated input.
    ParserRejected(String),
}

impl fmt::Display for DcfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 { offset, .. } => {
                write!(f, "invalid UTF-8 at byte offset {offset}")
            }
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
            Self::TruncatedFinalRecord => f.write_str("truncated final DCF record"),
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

/// A DCF field with its original name spelling and unfolded value.
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
    /// A continuation line contributes a single `\n` followed by its content
    /// after the DCF continuation indentation. Horizontal space immediately
    /// after the field colon is syntax, not value content. No other value
    /// whitespace is trimmed or normalized.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// One DCF record (paragraph).
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
    ///
    /// The returned field is present even when its value is empty, so `None`
    /// means absent rather than present-but-empty.
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
}

/// A parsed DCF document containing zero or more records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcfDocument {
    records: Vec<DcfRecord>,
}

impl DcfDocument {
    /// Parses UTF-8 DCF bytes as either a multi-record index or one record.
    ///
    /// Both LF and CRLF line endings are accepted. A final line ending is
    /// required so an interrupted final record cannot be mistaken for a
    /// complete one. A record is not required to contain `Package`; that is
    /// metadata validation for the domain-conversion layer, not DCF syntax.
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
}

fn normalize_line_endings(input: &str) -> Result<String, DcfError> {
    if !input.ends_with(['\n', '\r']) {
        return Err(DcfError::TruncatedFinalRecord);
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
    Ok(normalized)
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
