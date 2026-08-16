use std::error::Error;
use std::fmt;

use time::Date;
use time::format_description::FormatItem;

const ISO_DATE_FORMAT: &[FormatItem<'static>] =
    time::macros::format_description!("[year]-[month]-[day]");

/// A validated, canonical calendar date with day precision.
///
/// The date implementation is intentionally opaque so the public domain API
/// does not expose the private date-library type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicationDate(Date);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationDateError {
    Invalid {
        input: Box<str>,
        diagnostic: Box<str>,
    },
    NonCanonical {
        input: Box<str>,
    },
}

impl fmt::Display for PublicationDateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { input, diagnostic } => {
                write!(
                    formatter,
                    "invalid publication date {input:?}: {diagnostic}"
                )
            }
            Self::NonCanonical { input } => {
                write!(formatter, "publication date {input:?} is not YYYY-MM-DD")
            }
        }
    }
}

impl Error for PublicationDateError {}

impl PublicationDate {
    /// Parses exactly the canonical `YYYY-MM-DD` spelling.
    pub fn parse(input: impl AsRef<str>) -> Result<Self, PublicationDateError> {
        let input = input.as_ref();
        let date =
            Date::parse(input, ISO_DATE_FORMAT).map_err(|error| PublicationDateError::Invalid {
                input: input.into(),
                diagnostic: error.to_string().into(),
            })?;
        let publication = Self(date);
        if publication.to_string() != input {
            return Err(PublicationDateError::NonCanonical {
                input: input.into(),
            });
        }
        Ok(publication)
    }

    /// Returns the canonical `YYYY-MM-DD` spelling.
    pub fn as_str(&self) -> String {
        self.0
            .format(ISO_DATE_FORMAT)
            .expect("the static publication date format is valid")
    }
}

impl fmt::Display for PublicationDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_str())
    }
}

/// Publication metadata for a release.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReleasePublication {
    date: PublicationDate,
}

/// An absolute publication-date cutoff supplied by a caller's policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicationCutoff(PublicationDate);

impl PublicationCutoff {
    pub fn new(date: PublicationDate) -> Self {
        Self(date)
    }

    pub fn date(&self) -> PublicationDate {
        self.0
    }
}

impl ReleasePublication {
    pub fn new(date: PublicationDate) -> Self {
        Self { date }
    }

    pub fn date(&self) -> PublicationDate {
        self.date
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_formats_and_orders_calendar_dates() {
        let older = PublicationDate::parse("2024-02-29").unwrap();
        let newer = PublicationDate::parse("2025-01-01").unwrap();
        assert_eq!(older.to_string(), "2024-02-29");
        assert!(older < newer);
    }

    #[test]
    fn rejects_invalid_calendar_and_noncanonical_spelling() {
        for value in ["2023-02-29", "2024-02-30", "2024-2-01", "2024-02-1"] {
            assert!(PublicationDate::parse(value).is_err(), "{value}");
        }
    }
}
