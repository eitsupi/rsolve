use std::error::Error;
use std::fmt;

/// A validated shared environment coordinate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentId(Box<str>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvironmentIdError {
    Empty,
    TooLong,
    InvalidFirstCharacter,
    InvalidCharacter,
    ControlOrWhitespace,
}

impl fmt::Display for EnvironmentIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("environment ID is empty"),
            Self::TooLong => formatter.write_str("environment ID is longer than 64 characters"),
            Self::InvalidFirstCharacter => formatter
                .write_str("environment ID must start with a lowercase ASCII letter or digit"),
            Self::InvalidCharacter => formatter.write_str(
                "environment ID may contain only lowercase ASCII letters, digits, `_`, and `-`",
            ),
            Self::ControlOrWhitespace => {
                formatter.write_str("environment ID contains control or whitespace characters")
            }
        }
    }
}

impl Error for EnvironmentIdError {}

impl EnvironmentId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, EnvironmentIdError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(EnvironmentIdError::Empty);
        }
        if value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(EnvironmentIdError::ControlOrWhitespace);
        }
        let bytes = value.as_bytes();
        if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
            return Err(EnvironmentIdError::InvalidFirstCharacter);
        }
        if !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        }) {
            return Err(EnvironmentIdError::InvalidCharacter);
        }
        if value.len() > 64 {
            return Err(EnvironmentIdError::TooLong);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for EnvironmentId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for EnvironmentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_ids_use_filename_safe_ascii_coordinates() {
        assert!(EnvironmentId::new("a").is_ok());
        assert!(EnvironmentId::new("0-ci_test").is_ok());
        assert!(EnvironmentId::new("a".repeat(64)).is_ok());
        for value in ["", "_test", "-test", "Test", "test.name", "a/b"] {
            assert!(EnvironmentId::new(value).is_err(), "{value}");
        }
        assert!(matches!(
            EnvironmentId::new("a".repeat(65)),
            Err(EnvironmentIdError::TooLong)
        ));
    }
}
