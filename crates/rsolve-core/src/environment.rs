use std::error::Error;
use std::fmt;

/// A validated shared environment coordinate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentId(Box<str>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvironmentIdError {
    Empty,
    ControlOrWhitespace,
}

impl fmt::Display for EnvironmentIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("environment ID is empty"),
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
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvironmentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
