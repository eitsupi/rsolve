use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A version using R's numeric-version semantics, rather than SemVer.
///
/// The original input is retained for display and provenance.  Equality,
/// ordering, and hashing use the canonical numeric components instead.
#[derive(Clone, Debug)]
pub struct RPackageVersion {
    raw: Box<str>,
    components: Components,
}

#[derive(Clone, Debug)]
enum Components {
    /// Eight is a measured CRAN-sized inline capacity, not a semantic limit.
    /// A current-CRAN measurement found component counts `2:2537`,
    /// `3:21500`, `4:585`, `5:9`, and `6:4`, with none at seven or above;
    /// eight leaves headroom and also matches `vctrs`'s choice.  Longer
    /// sequences spill to the vector variant below.
    Inline {
        values: [u32; 8],
        len: u8,
    },
    Spill(Vec<u32>),
}

impl Components {
    fn from_vec(values: Vec<u32>) -> Self {
        if values.len() <= 8 {
            let mut inline = [0; 8];
            inline[..values.len()].copy_from_slice(&values);
            Self::Inline {
                values: inline,
                len: values.len() as u8,
            }
        } else {
            Self::Spill(values)
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len as usize,
            Self::Spill(values) => values.len(),
        }
    }

    fn get(&self, index: usize) -> u32 {
        match self {
            Self::Inline { values, len } => {
                debug_assert!(index < *len as usize);
                values[index]
            }
            Self::Spill(values) => values[index],
        }
    }

    fn canonical_len(&self) -> usize {
        let mut len = self.len();
        while len > 0 && self.get(len - 1) == 0 {
            len -= 1;
        }
        len
    }

    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.canonical_len()).map(|index| self.get(index))
    }
}

/// Errors returned when parsing an R package or bare numeric version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RPackageVersionError {
    Empty,
    EmptyComponent { index: usize },
    NonNumericComponent { index: usize },
    ComponentOverflow { index: usize },
    TooFewComponents { found: usize, minimum: usize },
}

impl fmt::Display for RPackageVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("R version is empty"),
            Self::EmptyComponent { index } => write!(f, "R version component {index} is empty"),
            Self::NonNumericComponent { index } => {
                write!(f, "R version component {index} is not numeric")
            }
            Self::ComponentOverflow { index } => {
                write!(f, "R version component {index} overflows u32")
            }
            Self::TooFewComponents { found, minimum } => {
                write!(
                    f,
                    "R version has {found} component(s), minimum is {minimum}"
                )
            }
        }
    }
}

impl Error for RPackageVersionError {}

impl RPackageVersion {
    /// Parses a package version.  Package versions require at least two
    /// components; this is the distinction from a bare numeric R version.
    pub fn parse(input: &str) -> Result<Self, RPackageVersionError> {
        Self::parse_with_minimum(input, 2)
    }

    /// Parses a bare numeric R version, which may contain one component.
    pub fn parse_bare(input: &str) -> Result<Self, RPackageVersionError> {
        Self::parse_with_minimum(input, 1)
    }

    fn parse_with_minimum(input: &str, minimum: usize) -> Result<Self, RPackageVersionError> {
        if input.is_empty() {
            return Err(RPackageVersionError::Empty);
        }

        let mut components = Vec::new();
        for (index, component) in input.split(['.', '-']).enumerate() {
            if component.is_empty() {
                return Err(RPackageVersionError::EmptyComponent { index });
            }

            let mut value = 0u32;
            for byte in component.bytes() {
                if !byte.is_ascii_digit() {
                    return Err(RPackageVersionError::NonNumericComponent { index });
                }
                value = value
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(u32::from(byte - b'0')))
                    .ok_or(RPackageVersionError::ComponentOverflow { index })?;
            }
            components.push(value);
        }

        if components.len() < minimum {
            return Err(RPackageVersionError::TooFewComponents {
                found: components.len(),
                minimum,
            });
        }

        Ok(Self {
            raw: input.into(),
            components: Components::from_vec(components),
        })
    }

    /// Returns the original spelling, including separators and leading zeros.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns the parsed components before trailing-zero canonicalization.
    pub fn components(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.components.len()).map(|index| self.components.get(index))
    }

    /// Returns the number of components after trailing-zero canonicalization.
    pub fn canonical_component_count(&self) -> usize {
        self.components.canonical_len()
    }
}

impl fmt::Display for RPackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl PartialEq for RPackageVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RPackageVersion {}

impl PartialOrd for RPackageVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RPackageVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Deliberately use numeric_version/package_version semantics here:
        // R metadata mixes `R (>= 4.4)` and `R (>= 4.4.0)`, and R 4.4.0 must
        // satisfy both.  compareVersion() treats the shorter spelling as
        // lower, so using it would make equivalent real requirements differ.
        self.components.iter().cmp(other.components.iter())
    }
}

impl Hash for RPackageVersion {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash precisely the sequence used by Ord/Eq.  In particular, raw
        // spelling and trailing zeroes must never create a distinct key.
        let canonical_len = self.components.canonical_len();
        canonical_len.hash(state);
        for component in self.components.iter() {
            component.hash(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn version(value: &str) -> RPackageVersion {
        RPackageVersion::parse(value).unwrap()
    }

    #[test]
    fn version_rules_are_table_driven() {
        let cases = [
            ("1.7-0", "1.7.0", Ordering::Equal),
            ("01.2", "1.2", Ordering::Equal),
            ("1.10", "1.9", Ordering::Greater),
            ("4.4", "4.4.0", Ordering::Equal),
            ("1.0", "1.0.0.0", Ordering::Equal),
            ("1.0.1", "1.0", Ordering::Greater),
            ("20260000.1", "65535.999", Ordering::Greater),
            ("1.4.68.19.3.27", "1.4.68.19.3.28", Ordering::Less),
        ];
        for (left, right, expected) in cases {
            assert_eq!(
                version(left).cmp(&version(right)),
                expected,
                "{left} vs {right}"
            );
        }
    }

    #[test]
    fn version_preserves_spelling_and_spills_after_eight_components() {
        let parsed = version("01.7-0");
        assert_eq!(parsed.to_string(), "01.7-0");
        assert_eq!(parsed.components().collect::<Vec<_>>(), [1, 7, 0]);

        let nine = version("1.2.3.4.5.6.7.8.9");
        let nine_same = version("1-2-3-4-5-6-7-8-9");
        assert_eq!(nine.components().count(), 9);
        assert_eq!(nine, nine_same);
        assert_eq!(nine.cmp(&nine_same), Ordering::Equal);
    }

    #[test]
    fn versions_equal_in_hash_maps_when_only_spelling_or_trailing_zeroes_differ() {
        let mut map = HashMap::new();
        map.insert(version("4.4"), "found");
        assert_eq!(map.get(&version("4.4.0")), Some(&"found"));

        let mut first = std::collections::hash_map::DefaultHasher::new();
        let mut second = std::collections::hash_map::DefaultHasher::new();
        version("01.2-0").hash(&mut first);
        version("1.2.0").hash(&mut second);
        assert_eq!(first.finish(), second.finish());
    }

    #[test]
    fn comparison_pins_numeric_version_semantics_not_compare_version_semantics() {
        let short = version("4.4");
        let long = version("4.4.0");
        assert_eq!(short.cmp(&long), Ordering::Equal);
        assert_eq!(short, long);
    }

    #[test]
    fn package_and_bare_version_arity_are_distinct() {
        assert!(matches!(
            RPackageVersion::parse("1"),
            Err(RPackageVersionError::TooFewComponents { .. })
        ));
        assert_eq!(RPackageVersion::parse_bare("1").unwrap().as_str(), "1");
    }

    #[test]
    fn version_parse_errors_are_typed_and_non_panicking() {
        let cases = [
            ("", RPackageVersionError::Empty),
            (".1", RPackageVersionError::EmptyComponent { index: 0 }),
            ("1.", RPackageVersionError::EmptyComponent { index: 1 }),
            ("-1", RPackageVersionError::EmptyComponent { index: 0 }),
            ("1-", RPackageVersionError::EmptyComponent { index: 1 }),
            ("1..2", RPackageVersionError::EmptyComponent { index: 1 }),
            ("1.-2", RPackageVersionError::EmptyComponent { index: 1 }),
            (
                "1.a",
                RPackageVersionError::NonNumericComponent { index: 1 },
            ),
            (
                "4294967296.1",
                RPackageVersionError::ComponentOverflow { index: 0 },
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(RPackageVersion::parse(input), Err(expected));
        }
    }
}
