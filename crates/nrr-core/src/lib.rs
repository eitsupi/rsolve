//! Domain model and provider-facing ports for nrr.
//!
//! This crate intentionally contains no transport, runtime, parser, solver,
//! cache, or CLI implementation details.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// R versions

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

// ---------------------------------------------------------------------------
// Names and opaque domain identifiers

/// A canonical R package name.
///
/// R package names are case-sensitive and are not case-folded here.  The
/// validation follows R's package-name character rule: an ASCII letter first,
/// followed by ASCII letters, digits, or periods, without a trailing period.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageName(Box<str>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageNameError {
    Empty,
    InvalidFirstCharacter,
    InvalidCharacter { index: usize },
    TrailingPeriod,
}

impl fmt::Display for PackageNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("package name is empty"),
            Self::InvalidFirstCharacter => f.write_str("package name must start with a letter"),
            Self::InvalidCharacter { index } => {
                write!(f, "package name has an invalid character at {index}")
            }
            Self::TrailingPeriod => f.write_str("package name must not end with a period"),
        }
    }
}

impl Error for PackageNameError {}

impl PackageName {
    pub fn new(input: impl AsRef<str>) -> Result<Self, PackageNameError> {
        let input = input.as_ref();
        if input.is_empty() {
            return Err(PackageNameError::Empty);
        }
        if !input.as_bytes()[0].is_ascii_alphabetic() {
            return Err(PackageNameError::InvalidFirstCharacter);
        }
        for (index, byte) in input.bytes().enumerate() {
            if !(byte.is_ascii_alphanumeric() || byte == b'.') {
                return Err(PackageNameError::InvalidCharacter { index });
            }
        }
        if input.ends_with('.') {
            return Err(PackageNameError::TrailingPeriod);
        }
        Ok(Self(input.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for PackageName {
    type Error = PackageNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

macro_rules! opaque_identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            pub fn new(input: impl AsRef<str>) -> Result<Self, IdentifierError> {
                let input = input.as_ref();
                if input.is_empty() {
                    return Err(IdentifierError::Empty {
                        kind: stringify!($name),
                    });
                }
                if input.chars().any(char::is_control) {
                    return Err(IdentifierError::ControlCharacter {
                        kind: stringify!($name),
                    });
                }
                Ok(Self(input.into()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    Empty { kind: &'static str },
    ControlCharacter { kind: &'static str },
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { kind } => write!(f, "{kind} is empty"),
            Self::ControlCharacter { kind } => write!(f, "{kind} contains a control character"),
        }
    }
}

impl Error for IdentifierError {}

/// A canonical repository URL coordinate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedGitUrl(Box<str>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedGitUrlError {
    Empty,
    InvalidScheme,
    MissingAuthority,
    CredentialsForbidden,
    QueryOrFragmentForbidden,
    InvalidHost,
    InvalidPort,
    InvalidPercentEscape,
    ControlOrWhitespace,
}

impl fmt::Display for NormalizedGitUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "normalized Git URL is empty",
            Self::InvalidScheme => "normalized Git URL has an invalid or non-canonical scheme",
            Self::MissingAuthority => "normalized Git URL must have an authority",
            Self::CredentialsForbidden => "normalized Git URL must not contain credentials",
            Self::QueryOrFragmentForbidden => {
                "normalized Git URL must not contain a query or fragment"
            }
            Self::InvalidHost => "normalized Git URL has an invalid host",
            Self::InvalidPort => "normalized Git URL has an invalid port",
            Self::InvalidPercentEscape => "normalized Git URL has an invalid percent escape",
            Self::ControlOrWhitespace => "normalized Git URL contains control or whitespace",
        };
        f.write_str(message)
    }
}

impl Error for NormalizedGitUrlError {}

impl NormalizedGitUrl {
    /// Canonicalise only URL equivalences that are local and unambiguous.
    /// Provider-specific aliases and repository equivalences remain distinct.
    /// Ref resolution, Git fetching, R-universe ingestion, and provider alias
    /// tables are intentionally deferred; the first slice uses CRAN sources.
    pub fn new(input: impl AsRef<str>) -> Result<Self, NormalizedGitUrlError> {
        let input = input.as_ref();
        if input.is_empty() {
            return Err(NormalizedGitUrlError::Empty);
        }
        if input
            .chars()
            .any(|character| character.is_control() || character.is_ascii_whitespace())
        {
            return Err(NormalizedGitUrlError::ControlOrWhitespace);
        }
        if input.contains('?') || input.contains('#') {
            return Err(NormalizedGitUrlError::QueryOrFragmentForbidden);
        }

        let Some(scheme_end) = input.find("://") else {
            return Err(NormalizedGitUrlError::InvalidScheme);
        };
        let scheme = &input[..scheme_end];
        if scheme.is_empty()
            || !scheme.as_bytes()[0].is_ascii_alphabetic()
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        {
            return Err(NormalizedGitUrlError::InvalidScheme);
        }
        let scheme = scheme.to_ascii_lowercase();
        let remainder = &input[scheme_end + 3..];
        let authority_end = remainder.find('/').unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        if authority.is_empty() {
            return Err(NormalizedGitUrlError::MissingAuthority);
        }
        if authority.contains('@') {
            return Err(NormalizedGitUrlError::CredentialsForbidden);
        }

        let (host, port) = canonical_host_and_port(authority)?;
        let path = normalize_url_component(&remainder[authority_end..])?;
        let port = port.filter(|port| !is_default_port(&scheme, *port));

        let mut canonical = format!("{scheme}://{host}");
        if let Some(port) = port {
            canonical.push(':');
            canonical.push_str(&port.to_string());
        }
        canonical.push_str(&path);
        Ok(Self(canonical.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NormalizedGitUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn canonical_host_and_port(
    authority: &str,
) -> Result<(String, Option<u16>), NormalizedGitUrlError> {
    let (host, port_text): (String, Option<&str>) = if let Some(rest) = authority.strip_prefix('[')
    {
        let Some(close) = rest.find(']') else {
            return Err(NormalizedGitUrlError::InvalidHost);
        };
        let host = &rest[..close];
        let remainder = &rest[close + 1..];
        let port = remainder.strip_prefix(':');
        if port.is_none() && !remainder.is_empty() {
            return Err(NormalizedGitUrlError::InvalidHost);
        }
        let address = IpAddr::from_str(host).map_err(|_| NormalizedGitUrlError::InvalidHost)?;
        if !matches!(address, IpAddr::V6(_)) {
            return Err(NormalizedGitUrlError::InvalidHost);
        }
        (format!("[{}]", address), port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            Some(_) => return Err(NormalizedGitUrlError::InvalidHost),
            None => (authority, None),
        };
        (host.to_owned(), port)
    };

    if host.is_empty() || host.contains('%') {
        return Err(NormalizedGitUrlError::InvalidHost);
    }
    let canonical_host = if host.starts_with('[') {
        host
    } else if let Ok(address) = IpAddr::from_str(&host) {
        address.to_string()
    } else {
        if !host.is_ascii()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(NormalizedGitUrlError::InvalidHost);
        }
        host.to_ascii_lowercase()
    };

    let port = port_text
        .map(|port| {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(NormalizedGitUrlError::InvalidPort);
            }
            port.parse::<u16>()
                .map_err(|_| NormalizedGitUrlError::InvalidPort)
        })
        .transpose()?;
    Ok((canonical_host, port))
}

fn is_default_port(scheme: &str, port: u16) -> bool {
    matches!(
        (scheme, port),
        ("https", 443) | ("http", 80) | ("ssh", 22) | ("git", 9418)
    )
}

fn normalize_url_component(component: &str) -> Result<String, NormalizedGitUrlError> {
    let mut normalized = String::with_capacity(component.len());
    let bytes = component.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(NormalizedGitUrlError::InvalidPercentEscape);
            }
            let value = (hex_value(bytes[index + 1]) << 4) | hex_value(bytes[index + 2]);
            if is_url_unreserved(value) {
                normalized.push(char::from(value));
            } else {
                normalized.push('%');
                normalized.push(char::from(bytes[index + 1]).to_ascii_uppercase());
                normalized.push(char::from(bytes[index + 2]).to_ascii_uppercase());
            }
            index += 3;
        } else {
            let character = component[index..]
                .chars()
                .next()
                .ok_or(NormalizedGitUrlError::InvalidPercentEscape)?;
            normalized.push(character);
            index += character.len_utf8();
        }
    }
    Ok(normalized)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("hex_value called for a non-hexadecimal byte"),
    }
}

fn is_url_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// A resolved full Git object ID. References and abbreviated object IDs are
/// intentionally not representable by this type.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitCommitId {
    algorithm: GitHashAlgorithm,
    hex: Box<str>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GitHashAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitCommitIdError {
    WrongLength { found: usize },
    NonHexadecimal,
}

impl fmt::Display for GitCommitIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { found } => {
                write!(
                    f,
                    "Git commit OID has invalid length {found}; expected 40 or 64"
                )
            }
            Self::NonHexadecimal => f.write_str("Git commit OID is not hexadecimal"),
        }
    }
}

impl Error for GitCommitIdError {}

impl GitCommitId {
    pub fn new(input: impl AsRef<str>) -> Result<Self, GitCommitIdError> {
        let input = input.as_ref();
        let algorithm = match input.len() {
            40 => GitHashAlgorithm::Sha1,
            64 => GitHashAlgorithm::Sha256,
            found => return Err(GitCommitIdError::WrongLength { found }),
        };
        if !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(GitCommitIdError::NonHexadecimal);
        }
        Ok(Self {
            algorithm,
            hex: input.to_ascii_lowercase().into(),
        })
    }

    pub fn algorithm(&self) -> GitHashAlgorithm {
        self.algorithm
    }

    pub fn as_str(&self) -> &str {
        &self.hex
    }
}

impl fmt::Display for GitCommitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex)
    }
}

opaque_identifier!(PackageNamespace);
opaque_identifier!(BioconductorRelease);
opaque_identifier!(RepositorySubdir);
opaque_identifier!(RegistryId);
opaque_identifier!(SnapshotId);
opaque_identifier!(ArtifactLocator);
opaque_identifier!(DistributionChannel);
opaque_identifier!(SourceScheme);

/// A validated lower-case hexadecimal SHA-256 digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest(Box<str>);

impl Sha256Digest {
    pub fn new(input: impl AsRef<str>) -> Result<Self, DigestError> {
        let input = input.as_ref();
        if input.len() != 64 {
            return Err(DigestError::WrongLength { found: input.len() });
        }
        if !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DigestError::NonHexadecimal);
        }
        Ok(Self(input.to_ascii_lowercase().into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DigestError {
    WrongLength { found: usize },
    NonHexadecimal,
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { found } => write!(f, "SHA-256 digest has length {found}, not 64"),
            Self::NonHexadecimal => f.write_str("SHA-256 digest contains a non-hexadecimal byte"),
        }
    }
}

impl Error for DigestError {}

// ---------------------------------------------------------------------------
// Constraints and dependencies

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RelationOp {
    Lt,
    Le,
    Eq,
    Ne,
    Ge,
    Gt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionClause {
    pub op: RelationOp,
    pub version: RPackageVersion,
}

impl VersionClause {
    pub fn new(op: RelationOp, version: RPackageVersion) -> Self {
        Self { op, version }
    }
}

/// A conjunction of R package-version relation clauses.
///
/// An empty clause list is the explicit unconstrained case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionConstraint {
    pub clauses: Vec<VersionClause>,
}

impl VersionConstraint {
    pub fn unconstrained() -> Self {
        Self { clauses: vec![] }
    }

    pub fn any() -> Self {
        Self::unconstrained()
    }

    pub fn new(clauses: Vec<VersionClause>) -> Self {
        Self { clauses }
    }

    pub fn from_clause(op: RelationOp, version: RPackageVersion) -> Self {
        Self::new(vec![VersionClause::new(op, version)])
    }

    pub fn is_unconstrained(&self) -> bool {
        self.clauses.is_empty()
    }

    pub fn satisfies(&self, candidate: &RPackageVersion) -> bool {
        self.clauses.iter().all(|clause| {
            let ordering = candidate.cmp(&clause.version);
            match clause.op {
                RelationOp::Lt => ordering == Ordering::Less,
                RelationOp::Le => ordering != Ordering::Greater,
                RelationOp::Eq => ordering == Ordering::Equal,
                RelationOp::Ne => ordering != Ordering::Equal,
                RelationOp::Ge => ordering != Ordering::Less,
                RelationOp::Gt => ordering == Ordering::Greater,
            }
        })
    }

    pub fn matches(&self, candidate: &RPackageVersion) -> bool {
        self.satisfies(candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DependencyKind {
    Depends,
    Imports,
    LinkingTo,
    Suggests,
    Enhances,
}

/// An optional source scope for a dependency.  R DESCRIPTION dependencies
/// normally use [`Any`], while providers may preserve a more specific scope.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub enum DependencySourceConstraint {
    #[default]
    Any,
    Registry {
        namespace: PackageNamespace,
    },
    Bioconductor {
        namespace: PackageNamespace,
        release: BioconductorRelease,
    },
    Git {
        repository: NormalizedGitUrl,
    },
    Exact(ReleaseIdentity),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyRequirement {
    pub kind: DependencyKind,
    pub name: PackageName,
    pub source: DependencySourceConstraint,
    pub constraint: VersionConstraint,
}

impl DependencyRequirement {
    pub fn new(
        kind: DependencyKind,
        name: PackageName,
        source: DependencySourceConstraint,
        constraint: VersionConstraint,
    ) -> Self {
        Self {
            kind,
            name,
            source,
            constraint,
        }
    }
}

// ---------------------------------------------------------------------------
// Identity and artifacts

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Provenance {
    RegistryRelease {
        namespace: PackageNamespace,
        version: RPackageVersion,
    },
    GitCommit {
        repository: NormalizedGitUrl,
        commit: GitCommitId,
        subdirectory: Option<RepositorySubdir>,
    },
    BioconductorRelease {
        namespace: PackageNamespace,
        release: BioconductorRelease,
        version: RPackageVersion,
    },
    ImmutableSource {
        scheme: SourceScheme,
        digest: Sha256Digest,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ReleaseIdentity {
    name: PackageName,
    provenance: Provenance,
}

impl ReleaseIdentity {
    pub fn new(name: PackageName, provenance: Provenance) -> Self {
        Self { name, provenance }
    }

    pub fn name(&self) -> &PackageName {
        &self.name
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum UpstreamChecksum {
    Md5(Box<str>),
    Sha256(Sha256Digest),
    Other {
        algorithm: Box<str>,
        value: Box<str>,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SourceArtifact {
    pub locator: ArtifactLocator,
    pub upstream_checksums: Vec<UpstreamChecksum>,
    pub size: Option<u64>,
}

/// Artifacts are typed separately from release identity.  The first slice
/// models source artifacts only; adding binary variants later does not change
/// the `ReleaseIdentity` coordinate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Artifact {
    Source(SourceArtifact),
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct DistributionMetadata {
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Distribution {
    pub registry: RegistryId,
    pub channel: DistributionChannel,
    pub snapshot: Option<SnapshotId>,
    pub artifacts: Vec<Artifact>,
    pub observed_metadata: DistributionMetadata,
}

// ---------------------------------------------------------------------------
// Metadata, release observations, and canonical construction

/// Normalized metadata excluding `Package`, `Version`, and every dependency
/// field.  Dependencies have exactly one home: `ReleaseObservation` and then
/// the validated `PackageRelease`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct ReleaseMetadata {
    fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseMetadataError {
    ReservedField { field: String },
}

impl fmt::Display for ReleaseMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedField { field } => {
                write!(f, "release metadata field {field:?} is not metadata")
            }
        }
    }
}

impl Error for ReleaseMetadataError {}

impl ReleaseMetadata {
    pub fn new(fields: BTreeMap<String, String>) -> Result<Self, ReleaseMetadataError> {
        for field in fields.keys() {
            let normalized = field.to_ascii_lowercase();
            if matches!(
                normalized.as_str(),
                "package"
                    | "version"
                    | "depends"
                    | "imports"
                    | "linkingto"
                    | "suggests"
                    | "enhances"
            ) {
                return Err(ReleaseMetadataError::ReservedField {
                    field: field.clone(),
                });
            }
        }
        Ok(Self { fields })
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, ReleaseMetadataError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self::new(
            pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        )
    }

    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }
}

#[derive(Clone, Debug)]
pub struct ReleaseObservation {
    pub identity: ReleaseIdentity,
    pub observed_package: PackageName,
    pub observed_version: RPackageVersion,
    pub metadata: ReleaseMetadata,
    pub dependencies: Vec<DependencyRequirement>,
    pub distributions: Vec<Distribution>,
}

/// A validated resolver-facing release.
///
/// Deliberately do not implement identity-only `Eq` or `Hash` for this type.
/// If two observations of one Git commit declared different versions were
/// inserted into a `HashSet<PackageRelease>` keyed only by identity, the
/// second observation could be silently discarded and the required
/// `ConflictingMetadata` error would never be detected.  Aggregation therefore
/// keys by [`ReleaseIdentity`] and checks metadata before merging.
#[derive(Clone, Debug)]
pub struct PackageRelease {
    identity: ReleaseIdentity,
    version: RPackageVersion,
    metadata: ReleaseMetadata,
    dependencies: Vec<DependencyRequirement>,
    distributions: Vec<Distribution>,
    metadata_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageReleaseError {
    ConflictingMetadata { field: &'static str },
    InvalidMetadata(ReleaseMetadataError),
    InvalidDependency { index: usize },
}

impl fmt::Display for PackageReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingMetadata { field } => {
                write!(f, "conflicting release metadata in {field}")
            }
            Self::InvalidMetadata(error) => error.fmt(f),
            Self::InvalidDependency { index } => write!(f, "invalid dependency at index {index}"),
        }
    }
}

impl Error for PackageReleaseError {}

impl TryFrom<ReleaseObservation> for PackageRelease {
    type Error = PackageReleaseError;

    fn try_from(observation: ReleaseObservation) -> Result<Self, Self::Error> {
        if observation.identity.name() != &observation.observed_package {
            return Err(PackageReleaseError::ConflictingMetadata {
                field: "package name",
            });
        }

        match observation.identity.provenance() {
            Provenance::RegistryRelease { version, .. }
            | Provenance::BioconductorRelease { version, .. } => {
                if version != &observation.observed_version {
                    return Err(PackageReleaseError::ConflictingMetadata {
                        field: "provenance version",
                    });
                }
            }
            Provenance::GitCommit { .. } | Provenance::ImmutableSource { .. } => {
                // For immutable sources the observed DESCRIPTION version is
                // validated metadata, not an identity coordinate.
            }
        }

        for (index, dependency) in observation.dependencies.iter().enumerate() {
            let invalid_exact_name = match &dependency.source {
                DependencySourceConstraint::Exact(identity) => identity.name() != &dependency.name,
                _ => false,
            };
            if dependency.name.as_str().is_empty() || invalid_exact_name {
                return Err(PackageReleaseError::InvalidDependency { index });
            }
        }

        let mut distributions = observation.distributions;
        let mut unique_distributions = Vec::with_capacity(distributions.len());
        for distribution in distributions.drain(..) {
            if !unique_distributions.contains(&distribution) {
                unique_distributions.push(distribution);
            }
        }

        Ok(Self {
            identity: observation.identity,
            version: observation.observed_version,
            metadata: observation.metadata,
            dependencies: observation.dependencies,
            distributions: unique_distributions,
            metadata_digest: None,
        })
    }
}

impl PackageRelease {
    pub fn identity(&self) -> &ReleaseIdentity {
        &self.identity
    }

    pub fn version(&self) -> &RPackageVersion {
        &self.version
    }

    pub fn metadata(&self) -> &ReleaseMetadata {
        &self.metadata
    }

    pub fn dependencies(&self) -> &[DependencyRequirement] {
        &self.dependencies
    }

    pub fn distributions(&self) -> &[Distribution] {
        &self.distributions
    }

    pub fn metadata_digest(&self) -> Option<&Sha256Digest> {
        self.metadata_digest.as_ref()
    }

    fn merge_distributions(&mut self, incoming: &[Distribution]) {
        for distribution in incoming {
            if !self.distributions.contains(distribution) {
                self.distributions.push(distribution.clone());
            }
        }
    }
}

/// Identity-keyed release aggregation.  A name/version match alone never
/// joins entries; distinct provenance produces distinct map entries.
#[derive(Clone, Debug, Default)]
pub struct ReleaseAggregation {
    releases: HashMap<ReleaseIdentity, PackageRelease>,
}

impl ReleaseAggregation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, observation: ReleaseObservation) -> Result<(), PackageReleaseError> {
        let release = PackageRelease::try_from(observation)?;
        if let Some(existing) = self.releases.get_mut(release.identity()) {
            if existing.version != release.version {
                return Err(PackageReleaseError::ConflictingMetadata { field: "version" });
            }
            if existing.metadata != release.metadata {
                return Err(PackageReleaseError::ConflictingMetadata { field: "metadata" });
            }
            if existing.dependencies != release.dependencies {
                return Err(PackageReleaseError::ConflictingMetadata {
                    field: "dependencies",
                });
            }
            existing.merge_distributions(&release.distributions);
        } else {
            self.releases.insert(release.identity.clone(), release);
        }
        Ok(())
    }

    pub fn get(&self, identity: &ReleaseIdentity) -> Option<&PackageRelease> {
        self.releases.get(identity)
    }

    pub fn len(&self) -> usize {
        self.releases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.releases.is_empty()
    }

    pub fn releases(&self) -> impl Iterator<Item = &PackageRelease> {
        self.releases.values()
    }
}

// ---------------------------------------------------------------------------
// Target representation

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Target {
    pub os: Box<str>,
    pub arch: Box<str>,
}

impl Target {
    pub fn new(os: impl Into<Box<str>>, arch: impl Into<Box<str>>) -> Self {
        Self {
            os: os.into(),
            arch: arch.into(),
        }
    }
}

/// The concrete R representation used as the solver's fixed target.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResolutionTarget {
    pub r_version: RPackageVersion,
    pub platform: Target,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::hash::{Hash, Hasher};

    fn version(value: &str) -> RPackageVersion {
        RPackageVersion::parse(value).unwrap()
    }

    fn package(value: &str) -> PackageName {
        PackageName::new(value).unwrap()
    }

    fn identity(provenance: Provenance) -> ReleaseIdentity {
        ReleaseIdentity::new(package("Matrix"), provenance)
    }

    fn source_distribution(label: &str) -> Distribution {
        Distribution {
            registry: RegistryId::new("cran").unwrap(),
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: Some(SnapshotId::new(label).unwrap()),
            artifacts: vec![Artifact::Source(SourceArtifact {
                locator: ArtifactLocator::new(label).unwrap(),
                upstream_checksums: vec![],
                size: None,
            })],
            observed_metadata: DistributionMetadata::default(),
        }
    }

    fn observation(
        identity: ReleaseIdentity,
        release_version: &str,
        distribution: Distribution,
    ) -> ReleaseObservation {
        ReleaseObservation {
            observed_package: identity.name().clone(),
            identity,
            observed_version: version(release_version),
            metadata: ReleaseMetadata::default(),
            dependencies: vec![],
            distributions: vec![distribution],
        }
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
    fn git_commit_ids_require_full_canonical_oids() {
        let upper = GitCommitId::new("ABCDEF0123456789ABCDEF0123456789ABCDEF01").unwrap();
        assert_eq!(upper.as_str(), "abcdef0123456789abcdef0123456789abcdef01");
        assert_eq!(upper.algorithm(), GitHashAlgorithm::Sha1);
        assert_eq!(
            GitCommitId::new("a".repeat(64)).unwrap().algorithm(),
            GitHashAlgorithm::Sha256
        );

        for invalid in [
            "main",
            "abcdef0123456789abcdef0123456789abcdef0",
            "abcdef0123456789abcdef0123456789abcdef012",
            &"a".repeat(39),
            &"a".repeat(41),
            &"a".repeat(63),
            &"a".repeat(65),
            &"g".repeat(40),
        ] {
            assert!(GitCommitId::new(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn normalized_git_urls_only_apply_safe_local_canonicalization() {
        let url = NormalizedGitUrl::new("HTTPS://EXAMPLE.TEST:443/repo%2f~").unwrap();
        assert_eq!(url.as_str(), "https://example.test/repo%2F~");
        assert_eq!(
            NormalizedGitUrl::new("ssh://example.test:22/repo").unwrap(),
            NormalizedGitUrl::new("ssh://example.test/repo").unwrap()
        );

        for (left, right) in [
            ("https://example.test/repo", "ssh://example.test/repo"),
            ("https://example.test/repo", "git://example.test/repo"),
            ("https://example.test/repo", "https://example.test/Repo"),
            ("https://example.test/repo", "https://example.test/repo.git"),
            ("https://example.test/repo", "https://example.test/repo/"),
            ("https://example.test/repo", "https://www.example.test/repo"),
        ] {
            assert_ne!(
                NormalizedGitUrl::new(left).unwrap(),
                NormalizedGitUrl::new(right).unwrap(),
                "core must not unify {left:?} and {right:?}"
            );
        }

        for invalid in [
            "repo",
            "https://user:password@example.test/repo",
            "https://example.test/repo?token=secret",
            "https://example.test/repo#fragment",
            "https://example.test:bad/repo",
            "https://example.test/repo%2",
        ] {
            assert!(
                NormalizedGitUrl::new(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
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

    #[test]
    fn constraints_evaluate_all_r_relations_and_unconstrained_case() {
        let candidate = version("4.4.0");
        let cases = [
            (RelationOp::Ge, "4.4", true),
            (RelationOp::Gt, "4.4", false),
            (RelationOp::Le, "4.4.0", true),
            (RelationOp::Lt, "4.4.0", false),
            (RelationOp::Eq, "4.4", true),
            (RelationOp::Ne, "4.4", false),
        ];
        for (op, required, expected) in cases {
            assert_eq!(
                VersionConstraint::from_clause(op, version(required)).satisfies(&candidate),
                expected,
                "{op:?} {required}"
            );
        }
        assert!(VersionConstraint::unconstrained().satisfies(&candidate));
        assert!(
            VersionConstraint::new(vec![
                VersionClause::new(RelationOp::Ge, version("4.0")),
                VersionClause::new(RelationOp::Lt, version("5.0")),
            ])
            .satisfies(&candidate)
        );
    }

    #[test]
    fn metadata_rejects_dependency_and_identity_fields() {
        let mut fields = BTreeMap::new();
        fields.insert("Depends".to_owned(), "R (>= 4.4)".to_owned());
        assert!(matches!(
            ReleaseMetadata::new(fields),
            Err(ReleaseMetadataError::ReservedField { .. })
        ));
    }

    #[test]
    fn canonical_constructor_accepts_each_provenance_variant() {
        let registry = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        });
        let git = identity(Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
            subdirectory: None,
        });
        let bioc = identity(Provenance::BioconductorRelease {
            namespace: PackageNamespace::new("bioc").unwrap(),
            release: BioconductorRelease::new("3.20").unwrap(),
            version: version("1.2.3"),
        });
        let immutable = identity(Provenance::ImmutableSource {
            scheme: SourceScheme::new("sha256").unwrap(),
            digest: Sha256Digest::new("a".repeat(64)).unwrap(),
        });

        for (release_identity, release_version) in [
            (registry, "1.6-5"),
            (git, "1.0.0"),
            (bioc, "1.2.3"),
            (immutable, "9.9.9"),
        ] {
            let release = PackageRelease::try_from(observation(
                release_identity.clone(),
                release_version,
                source_distribution("source"),
            ))
            .unwrap();
            assert_eq!(release.identity(), &release_identity);
            assert_eq!(release.version().as_str(), release_version);
        }
    }

    #[test]
    fn canonical_constructor_rejects_name_and_coordinate_mismatches() {
        let registry_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        });
        let mut wrong_name =
            observation(registry_identity.clone(), "1.6-5", source_distribution("a"));
        wrong_name.observed_package = package("Other");
        assert!(matches!(
            PackageRelease::try_from(wrong_name),
            Err(PackageReleaseError::ConflictingMetadata { .. })
        ));

        let wrong_version = observation(registry_identity, "1.6-6", source_distribution("b"));
        assert!(matches!(
            PackageRelease::try_from(wrong_version),
            Err(PackageReleaseError::ConflictingMetadata {
                field: "provenance version"
            })
        ));

        let bioc_identity = identity(Provenance::BioconductorRelease {
            namespace: PackageNamespace::new("bioc").unwrap(),
            release: BioconductorRelease::new("3.20").unwrap(),
            version: version("1.2.3"),
        });
        assert!(matches!(
            PackageRelease::try_from(observation(
                bioc_identity,
                "1.2.4",
                source_distribution("c")
            )),
            Err(PackageReleaseError::ConflictingMetadata { .. })
        ));

        let git_identity = identity(Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
            subdirectory: None,
        });
        let mut git_wrong_name = observation(git_identity, "1.0.0", source_distribution("d"));
        git_wrong_name.observed_package = package("Other");
        assert!(matches!(
            PackageRelease::try_from(git_wrong_name),
            Err(PackageReleaseError::ConflictingMetadata {
                field: "package name"
            })
        ));

        let immutable_identity = identity(Provenance::ImmutableSource {
            scheme: SourceScheme::new("sha256").unwrap(),
            digest: Sha256Digest::new("b".repeat(64)).unwrap(),
        });
        let mut immutable_wrong_name =
            observation(immutable_identity, "1.0.0", source_distribution("e"));
        immutable_wrong_name.observed_package = package("Other");
        assert!(matches!(
            PackageRelease::try_from(immutable_wrong_name),
            Err(PackageReleaseError::ConflictingMetadata {
                field: "package name"
            })
        ));
    }

    #[test]
    fn canonical_constructor_preserves_dependencies_as_first_class_data() {
        let matrix = package("Matrix");
        let dependency = DependencyRequirement::new(
            DependencyKind::Depends,
            package("R"),
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(RelationOp::Ge, version("4.4.0")),
        );
        let release = PackageRelease::try_from(ReleaseObservation {
            identity: identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.6-5"),
            }),
            observed_package: matrix,
            observed_version: version("1.6-5"),
            metadata: ReleaseMetadata::default(),
            dependencies: vec![dependency.clone()],
            distributions: vec![],
        })
        .unwrap();
        assert_eq!(release.dependencies(), &[dependency]);
    }

    #[test]
    fn canonical_constructor_rejects_exact_dependency_name_mismatch() {
        let release_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        });
        let dependency = DependencyRequirement::new(
            DependencyKind::Depends,
            package("Other"),
            DependencySourceConstraint::Exact(release_identity),
            VersionConstraint::unconstrained(),
        );
        let result = PackageRelease::try_from(ReleaseObservation {
            identity: identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.6-5"),
            }),
            observed_package: package("Matrix"),
            observed_version: version("1.6-5"),
            metadata: ReleaseMetadata::default(),
            dependencies: vec![dependency],
            distributions: vec![],
        });
        assert!(matches!(
            result,
            Err(PackageReleaseError::InvalidDependency { index: 0 })
        ));
    }

    #[test]
    fn same_git_commit_with_two_versions_reports_conflicting_metadata() {
        let provenance = Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
            subdirectory: None,
        };
        let release_identity = identity(provenance);
        let first = observation(release_identity.clone(), "1.0.0", source_distribution("a"));
        let second = observation(release_identity, "2.0.0", source_distribution("b"));

        let mut aggregation = ReleaseAggregation::new();
        aggregation.observe(first).unwrap();
        assert!(matches!(
            aggregation.observe(second),
            Err(PackageReleaseError::ConflictingMetadata { field: "version" })
        ));
        assert_eq!(aggregation.len(), 1);
    }

    #[test]
    fn aggregation_merges_distributions_only_for_established_same_identity() {
        let provenance = Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        };
        let same_identity = identity(provenance.clone());
        let mut aggregation = ReleaseAggregation::new();
        aggregation
            .observe(observation(
                same_identity.clone(),
                "1.6-5",
                source_distribution("archive"),
            ))
            .unwrap();
        aggregation
            .observe(observation(
                same_identity.clone(),
                "1.6-5",
                source_distribution("snapshot"),
            ))
            .unwrap();
        assert_eq!(aggregation.len(), 1);
        assert_eq!(
            aggregation
                .get(&same_identity)
                .unwrap()
                .distributions()
                .len(),
            2
        );

        // Same name/version, but a different registry namespace, is not an
        // established provenance and therefore remains a separate candidate.
        let patched_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("private").unwrap(),
            version: version("1.6-5"),
        });
        aggregation
            .observe(observation(
                patched_identity,
                "1.6-5",
                source_distribution("patched"),
            ))
            .unwrap();
        assert_eq!(aggregation.len(), 2);
        assert_eq!(
            aggregation
                .get(&same_identity)
                .unwrap()
                .distributions()
                .len(),
            2,
            "name/version alone must not merge patched source"
        );
    }

    #[test]
    fn first_observation_deduplicates_distributions() {
        let same_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        });
        let duplicate = source_distribution("same");
        let mut observation = observation(same_identity.clone(), "1.6-5", duplicate.clone());
        observation.distributions.push(duplicate);

        let release = PackageRelease::try_from(observation).unwrap();
        assert_eq!(release.distributions().len(), 1);
    }

    #[test]
    fn package_release_is_not_identity_only_hashable() {
        // This is intentionally a compile-time shape assertion made concrete
        // by the conflict scenario above: only ReleaseIdentity is used as the
        // aggregation key, so a differing Git version cannot be discarded by
        // identity-only HashSet deduplication.
        let mut identities = HashSet::new();
        let id = identity(Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
            subdirectory: None,
        });
        identities.insert(id.clone());
        assert!(identities.contains(&id));
    }
}
