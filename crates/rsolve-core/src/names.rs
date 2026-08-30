use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

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
    InvalidPathCharacter,
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
            Self::InvalidPathCharacter => "normalized Git URL has an invalid path character",
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
            .any(|character| character.is_control() || character.is_whitespace())
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
            if !is_url_path_character(bytes[index]) {
                return Err(NormalizedGitUrlError::InvalidPathCharacter);
            }
            normalized.push(char::from(bytes[index]));
            index += 1;
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

fn is_url_path_character(byte: u8) -> bool {
    is_url_unreserved(byte)
        || matches!(
            byte,
            b'/' | b':'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
        )
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
    NullObject,
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
            Self::NullObject => f.write_str("Git commit OID must not be Git's null object"),
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
        if input.bytes().all(|byte| byte == b'0') {
            return Err(GitCommitIdError::NullObject);
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
/// A canonical relative slash-separated path within a source repository.
///
/// This type accepts canonical wire/domain values only. Human-facing inputs
/// that permit `.` or `..` components must be normalized before construction,
/// such as by the manifest parser; accepting multiple spellings here would
/// make source identities ambiguous.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositorySubdir(Box<str>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositorySubdirError {
    Empty,
    Absolute,
    Backslash,
    ControlCharacter { index: usize },
    EmptyComponent { index: usize },
    DotComponent { index: usize },
    ParentComponent { index: usize },
    WindowsDrivePrefix,
}

impl fmt::Display for RepositorySubdirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("repository subdirectory must not be empty"),
            Self::Absolute => f.write_str("repository subdirectory must be a relative path"),
            Self::Backslash => f.write_str("repository subdirectory must use slash separators"),
            Self::ControlCharacter { index } => write!(
                f,
                "repository subdirectory contains a control character at {index}"
            ),
            Self::EmptyComponent { index } => write!(
                f,
                "repository subdirectory has an empty component at {index}"
            ),
            Self::DotComponent { index } => write!(
                f,
                "repository subdirectory has a non-canonical dot component at {index}"
            ),
            Self::ParentComponent { index } => write!(
                f,
                "repository subdirectory has a parent component at {index}"
            ),
            Self::WindowsDrivePrefix => {
                f.write_str("repository subdirectory must not have a Windows drive prefix")
            }
        }
    }
}

impl Error for RepositorySubdirError {}

impl RepositorySubdir {
    pub fn new(input: impl AsRef<str>) -> Result<Self, RepositorySubdirError> {
        let input = input.as_ref();
        if input.is_empty() {
            return Err(RepositorySubdirError::Empty);
        }
        if input.starts_with('/') {
            return Err(RepositorySubdirError::Absolute);
        }
        if input.contains('\\') {
            return Err(RepositorySubdirError::Backslash);
        }
        for (index, character) in input.char_indices() {
            if character.is_control() {
                return Err(RepositorySubdirError::ControlCharacter { index });
            }
        }
        if let Some(first) = input.split('/').next()
            && first.len() >= 2
            && first.as_bytes()[0].is_ascii_alphabetic()
            && first.as_bytes()[1] == b':'
        {
            return Err(RepositorySubdirError::WindowsDrivePrefix);
        }
        for (index, component) in input.split('/').enumerate() {
            match component {
                "" => return Err(RepositorySubdirError::EmptyComponent { index }),
                "." => return Err(RepositorySubdirError::DotComponent { index }),
                ".." => return Err(RepositorySubdirError::ParentComponent { index }),
                _ => {}
            }
        }
        Ok(Self(input.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepositorySubdir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
opaque_identifier!(RepositoryId);
opaque_identifier!(RegistryId);
opaque_identifier!(SnapshotId);
opaque_identifier!(ArtifactLocator);
opaque_identifier!(DistributionChannel);
opaque_identifier!(SourceScheme);

/// The manifest declaration order of a repository, represented independently
/// from an external integer field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryRank(u64);

impl RepositoryRank {
    pub const fn new(ordinal: u64) -> Self {
        Self(ordinal)
    }

    pub const fn ordinal(self) -> u64 {
        self.0
    }

    pub fn from_usize(ordinal: usize) -> Option<Self> {
        u64::try_from(ordinal).ok().map(Self)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
            &"0".repeat(40),
            &"0".repeat(64),
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
            "https://example.test/ま/foo",
            "https://example.test/repo\u{2003}backup",
            "https://example.test/repo\\backup",
            "https://example.test/repo[backup",
        ] {
            assert!(
                NormalizedGitUrl::new(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn repository_subdirectories_require_canonical_relative_paths() {
        assert_eq!(RepositorySubdir::new("a/b").unwrap().as_str(), "a/b");
        for invalid in [
            "",
            "/absolute",
            "\\absolute",
            "a\\b",
            "a//b",
            "a/./b",
            "a/../b",
            "../escape",
            "a/b/",
            ".",
            "..",
            "C:/source",
            "c:source",
            "//server/share",
        ] {
            assert!(
                RepositorySubdir::new(invalid).is_err(),
                "accepted non-canonical subdirectory {invalid:?}"
            );
        }
    }

    #[test]
    fn repository_subdirectories_reject_control_characters() {
        assert!(matches!(
            RepositorySubdir::new("a/\n/b"),
            Err(RepositorySubdirError::ControlCharacter { .. })
        ));
    }

    #[test]
    fn repository_ids_are_opaque_and_ranks_are_orderable_values() {
        assert!(RepositoryId::new("").is_err());
        assert!(RepositoryId::new("primary\n").is_err());
        let first = RepositoryRank::new(0);
        let second = RepositoryRank::new(1);
        assert!(first < second);
        assert_eq!(first.ordinal(), 0);
        assert_eq!(RepositoryRank::from_usize(1).unwrap().ordinal(), 1);
    }
}
