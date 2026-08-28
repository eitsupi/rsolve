use super::ManifestError;
use rsolve_core::{PackageNamespace, RegistryId, RepositoryId};
use sha2::{Digest, Sha256};
use std::fmt;
use url::Url;

/// A transport URL after manifest-level validation and normalization.
///
/// This type intentionally carries no provider capability.  A URL being
/// syntactically valid does not imply that it serves CRAN or R-universe data.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Endpoint(Box<str>);

impl Endpoint {
    pub fn new(input: impl AsRef<str>) -> Result<Self, ManifestError> {
        Self::parse(input)
    }

    pub fn parse(input: impl AsRef<str>) -> Result<Self, ManifestError> {
        let original = input.as_ref();
        reject_raw_root_escape(original)?;
        let mut url = Url::parse(original).map_err(|error| ManifestError::InvalidEndpoint {
            value: original.to_owned(),
            reason: error.to_string(),
        })?;
        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(ManifestError::InvalidEndpoint {
                    value: original.to_owned(),
                    reason: format!("scheme `{scheme}` is not HTTP or HTTPS"),
                });
            }
        }
        if url.host_str().is_none() {
            return Err(ManifestError::InvalidEndpoint {
                value: original.to_owned(),
                reason: "an absolute URL with a host is required".into(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ManifestError::InvalidEndpoint {
                value: original.to_owned(),
                reason: "credentials are forbidden".into(),
            });
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ManifestError::InvalidEndpoint {
                value: original.to_owned(),
                reason: "query and fragment are forbidden".into(),
            });
        }
        if url.port().is_some_and(|port| port == 0) {
            return Err(ManifestError::InvalidEndpoint {
                value: original.to_owned(),
                reason: "port zero is forbidden".into(),
            });
        }
        // Keep a repository endpoint's path, but canonicalize only local dot
        // segments.  We do not infer provider-specific paths or aliases.
        let path = normalize_url_path(url.path())?;
        url.set_path(&path);
        if (url.scheme() == "http" && url.port() == Some(80))
            || (url.scheme() == "https" && url.port() == Some(443))
        {
            url.set_port(None)
                .map_err(|_| ManifestError::InvalidEndpoint {
                    value: original.to_owned(),
                    reason: "invalid default port".into(),
                })?;
        }
        Ok(Self(url.to_string().into_boxed_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn scheme(&self) -> &str {
        self.0.split_once(":").map_or("", |(scheme, _)| scheme)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub(super) fn normalize_url_path(path: &str) -> Result<String, ManifestError> {
    if path
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ManifestError::InvalidEndpoint {
            value: path.into(),
            reason: "path contains control or whitespace".into(),
        });
    }
    let trailing = path.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "." => {}
            ".." => {
                match parts.last() {
                    // The first empty segment is the URL's root marker; a
                    // parent segment cannot remove it.
                    Some(&"") if parts.len() == 1 && path.starts_with('/') => {
                        return Err(ManifestError::InvalidEndpoint {
                            value: path.into(),
                            reason: "path escapes the URL root".into(),
                        });
                    }
                    Some(_) => {
                        parts.pop();
                    }
                    None => {
                        return Err(ManifestError::InvalidEndpoint {
                            value: path.into(),
                            reason: "path escapes the URL root".into(),
                        });
                    }
                }
                if parts.is_empty() && path.starts_with('/') {
                    return Err(ManifestError::InvalidEndpoint {
                        value: path.into(),
                        reason: "path escapes the URL root".into(),
                    });
                }
            }
            value => parts.push(value),
        }
    }
    let mut result = parts.join("/");
    if trailing && !result.ends_with('/') {
        result.push('/');
    }
    if result.is_empty() {
        result.push('/');
    }
    Ok(result)
}

/// URL parsers may erase leading dot segments before exposing `path()`. Keep
/// the fail-closed root-escape check on the manifest spelling as well.
pub(super) fn reject_raw_root_escape(input: &str) -> Result<(), ManifestError> {
    let Some((_, authority_and_path)) = input.split_once("://") else {
        return Ok(());
    };
    let authority_and_path = authority_and_path.split(['?', '#']).next().unwrap_or("");
    let path = authority_and_path
        .find('/')
        .map(|index| &authority_and_path[index..])
        .unwrap_or("");
    let path = path.split(['?', '#']).next().unwrap_or("");
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "." => {}
            ".." => {
                if segments.len() <= 1 {
                    return Err(ManifestError::InvalidEndpoint {
                        value: input.into(),
                        reason: "path escapes the URL root".into(),
                    });
                }
                segments.pop();
            }
            value => segments.push(value),
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistrySpec {
    Cran,
    CranLike { namespace: PackageNamespace },
    RUniverse,
}

impl RegistrySpec {
    pub fn cran_like(namespace: PackageNamespace) -> Result<Self, ManifestError> {
        if namespace.as_str() == "cran" {
            return Err(ManifestError::InvalidRegistry {
                reason: "cran-like cannot use reserved namespace `cran`".into(),
            });
        }
        Ok(Self::CranLike { namespace })
    }

    pub fn provenance_policy(&self) -> RegistryProvenancePolicy {
        match self {
            Self::Cran => RegistryProvenancePolicy::FixedNamespace(
                PackageNamespace::new("cran").expect("cran is a valid namespace"),
            ),
            Self::CranLike { namespace } => {
                RegistryProvenancePolicy::FixedNamespace(namespace.clone())
            }
            Self::RUniverse => RegistryProvenancePolicy::GitMetadata,
        }
    }

    pub(super) fn tag(&self) -> &'static str {
        match self {
            Self::Cran => "cran",
            Self::CranLike { .. } => "cran-like",
            Self::RUniverse => "r-universe",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryProvenancePolicy {
    FixedNamespace(PackageNamespace),
    GitMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySpec {
    id: RepositoryId,
    registry: RegistrySpec,
    manifest_endpoint: Endpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveRepository {
    spec: RepositorySpec,
    effective_endpoint: Endpoint,
}

impl RepositorySpec {
    pub fn new(
        id: RepositoryId,
        registry: RegistrySpec,
        manifest_endpoint: Endpoint,
    ) -> Result<Self, ManifestError> {
        validate_repository_id(&id)?;
        if let RegistrySpec::CranLike { namespace } = &registry
            && namespace.as_str() == "cran"
        {
            return Err(ManifestError::InvalidRegistry {
                reason: "cran-like cannot use reserved namespace `cran`".into(),
            });
        }
        Ok(Self {
            id,
            registry,
            manifest_endpoint,
        })
    }

    pub fn effective(&self, endpoint: Endpoint) -> EffectiveRepository {
        EffectiveRepository {
            spec: self.clone(),
            effective_endpoint: endpoint,
        }
    }

    pub fn manifest_endpoint(&self) -> &Endpoint {
        &self.manifest_endpoint
    }

    pub fn id(&self) -> &RepositoryId {
        &self.id
    }

    pub fn registry(&self) -> &RegistrySpec {
        &self.registry
    }

    /// The configured registry identity excludes repository IDs and ephemeral
    /// endpoint overrides by construction.
    pub fn configured_registry_id(&self) -> Result<RegistryId, ManifestError> {
        let namespace = match &self.registry {
            RegistrySpec::CranLike { namespace } => Some(namespace.as_str().as_bytes()),
            _ => None,
        };
        let mut fields = vec![self.registry.tag().as_bytes()];
        if let Some(namespace) = namespace {
            fields.push(namespace);
        }
        fields.push(self.manifest_endpoint.as_str().as_bytes());
        let digest = digest_fields(&fields);
        RegistryId::new(hex_digest(&digest)).map_err(|error| ManifestError::InvalidRepository {
            reason: error.to_string(),
        })
    }

    pub fn registry_id(&self) -> Result<RegistryId, ManifestError> {
        self.configured_registry_id()
    }
}

impl EffectiveRepository {
    pub fn configured_registry_id(&self) -> Result<RegistryId, ManifestError> {
        self.spec.configured_registry_id()
    }

    pub fn registry_id(&self) -> Result<RegistryId, ManifestError> {
        self.configured_registry_id()
    }

    pub fn effective_endpoint(&self) -> &Endpoint {
        &self.effective_endpoint
    }

    pub fn spec(&self) -> &RepositorySpec {
        &self.spec
    }
}

pub(super) fn validate_named_id(value: &str, kind: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 64
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
    {
        return Err(ManifestError::InvalidIdentifier {
            kind: kind.into(),
            value: value.into(),
        });
    }
    Ok(())
}

pub(super) fn validate_repository_id(id: &RepositoryId) -> Result<(), ManifestError> {
    validate_named_id(id.as_str(), "repository")
}

pub(super) fn validate_selector(value: &str, context: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 1024
        || value.chars().any(|character| character.is_control())
    {
        return Err(ManifestError::InvalidDependencyField {
            name: context.into(),
            reason: "Git selector must be a non-empty, bounded, non-control string".into(),
        });
    }
    Ok(())
}

pub(super) fn validate_relative_subdirectory(value: &str) -> Result<(), String> {
    if value.is_empty() || value.starts_with('/') || value.contains('\\') {
        return Err("subdirectory must be a non-empty relative slash path".into());
    }
    if value.chars().any(char::is_control) {
        return Err("subdirectory contains a control character".into());
    }
    let mut depth = 0usize;
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." if depth > 0 => depth -= 1,
            ".." => return Err("subdirectory escapes the source root".into()),
            _ => depth += 1,
        }
    }
    if depth == 0 {
        return Err("subdirectory must contain a path component".into());
    }
    Ok(())
}

pub(super) fn normalize_requested_path(value: &str) -> Result<String, String> {
    let value = value.replace('\\', "/");
    if value.starts_with('/') || value.starts_with("//") || value.as_bytes().get(1) == Some(&b':') {
        return Err("path must not be absolute or use a drive/UNC prefix".into());
    }
    if value.chars().any(char::is_control) {
        return Err("path contains a control character".into());
    }
    let mut parts = Vec::new();
    for component in value.split('/') {
        match component {
            "" | "." => {}
            _ => parts.push(component),
        }
    }
    if parts.is_empty() || parts.last() == Some(&"..") {
        return Err("path must have a non-empty final component".into());
    }
    Ok(parts.join("/"))
}

pub(super) fn digest_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"rsolve.manifest.v1\0");
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().to_vec()
}

pub(super) fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
