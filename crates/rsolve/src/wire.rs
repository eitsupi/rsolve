//! Strict v1 TOML wire codec for the shared logical lock.
//!
//! The DTOs in this module are private implementation details. Domain types
//! remain independent of serde and TOML, and unknown fields are rejected so
//! machine-local materialization facts cannot be silently accepted.

use std::error::Error;
use std::fmt;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};

use rsolve_core::{
    DependencyKind, DependencySourceConstraint, DistributionChannel, EnvironmentId, PackageName,
    Provenance, PublicationDate, RPackageVersion, RegistryId, RelationOp, ReleaseIdentity,
    RepositorySubdir, Sha256Digest, SnapshotId, SourceScheme, VersionClause, VersionConstraint,
};

use crate::lock::{
    LockError, LockedDependencyEdge, LockedDistributionRef, LockedPackage, LockedResolution,
    Lockfile,
};

const SCHEMA_VERSION: u32 = 1;
const SCHEMA_REVISION: u32 = 1;

// RFC 3986 unreserved bytes are left literal. Everything else is percent
// encoded, including Unicode UTF-8 bytes and all identity delimiters.
const NON_UNRESERVED: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockWireError {
    Parse(String),
    Serialize(String),
    UnsupportedSchema { version: u32, revision: u32 },
    InvalidIdentity(String),
    NonCanonicalIdentity(String),
    NonCanonicalVersion { field: String, value: String },
    InvalidField { field: String, message: String },
    Domain(LockError),
}

impl fmt::Display for LockWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(message) => write!(formatter, "lock TOML parse failed: {message}"),
            Self::Serialize(message) => {
                write!(formatter, "lock TOML serialization failed: {message}")
            }
            Self::UnsupportedSchema { version, revision } => write!(
                formatter,
                "unsupported lock schema version {version}, revision {revision}"
            ),
            Self::InvalidIdentity(identity) => {
                write!(formatter, "invalid lock identity {identity}")
            }
            Self::NonCanonicalIdentity(identity) => {
                write!(formatter, "non-canonical lock identity {identity}")
            }
            Self::NonCanonicalVersion { field, value } => {
                write!(formatter, "non-canonical version in {field}: {value}")
            }
            Self::InvalidField { field, message } => {
                write!(formatter, "invalid lock field {field}: {message}")
            }
            Self::Domain(error) => error.fmt(formatter),
        }
    }
}

impl Error for LockWireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Domain(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct WireLockfile {
    schema_version: u32,
    schema_revision: u32,
    resolutions: Vec<WireResolution>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct WireResolution {
    environment: String,
    r_version: String,
    os: String,
    arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    publication_cutoff: Option<String>,
    packages: Vec<WirePackage>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct WirePackage {
    identity: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    published_version_spelling: Option<String>,
    distributions: Vec<WireDistribution>,
    dependencies: Vec<WireDependency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct WireDistribution {
    registry: String,
    channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct WireDependency {
    kind: String,
    name: String,
    source: WireSource,
    clauses: Vec<WireClause>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
enum WireSource {
    Any,
    Registry { namespace: String },
    Bioconductor { namespace: String, release: String },
    Git { repository: String },
    Exact { identity: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct WireClause {
    op: String,
    version: String,
}

/// Decode a strict v1 logical lockfile.
pub fn from_toml(input: &str) -> Result<Lockfile, LockWireError> {
    let wire: WireLockfile =
        toml::from_str(input).map_err(|error| LockWireError::Parse(error.to_string()))?;
    if wire.schema_version != SCHEMA_VERSION || wire.schema_revision != SCHEMA_REVISION {
        return Err(LockWireError::UnsupportedSchema {
            version: wire.schema_version,
            revision: wire.schema_revision,
        });
    }
    let resolutions = wire
        .resolutions
        .into_iter()
        .map(decode_resolution)
        .collect::<Result<Vec<_>, _>>()?;
    Lockfile::new(resolutions).map_err(LockWireError::Domain)
}

/// Encode a logical lockfile with deterministic field and collection order.
pub fn to_toml(lockfile: &Lockfile) -> Result<String, LockWireError> {
    // Re-normalize a clone so public field mutation cannot affect byte
    // determinism or bypass domain validation at the wire boundary.
    let normalized = Lockfile::new(lockfile.resolutions.clone()).map_err(LockWireError::Domain)?;
    let wire = WireLockfile {
        schema_version: SCHEMA_VERSION,
        schema_revision: SCHEMA_REVISION,
        resolutions: normalized
            .resolutions
            .iter()
            .map(encode_resolution)
            .collect::<Result<Vec<_>, _>>()?,
    };
    toml::to_string(&wire).map_err(|error| LockWireError::Serialize(error.to_string()))
}

impl Lockfile {
    pub fn from_toml(input: &str) -> Result<Self, LockWireError> {
        from_toml(input)
    }

    pub fn to_toml(&self) -> Result<String, LockWireError> {
        to_toml(self)
    }
}

fn decode_resolution(wire: WireResolution) -> Result<LockedResolution, LockWireError> {
    let environment = EnvironmentId::new(wire.environment)
        .map_err(|error| invalid_field("environment", error.to_string()))?;
    let r_version = parse_canonical_r_version_field("r-version", &wire.r_version)?;
    let os = wire.os.into_boxed_str();
    let arch = wire.arch.into_boxed_str();
    if os.is_empty() {
        return Err(invalid_field("os", "value is empty"));
    }
    if arch.is_empty() {
        return Err(invalid_field("arch", "value is empty"));
    }
    let packages = wire
        .packages
        .into_iter()
        .map(decode_package)
        .collect::<Result<Vec<_>, _>>()?;
    let publication_cutoff = wire
        .publication_cutoff
        .map(|value| {
            PublicationDate::parse(&value)
                .map_err(|error| invalid_field("publication-cutoff", error.to_string()))
        })
        .transpose()?;
    Ok(LockedResolution {
        target: rsolve_core::ResolutionTarget::new(r_version, rsolve_core::Target::new(os, arch)),
        environment,
        publication_cutoff,
        packages,
    })
}

fn encode_resolution(resolution: &LockedResolution) -> Result<WireResolution, LockWireError> {
    Ok(WireResolution {
        environment: resolution.environment.to_string(),
        r_version: canonical_version(&resolution.target.r_version),
        os: resolution.target.platform.os.to_string(),
        arch: resolution.target.platform.arch.to_string(),
        publication_cutoff: resolution.publication_cutoff.map(|date| date.to_string()),
        packages: resolution
            .packages
            .iter()
            .map(encode_package)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn decode_package(wire: WirePackage) -> Result<LockedPackage, LockWireError> {
    let identity = decode_identity(&wire.identity)?;
    let version = parse_canonical_version_field("version", &wire.version)?;
    let published_version_spelling = wire.published_version_spelling.map(String::into_boxed_str);
    let metadata_sha256 = wire
        .metadata_sha256
        .map(|value| {
            Sha256Digest::new(value)
                .map_err(|error| invalid_field("metadata-sha256", error.to_string()))
        })
        .transpose()?;
    let distributions = wire
        .distributions
        .into_iter()
        .map(decode_distribution)
        .collect::<Result<Vec<_>, _>>()?;
    let dependencies = wire
        .dependencies
        .into_iter()
        .map(decode_dependency)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LockedPackage {
        identity,
        version,
        published_version_spelling,
        distributions,
        dependencies,
        metadata_sha256,
    })
}

fn encode_package(package: &LockedPackage) -> Result<WirePackage, LockWireError> {
    Ok(WirePackage {
        identity: encode_identity(&package.identity)?,
        version: canonical_version(&package.version),
        published_version_spelling: package
            .published_version_spelling
            .as_deref()
            .map(str::to_owned),
        distributions: package
            .distributions
            .iter()
            .map(encode_distribution)
            .collect(),
        dependencies: package
            .dependencies
            .iter()
            .map(encode_dependency)
            .collect::<Result<Vec<_>, _>>()?,
        metadata_sha256: package.metadata_sha256.as_ref().map(ToString::to_string),
    })
}

fn decode_distribution(wire: WireDistribution) -> Result<LockedDistributionRef, LockWireError> {
    Ok(LockedDistributionRef {
        registry: RegistryId::new(wire.registry)
            .map_err(|error| invalid_field("distribution.registry", error.to_string()))?,
        channel: DistributionChannel::new(wire.channel)
            .map_err(|error| invalid_field("distribution.channel", error.to_string()))?,
        snapshot: wire
            .snapshot
            .map(|value| {
                SnapshotId::new(value)
                    .map_err(|error| invalid_field("distribution.snapshot", error.to_string()))
            })
            .transpose()?,
    })
}

fn encode_distribution(distribution: &LockedDistributionRef) -> WireDistribution {
    WireDistribution {
        registry: distribution.registry.to_string(),
        channel: distribution.channel.to_string(),
        snapshot: distribution.snapshot.as_ref().map(ToString::to_string),
    }
}

fn decode_dependency(wire: WireDependency) -> Result<LockedDependencyEdge, LockWireError> {
    let kind = parse_kind(&wire.kind)?;
    let name = PackageName::new(wire.name)
        .map_err(|error| invalid_field("dependency.name", error.to_string()))?;
    let source = decode_source(wire.source)?;
    let clauses = wire
        .clauses
        .into_iter()
        .map(|clause| {
            Ok(VersionClause::new(
                parse_relation(&clause.op)?,
                parse_canonical_version_field("dependency.clauses.version", &clause.version)?,
            ))
        })
        .collect::<Result<Vec<_>, LockWireError>>()?;
    Ok(LockedDependencyEdge {
        kind,
        name,
        source,
        constraint: VersionConstraint::new(clauses),
    })
}

fn encode_dependency(dependency: &LockedDependencyEdge) -> Result<WireDependency, LockWireError> {
    Ok(WireDependency {
        kind: dependency_kind_token(dependency.kind).to_owned(),
        name: dependency.name.to_string(),
        source: encode_source(&dependency.source)?,
        clauses: dependency
            .constraint
            .clauses
            .iter()
            .map(|clause| WireClause {
                op: relation_token(clause.op).to_owned(),
                version: canonical_version(&clause.version),
            })
            .collect(),
    })
}

fn decode_source(source: WireSource) -> Result<DependencySourceConstraint, LockWireError> {
    match source {
        WireSource::Any => Ok(DependencySourceConstraint::Any),
        WireSource::Registry { namespace } => Ok(DependencySourceConstraint::Registry {
            namespace: rsolve_core::PackageNamespace::new(namespace)
                .map_err(|error| invalid_field("dependency.source.namespace", error.to_string()))?,
        }),
        WireSource::Bioconductor { namespace, release } => {
            Ok(DependencySourceConstraint::Bioconductor {
                namespace: rsolve_core::PackageNamespace::new(namespace).map_err(|error| {
                    invalid_field("dependency.source.namespace", error.to_string())
                })?,
                release: rsolve_core::BioconductorRelease::new(release).map_err(|error| {
                    invalid_field("dependency.source.release", error.to_string())
                })?,
            })
        }
        WireSource::Git { repository } => Ok(DependencySourceConstraint::Git {
            repository: rsolve_core::NormalizedGitUrl::new(repository).map_err(|error| {
                invalid_field("dependency.source.repository", error.to_string())
            })?,
        }),
        WireSource::Exact { identity } => Ok(DependencySourceConstraint::Exact(decode_identity(
            &identity,
        )?)),
    }
}

fn encode_source(source: &DependencySourceConstraint) -> Result<WireSource, LockWireError> {
    Ok(match source {
        DependencySourceConstraint::Any => WireSource::Any,
        DependencySourceConstraint::Registry { namespace } => WireSource::Registry {
            namespace: namespace.to_string(),
        },
        DependencySourceConstraint::Bioconductor { namespace, release } => {
            WireSource::Bioconductor {
                namespace: namespace.to_string(),
                release: release.to_string(),
            }
        }
        DependencySourceConstraint::Git { repository } => WireSource::Git {
            repository: repository.to_string(),
        },
        DependencySourceConstraint::Exact(identity) => WireSource::Exact {
            identity: encode_identity(identity)?,
        },
    })
}

fn parse_kind(value: &str) -> Result<DependencyKind, LockWireError> {
    match value {
        "depends" => Ok(DependencyKind::Depends),
        "imports" => Ok(DependencyKind::Imports),
        "linking-to" => Ok(DependencyKind::LinkingTo),
        "suggests" => Ok(DependencyKind::Suggests),
        "enhances" => Ok(DependencyKind::Enhances),
        _ => Err(invalid_field(
            "dependency.kind",
            format!("unknown token {value}"),
        )),
    }
}

fn dependency_kind_token(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Depends => "depends",
        DependencyKind::Imports => "imports",
        DependencyKind::LinkingTo => "linking-to",
        DependencyKind::Suggests => "suggests",
        DependencyKind::Enhances => "enhances",
    }
}

fn parse_relation(value: &str) -> Result<RelationOp, LockWireError> {
    match value {
        "lt" => Ok(RelationOp::Lt),
        "le" => Ok(RelationOp::Le),
        "eq" => Ok(RelationOp::Eq),
        "ne" => Ok(RelationOp::Ne),
        "ge" => Ok(RelationOp::Ge),
        "gt" => Ok(RelationOp::Gt),
        _ => Err(invalid_field(
            "dependency.clauses.op",
            format!("unknown token {value}"),
        )),
    }
}

fn relation_token(op: RelationOp) -> &'static str {
    match op {
        RelationOp::Lt => "lt",
        RelationOp::Le => "le",
        RelationOp::Eq => "eq",
        RelationOp::Ne => "ne",
        RelationOp::Ge => "ge",
        RelationOp::Gt => "gt",
    }
}

fn parse_version(field: &str, value: &str) -> Result<RPackageVersion, LockWireError> {
    RPackageVersion::parse(value).map_err(|error| invalid_field(field, error.to_string()))
}

fn parse_canonical_version_field(
    field: &str,
    value: &str,
) -> Result<RPackageVersion, LockWireError> {
    let version = parse_version(field, value)?;
    if canonical_version(&version) != value {
        return Err(LockWireError::NonCanonicalVersion {
            field: field.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(version)
}

fn parse_canonical_r_version_field(
    field: &str,
    value: &str,
) -> Result<RPackageVersion, LockWireError> {
    let version = RPackageVersion::parse_bare(value)
        .map_err(|error| invalid_field(field, error.to_string()))?;
    if canonical_version(&version) != value {
        return Err(LockWireError::NonCanonicalVersion {
            field: field.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(version)
}

fn canonical_version(version: &RPackageVersion) -> String {
    let mut components = version.components().collect::<Vec<_>>();
    while components.len() > 2 && components.last() == Some(&0) {
        components.pop();
    }
    components
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn encode_component(value: &str) -> String {
    utf8_percent_encode(value, NON_UNRESERVED).to_string()
}

fn decode_component(value: &str) -> Result<String, LockWireError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| LockWireError::InvalidIdentity(value.to_owned()))
}

fn encode_identity(identity: &ReleaseIdentity) -> Result<String, LockWireError> {
    let name = encode_component(identity.name().as_str());
    let encoded = match identity.provenance() {
        Provenance::RBasePackage { .. } => {
            return Err(LockWireError::InvalidIdentity("R base package".into()));
        }
        Provenance::RegistryRelease { namespace, version } => format!(
            "registry:{}::{}@{}",
            encode_component(namespace.as_str()),
            name,
            canonical_version(version)
        ),
        Provenance::BioconductorRelease {
            namespace,
            release,
            version,
        } => format!(
            "bioconductor:{}:{}::{}@{}",
            encode_component(namespace.as_str()),
            encode_component(release.as_str()),
            name,
            canonical_version(version)
        ),
        Provenance::GitCommit {
            repository,
            commit,
            subdirectory,
        } => format!(
            "git:{}@{}:{}::{}",
            encode_component(repository.as_str()),
            encode_component(commit.as_str()),
            subdirectory
                .as_ref()
                .map_or_else(String::new, |value| encode_component(value.as_str())),
            name
        ),
        Provenance::ImmutableSource { scheme, digest } => format!(
            "immutable:{}@{}::{}",
            encode_component(scheme.as_str()),
            encode_component(digest.as_str()),
            name
        ),
    };
    Ok(encoded)
}

fn decode_identity(value: &str) -> Result<ReleaseIdentity, LockWireError> {
    let identity = if let Some(value) = value.strip_prefix("registry:") {
        let (coordinates, version) = value
            .rsplit_once('@')
            .ok_or_else(|| invalid_identity(value))?;
        let (namespace, name) = coordinates
            .split_once("::")
            .ok_or_else(|| invalid_identity(value))?;
        ReleaseIdentity::new(
            parse_package_component(name)?,
            Provenance::RegistryRelease {
                namespace: parse_namespace_component(namespace)?,
                version: parse_canonical_version(version)?,
            },
        )
    } else if let Some(value) = value.strip_prefix("bioconductor:") {
        let (coordinates, version) = value
            .rsplit_once('@')
            .ok_or_else(|| invalid_identity(value))?;
        let pieces = coordinates.split("::").collect::<Vec<_>>();
        if pieces.len() != 2 {
            return Err(invalid_identity(value));
        }
        let (namespace, release) = pieces[0]
            .split_once(':')
            .ok_or_else(|| invalid_identity(value))?;
        ReleaseIdentity::new(
            parse_package_component(pieces[1])?,
            Provenance::BioconductorRelease {
                namespace: parse_namespace_component(namespace)?,
                release: parse_release_component(release)?,
                version: parse_canonical_version(version)?,
            },
        )
    } else if let Some(value) = value.strip_prefix("git:") {
        let (coordinates, name) = value
            .rsplit_once("::")
            .ok_or_else(|| invalid_identity(value))?;
        let (url, rest) = coordinates
            .split_once('@')
            .ok_or_else(|| invalid_identity(value))?;
        let (commit, subdirectory) = rest
            .split_once(':')
            .ok_or_else(|| invalid_identity(value))?;
        ReleaseIdentity::new(
            parse_package_component(name)?,
            Provenance::GitCommit {
                repository: rsolve_core::NormalizedGitUrl::new(decode_required(url, value)?)
                    .map_err(|error| invalid_identity(error.to_string()))?,
                commit: rsolve_core::GitCommitId::new(decode_required(commit, value)?)
                    .map_err(|error| invalid_identity(error.to_string()))?,
                subdirectory: if subdirectory.is_empty() {
                    None
                } else {
                    Some(
                        RepositorySubdir::new(decode_required(subdirectory, value)?)
                            .map_err(|error| invalid_identity(error.to_string()))?,
                    )
                },
            },
        )
    } else if let Some(value) = value.strip_prefix("immutable:") {
        let (coordinates, name) = value
            .rsplit_once("::")
            .ok_or_else(|| invalid_identity(value))?;
        let (scheme, digest) = coordinates
            .split_once('@')
            .ok_or_else(|| invalid_identity(value))?;
        ReleaseIdentity::new(
            parse_package_component(name)?,
            Provenance::ImmutableSource {
                scheme: SourceScheme::new(decode_required(scheme, value)?)
                    .map_err(|error| invalid_identity(error.to_string()))?,
                digest: Sha256Digest::new(decode_required(digest, value)?)
                    .map_err(|error| invalid_identity(error.to_string()))?,
            },
        )
    } else {
        return Err(invalid_identity(value));
    };
    let canonical = encode_identity(&identity)?;
    if canonical != value {
        return Err(LockWireError::NonCanonicalIdentity(value.into()));
    }
    Ok(identity)
}

fn decode_required(value: &str, original: &str) -> Result<String, LockWireError> {
    decode_component(value).map_err(|_| invalid_identity(original))
}

fn parse_package_component(value: &str) -> Result<PackageName, LockWireError> {
    PackageName::new(decode_component(value)?).map_err(|error| invalid_identity(error.to_string()))
}

fn parse_namespace_component(value: &str) -> Result<rsolve_core::PackageNamespace, LockWireError> {
    rsolve_core::PackageNamespace::new(decode_component(value)?)
        .map_err(|error| invalid_identity(error.to_string()))
}

fn parse_release_component(value: &str) -> Result<rsolve_core::BioconductorRelease, LockWireError> {
    rsolve_core::BioconductorRelease::new(decode_component(value)?)
        .map_err(|error| invalid_identity(error.to_string()))
}

fn parse_canonical_version(value: &str) -> Result<RPackageVersion, LockWireError> {
    let decoded = decode_component(value)?;
    let version = parse_version("identity.version", &decoded)?;
    if canonical_version(&version) != decoded {
        return Err(LockWireError::NonCanonicalIdentity(value.into()));
    }
    Ok(version)
}

fn invalid_identity(value: impl Into<String>) -> LockWireError {
    LockWireError::InvalidIdentity(value.into())
}

fn invalid_field(field: impl Into<String>, message: impl Into<String>) -> LockWireError {
    LockWireError::InvalidField {
        field: field.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
