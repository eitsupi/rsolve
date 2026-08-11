//! Strict v1 TOML wire codec for the shared logical lock.
//!
//! The DTOs in this module are private implementation details. Domain types
//! remain independent of serde and TOML, and unknown fields are rejected so
//! machine-local materialization facts cannot be silently accepted.

use std::error::Error;
use std::fmt;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};

use nrr_core::{
    DependencyKind, DependencySourceConstraint, DistributionChannel, EnvironmentId, PackageName,
    Provenance, RPackageVersion, RegistryId, RelationOp, ReleaseIdentity, RepositorySubdir,
    Sha256Digest, SnapshotId, SourceScheme, VersionClause, VersionConstraint,
};

use crate::lock::{
    LockError, LockedDependencyEdge, LockedDistributionRef, LockedPackage, LockedResolution,
    Lockfile,
};

const SCHEMA_VERSION: u32 = 1;
const SCHEMA_REVISION: u32 = 0;

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
    let r_version = parse_canonical_version_field("r-version", &wire.r_version)?;
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
    Ok(LockedResolution {
        target: nrr_core::ResolutionTarget::new(r_version, nrr_core::Target::new(os, arch)),
        environment,
        packages,
    })
}

fn encode_resolution(resolution: &LockedResolution) -> Result<WireResolution, LockWireError> {
    Ok(WireResolution {
        environment: resolution.environment.to_string(),
        r_version: canonical_version(&resolution.target.r_version),
        os: resolution.target.platform.os.to_string(),
        arch: resolution.target.platform.arch.to_string(),
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
            namespace: nrr_core::PackageNamespace::new(namespace)
                .map_err(|error| invalid_field("dependency.source.namespace", error.to_string()))?,
        }),
        WireSource::Bioconductor { namespace, release } => {
            Ok(DependencySourceConstraint::Bioconductor {
                namespace: nrr_core::PackageNamespace::new(namespace).map_err(|error| {
                    invalid_field("dependency.source.namespace", error.to_string())
                })?,
                release: nrr_core::BioconductorRelease::new(release).map_err(|error| {
                    invalid_field("dependency.source.release", error.to_string())
                })?,
            })
        }
        WireSource::Git { repository } => Ok(DependencySourceConstraint::Git {
            repository: nrr_core::NormalizedGitUrl::new(repository).map_err(|error| {
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
                repository: nrr_core::NormalizedGitUrl::new(decode_required(url, value)?)
                    .map_err(|error| invalid_identity(error.to_string()))?,
                commit: nrr_core::GitCommitId::new(decode_required(commit, value)?)
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

fn parse_namespace_component(value: &str) -> Result<nrr_core::PackageNamespace, LockWireError> {
    nrr_core::PackageNamespace::new(decode_component(value)?)
        .map_err(|error| invalid_identity(error.to_string()))
}

fn parse_release_component(value: &str) -> Result<nrr_core::BioconductorRelease, LockWireError> {
    nrr_core::BioconductorRelease::new(decode_component(value)?)
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
mod tests {
    use super::*;
    use crate::lock::LockedDistributionRef;

    fn version(value: &str) -> RPackageVersion {
        RPackageVersion::parse(value).unwrap()
    }

    fn package(value: &str) -> PackageName {
        PackageName::new(value).unwrap()
    }

    fn identity(name: &str, provenance: Provenance) -> ReleaseIdentity {
        ReleaseIdentity::new(package(name), provenance)
    }

    fn distribution(channel: &str, snapshot: Option<&str>) -> LockedDistributionRef {
        LockedDistributionRef {
            registry: RegistryId::new("cran").unwrap(),
            channel: DistributionChannel::new(channel).unwrap(),
            snapshot: snapshot.map(|value| SnapshotId::new(value).unwrap()),
        }
    }

    fn dependency(
        kind: DependencyKind,
        name: &str,
        source: DependencySourceConstraint,
        op: RelationOp,
    ) -> LockedDependencyEdge {
        LockedDependencyEdge {
            kind,
            name: package(name),
            source,
            constraint: VersionConstraint::new(vec![VersionClause::new(op, version("1.0"))]),
        }
    }

    fn package_record(name: &str, provenance: Provenance) -> LockedPackage {
        LockedPackage {
            identity: identity(name, provenance),
            version: version("1.0"),
            published_version_spelling: None,
            distributions: vec![distribution("source", Some("snapshot-1"))],
            dependencies: vec![
                dependency(
                    DependencyKind::Depends,
                    "dep.any",
                    DependencySourceConstraint::Any,
                    RelationOp::Ge,
                ),
                dependency(
                    DependencyKind::Imports,
                    "dep.registry",
                    DependencySourceConstraint::Registry {
                        namespace: nrr_core::PackageNamespace::new("cran").unwrap(),
                    },
                    RelationOp::Eq,
                ),
                dependency(
                    DependencyKind::LinkingTo,
                    "dep.bioc",
                    DependencySourceConstraint::Bioconductor {
                        namespace: nrr_core::PackageNamespace::new("bioc").unwrap(),
                        release: nrr_core::BioconductorRelease::new("3.20").unwrap(),
                    },
                    RelationOp::Le,
                ),
                dependency(
                    DependencyKind::Suggests,
                    "dep.git",
                    DependencySourceConstraint::Git {
                        repository: nrr_core::NormalizedGitUrl::new("https://example.test/repo")
                            .unwrap(),
                    },
                    RelationOp::Ne,
                ),
                dependency(
                    DependencyKind::Enhances,
                    "dep.exact",
                    DependencySourceConstraint::Exact(identity(
                        "dep.exact",
                        Provenance::ImmutableSource {
                            scheme: SourceScheme::new("sha256").unwrap(),
                            digest: Sha256Digest::new("b".repeat(64)).unwrap(),
                        },
                    )),
                    RelationOp::Lt,
                ),
            ],
            metadata_sha256: Some(Sha256Digest::new("a".repeat(64)).unwrap()),
        }
    }

    fn logical_lock() -> Lockfile {
        Lockfile::new(vec![LockedResolution {
            target: nrr_core::ResolutionTarget::new(
                version("4.4.0"),
                nrr_core::Target::new("linux", "x86_64"),
            ),
            environment: EnvironmentId::new("default").unwrap(),
            packages: vec![
                package_record(
                    "registry",
                    Provenance::RegistryRelease {
                        namespace: nrr_core::PackageNamespace::new("cran").unwrap(),
                        version: version("1.0"),
                    },
                ),
                package_record(
                    "bioc",
                    Provenance::BioconductorRelease {
                        namespace: nrr_core::PackageNamespace::new("bioc").unwrap(),
                        release: nrr_core::BioconductorRelease::new("3.20").unwrap(),
                        version: version("1.0"),
                    },
                ),
                package_record(
                    "git",
                    Provenance::GitCommit {
                        repository: nrr_core::NormalizedGitUrl::new("https://example.test/repo")
                            .unwrap(),
                        commit: nrr_core::GitCommitId::new(
                            "0123456789abcdef0123456789abcdef01234567",
                        )
                        .unwrap(),
                        subdirectory: Some(RepositorySubdir::new("sub/pkg").unwrap()),
                    },
                ),
                package_record(
                    "immutable",
                    Provenance::ImmutableSource {
                        scheme: SourceScheme::new("sha256").unwrap(),
                        digest: Sha256Digest::new("c".repeat(64)).unwrap(),
                    },
                ),
            ],
        }])
        .unwrap()
    }

    #[test]
    fn all_logical_provenance_and_source_constraints_round_trip() {
        let lock = logical_lock();
        let text = to_toml(&lock).unwrap();
        let decoded = from_toml(&text).unwrap();
        assert_eq!(decoded, lock);
        assert!(text.contains("schema-version = 1"));
        assert!(text.contains("linking-to"));
    }

    #[test]
    fn identity_encoding_is_canonical_and_lossless() {
        for package in &logical_lock().resolutions[0].packages {
            let encoded = encode_identity(&package.identity).unwrap();
            assert_eq!(decode_identity(&encoded).unwrap(), package.identity);
        }
        for (value, expected) in [
            ("registry:cran::registry@1.0.0", "noncanonical version"),
            ("registry:cran::registry%2E@1.0", "over-escaped unreserved"),
            ("registry:cran::registry%2e@1.0", "lowercase percent hex"),
            (
                "git:https%3A%2F%2FEXAMPLE.test%2Frepo@0123456789abcdef0123456789abcdef01234567::git",
                "non-normalized URL",
            ),
            (
                "git:https%3A%2F%2Fexample.test%2Frepo@0123::git",
                "abbreviated commit",
            ),
        ] {
            assert!(
                matches!(
                    decode_identity(value),
                    Err(LockWireError::NonCanonicalIdentity(_))
                        | Err(LockWireError::InvalidIdentity(_))
                ),
                "{expected}"
            );
        }
    }

    #[test]
    fn canonical_version_fields_have_one_wire_spelling() {
        let make_lock = |package_version: &str, clause_version: &str, r_version: &str| {
            Lockfile::new(vec![LockedResolution {
                target: nrr_core::ResolutionTarget::new(
                    version(r_version),
                    nrr_core::Target::new("linux", "x86_64"),
                ),
                environment: EnvironmentId::new("default").unwrap(),
                packages: vec![LockedPackage {
                    identity: identity(
                        "spellings",
                        Provenance::RegistryRelease {
                            namespace: nrr_core::PackageNamespace::new("cran").unwrap(),
                            version: version(package_version),
                        },
                    ),
                    version: version(package_version),
                    published_version_spelling: None,
                    distributions: Vec::new(),
                    dependencies: vec![LockedDependencyEdge {
                        kind: DependencyKind::Depends,
                        name: package("dep"),
                        source: DependencySourceConstraint::Any,
                        constraint: VersionConstraint::new(vec![VersionClause::new(
                            RelationOp::Ge,
                            version(clause_version),
                        )]),
                    }],
                    metadata_sha256: None,
                }],
            }])
            .unwrap()
        };
        let canonical = make_lock("1.6.5", "1.0", "4.4");
        let alternate = make_lock("1.6-5", "1.0.0", "4.4.0");
        let leading_zero = make_lock("01.6.5", "01.0", "04.4");
        assert_eq!(to_toml(&canonical).unwrap(), to_toml(&alternate).unwrap());
        assert_eq!(
            to_toml(&canonical).unwrap(),
            to_toml(&leading_zero).unwrap()
        );
        let text = to_toml(&canonical).unwrap();
        assert!(matches!(
            from_toml(&text.replace("r-version = \"4.4\"", "r-version = \"4.4.0\"")),
            Err(LockWireError::NonCanonicalVersion { field, .. }) if field == "r-version"
        ));
        assert!(matches!(
            from_toml(&text.replace("version = \"1.6.5\"", "version = \"1.6.5.0\"")),
            Err(LockWireError::NonCanonicalVersion { field, .. }) if field == "version"
        ));
        assert!(matches!(
            from_toml(&text.replace("version = \"1.6.5\"", "version = \"01.6.5\"")),
            Err(LockWireError::NonCanonicalVersion { field, .. }) if field == "version"
        ));
        assert!(matches!(
            from_toml(&text.replace("op = \"ge\"\nversion = \"1.0\"", "op = \"ge\"\nversion = \"1.0.0\"")),
            Err(LockWireError::NonCanonicalVersion { field, .. })
                if field == "dependency.clauses.version"
        ));
    }

    #[test]
    fn resolution_projection_wire_output_excludes_artifact_facts() {
        let name = package("artifactless");
        let release_version = version("1.0");
        let release = nrr_core::PackageRelease::try_from(nrr_core::ReleaseObservation {
            identity: identity(
                "artifactless",
                Provenance::RegistryRelease {
                    namespace: nrr_core::PackageNamespace::new("cran").unwrap(),
                    version: release_version.clone(),
                },
            ),
            observed_package: name,
            observed_version: release_version,
            metadata: nrr_core::ReleaseMetadata::default(),
            dependencies: Vec::new(),
            distributions: vec![nrr_core::Distribution {
                registry: RegistryId::new("cran").unwrap(),
                channel: DistributionChannel::new("source").unwrap(),
                snapshot: None,
                artifacts: vec![nrr_core::Artifact::Source(nrr_core::SourceArtifact {
                    locator: nrr_core::ArtifactLocator::new("/machine/secret.tar.gz").unwrap(),
                    upstream_checksums: vec![nrr_core::UpstreamChecksum::Md5("deadbeef".into())],
                    size: Some(4242),
                })],
                observed_metadata: nrr_core::DistributionMetadata::default(),
            }],
        })
        .unwrap();
        let resolution = nrr_core::Resolution::new(
            nrr_core::ResolutionTarget::new(
                version("4.4"),
                nrr_core::Target::new("linux", "x86_64"),
            ),
            vec![nrr_core::ResolvedPackage::new(
                nrr_core::SolverKey::InstalledName(package("artifactless")),
                release,
            )],
        );
        let lock =
            Lockfile::from_resolution(&resolution, EnvironmentId::new("default").unwrap()).unwrap();
        let text = to_toml(&lock).unwrap();
        for forbidden in ["/machine/secret.tar.gz", "deadbeef", "4242"] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn reader_enforces_schema_and_exactly_one_resolution() {
        let empty = "schema-version = 1\nschema-revision = 0\nresolutions = []\n";
        assert!(matches!(
            from_toml(empty),
            Err(LockWireError::Domain(
                LockError::UnsupportedResolutionCount { found: 0 }
            ))
        ));
        let two = "schema-version = 1\nschema-revision = 0\n\n[[resolutions]]\nenvironment = \"default\"\nr-version = \"4.4\"\nos = \"linux\"\narch = \"x86_64\"\npackages = []\n\n[[resolutions]]\nenvironment = \"other\"\nr-version = \"4.4\"\nos = \"linux\"\narch = \"x86_64\"\npackages = []\n";
        assert!(matches!(
            from_toml(two),
            Err(LockWireError::Domain(
                LockError::UnsupportedResolutionCount { found: 2 }
            ))
        ));
        assert!(matches!(
            from_toml("schema-version = 2\nschema-revision = 0\nresolutions = []\n"),
            Err(LockWireError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn unknown_and_machine_local_fields_are_rejected_and_not_emitted() {
        let unknown = "schema-version = 1\nschema-revision = 0\nartifact-url = \"/tmp/a\"\nresolutions = []\n";
        assert!(matches!(from_toml(unknown), Err(LockWireError::Parse(_))));
        let forbidden = "schema-version = 1\nschema-revision = 0\n\n[[resolutions]]\nenvironment = \"default\"\nr-version = \"4.4\"\nos = \"linux\"\narch = \"x86_64\"\n\n[[resolutions.packages]]\nidentity = \"registry:cran::foo@1.0\"\nversion = \"1.0\"\ndistributions = []\ndependencies = []\nartifact-url = \"/tmp/a\"\n";
        assert!(matches!(from_toml(forbidden), Err(LockWireError::Parse(_))));
        let text = to_toml(&logical_lock()).unwrap();
        for forbidden in [
            "artifact-url",
            "cache-path",
            "link-method",
            "artifact-sha256",
            "size",
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn reversed_logical_input_has_identical_wire_bytes() {
        let first = logical_lock();
        let mut resolution = first.resolutions[0].clone();
        resolution.packages.reverse();
        for package in &mut resolution.packages {
            package.dependencies.reverse();
            package.distributions.reverse();
        }
        let second = Lockfile::new(vec![resolution]).unwrap();
        assert_eq!(to_toml(&first).unwrap(), to_toml(&second).unwrap());
    }
}
