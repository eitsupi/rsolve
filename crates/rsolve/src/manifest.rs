use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use rsolve_core::{
    DependencySourceConstraint, LockedIdentities, PackageRequirement, RPackageVersion,
    RepositoryId, ResolutionRequest, ResolutionTarget, RootExpansionPolicy, RootRequirement,
    VersionConstraint,
};

/// The deliberately small, typed manifest subset used by the first slice.
///
/// This is an in-memory composition input, not a claim about the eventual
/// `rsolve.toml` wire schema.  TOML parsing and schema evolution remain outside
/// this slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub r_requirement: VersionConstraint,
    pub target: ManifestTarget,
    pub requirements: Vec<ManifestDependency>,
}

impl Manifest {
    pub fn new(
        r_requirement: VersionConstraint,
        target: ManifestTarget,
        requirements: Vec<ManifestDependency>,
    ) -> Result<Self, ManifestError> {
        let manifest = Self {
            r_requirement,
            target,
            requirements,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn into_resolution_request(self) -> Result<ResolutionRequest, ManifestError> {
        compose_resolution_request(self)
    }

    fn validate(&self) -> Result<(), ManifestError> {
        let mut names = HashSet::with_capacity(self.requirements.len());
        for requirement in &self.requirements {
            if requirement.name.as_str() == "R" {
                return Err(ManifestError::RIsNotAPackageRequirement);
            }
            if !names.insert(requirement.name.clone()) {
                return Err(ManifestError::DuplicateRequirement {
                    name: requirement.name.clone(),
                });
            }
        }
        Ok(())
    }
}

/// A direct package requirement in the first-slice manifest.
///
/// All direct requirements are ordinary `Depends` roots with an unconstrained
/// source scope.  Other dependency kinds and source selectors belong to the
/// later manifest schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestDependency {
    pub name: rsolve_core::PackageName,
    pub constraint: VersionConstraint,
}

impl ManifestDependency {
    pub fn new(name: rsolve_core::PackageName, constraint: VersionConstraint) -> Self {
        Self { name, constraint }
    }
}

/// The one logical target supported by the first slice: an exact R version.
/// Host operating system and architecture are deliberately not part of the
/// shared resolution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestTarget {
    pub r_version: RPackageVersion,
}

impl ManifestTarget {
    pub fn new(r_version: RPackageVersion) -> Self {
        Self { r_version }
    }

    fn into_resolution_target(self) -> ResolutionTarget {
        ResolutionTarget::new(self.r_version)
    }
}

/// Errors from validating or composing the first-slice manifest subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    RIsNotAPackageRequirement,
    DuplicateRequirement { name: rsolve_core::PackageName },
    InvalidDependency(String),
    Toml(String),
    Io { path: PathBuf, source: String },
    NotFound { start: PathBuf },
    UnknownSchema { schema: i64 },
    MissingField { field: String },
    InvalidField { field: String, reason: String },
    UnknownField { field: String },
    WrongType { field: String, expected: String },
    UnknownRegistryKind { kind: String },
    InvalidRegistry { reason: String },
    InvalidRepository { reason: String },
    DuplicateRepository { id: RepositoryId },
    UnknownRepositoryReference { id: RepositoryId, field: String },
    UnknownEnvironmentGroup { environment: String, group: String },
    DuplicateEnvironmentGroup { environment: String, group: String },
    UnknownEnvironment { id: String },
    InvalidVersionConstraint { field: String, reason: String },
    TargetOutsideRConstraint { target: String, constraint: String },
    DirectSourceRequiresAcquisition { name: rsolve_core::PackageName },
    InvalidIdentifier { kind: String, value: String },
    InvalidEndpoint { value: String, reason: String },
    SourceConflict { field: String },
    InvalidDependencyField { name: String, reason: String },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RIsNotAPackageRequirement => f.write_str(
                "R is expressed by the manifest R constraint, not a package requirement",
            ),
            Self::DuplicateRequirement { name } => {
                write!(f, "manifest has duplicate direct requirement {name}")
            }
            Self::InvalidDependency(error) => write!(f, "invalid package requirement: {error}"),
            Self::Toml(error) => write!(f, "invalid manifest TOML: {error}"),
            Self::Io { path, source } => {
                write!(f, "failed to read manifest {}: {source}", path.display())
            }
            Self::NotFound { start } => write!(
                f,
                "no rsolve.toml found from {} to filesystem root",
                start.display()
            ),
            Self::UnknownSchema { schema } => write!(f, "unsupported manifest schema {schema}"),
            Self::MissingField { field } => {
                write!(f, "manifest is missing required field `{field}`")
            }
            Self::InvalidField { field, reason } => {
                write!(f, "invalid manifest field `{field}`: {reason}")
            }
            Self::UnknownField { field } => write!(f, "unknown manifest field `{field}`"),
            Self::WrongType { field, expected } => {
                write!(f, "manifest field `{field}` must be {expected}")
            }
            Self::UnknownRegistryKind { kind } => write!(f, "unknown registry kind `{kind}`"),
            Self::InvalidRegistry { reason } => {
                write!(f, "invalid registry specification: {reason}")
            }
            Self::InvalidRepository { reason } => write!(f, "invalid repository: {reason}"),
            Self::DuplicateRepository { id } => write!(f, "duplicate repository ID `{id}`"),
            Self::UnknownRepositoryReference { id, field } => {
                write!(
                    f,
                    "dependency `{field}` references unknown repository `{id}`"
                )
            }
            Self::UnknownEnvironmentGroup { environment, group } => write!(
                f,
                "environment `{environment}` references unknown group `{group}`"
            ),
            Self::DuplicateEnvironmentGroup { environment, group } => write!(
                f,
                "environment `{environment}` references group `{group}` more than once"
            ),
            Self::UnknownEnvironment { id } => write!(f, "unknown environment `{id}`"),
            Self::InvalidVersionConstraint { field, reason } => {
                write!(f, "invalid version constraint `{field}`: {reason}")
            }
            Self::TargetOutsideRConstraint { target, constraint } => write!(
                f,
                "target R version `{target}` does not satisfy constraint `{constraint}`"
            ),
            Self::DirectSourceRequiresAcquisition { name } => write!(
                f,
                "direct source for `{name}` requires acquisition before resolution"
            ),
            Self::InvalidIdentifier { kind, value } => {
                write!(f, "invalid {kind} identifier `{value}`")
            }
            Self::InvalidEndpoint { value, reason } => {
                write!(f, "invalid endpoint `{value}`: {reason}")
            }
            Self::SourceConflict { field } => {
                write!(f, "conflicting or unsupported source fields in `{field}`")
            }
            Self::InvalidDependencyField { name, reason } => {
                write!(f, "invalid dependency `{name}`: {reason}")
            }
        }
    }
}

impl Error for ManifestError {}

/// Compose the minimal manifest into exactly one owned request.
pub fn compose_resolution_request(manifest: Manifest) -> Result<ResolutionRequest, ManifestError> {
    compose_resolution_request_with_locked(manifest, LockedIdentities::new())
}

/// Compose the minimal manifest while carrying an already-read, owned lock
/// identity mapping into the request.
pub fn compose_resolution_request_with_locked(
    manifest: Manifest,
    locked: LockedIdentities,
) -> Result<ResolutionRequest, ManifestError> {
    manifest.validate()?;
    let Manifest {
        r_requirement,
        target,
        requirements,
    } = manifest;

    let roots = requirements
        .into_iter()
        .map(|requirement| {
            Ok(RootRequirement {
                package: PackageRequirement::new(
                    requirement.name,
                    DependencySourceConstraint::Any,
                    requirement.constraint,
                )
                .map_err(|error| ManifestError::InvalidDependency(error.to_string()))?,
                expansion: RootExpansionPolicy::HardOnly,
            })
        })
        .collect::<Result<Vec<_>, ManifestError>>()?;

    Ok(ResolutionRequest::new(
        roots,
        target.into_resolution_target(),
        r_requirement,
        locked,
    ))
}

mod compose;
mod repository;
mod wire;

pub use compose::{ComposedEnvironment, ComposedRootIntent};
pub(crate) use repository::configured_registry_id_for;
pub use repository::{
    EffectiveRepository, Endpoint, RegistryProvenancePolicy, RegistrySpec, RepositorySpec,
};
pub use wire::{
    DirectUrl, GitSelector, ManifestDependencySpec, ManifestDocument, ManifestSource,
    discover_manifest, load_manifest, parse_manifest, read_manifest,
};

#[cfg(test)]
mod tests;
