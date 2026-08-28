use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use rsolve_core::{
    DependencySourceConstraint, LockedIdentities, PackageRequirement, RPackageVersion,
    ResolutionRequest, ResolutionTarget, RootExpansionPolicy, RootRequirement, VersionConstraint,
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

#[cfg(test)]
mod tests {
    use super::*;
    use rsolve_core::{
        PackageName, PackageNamespace, Provenance, RelationOp, ReleaseIdentity, SolverKey,
        VersionClause,
    };

    fn version(value: &str) -> RPackageVersion {
        RPackageVersion::parse(value).unwrap()
    }

    fn package(value: &str) -> PackageName {
        PackageName::new(value).unwrap()
    }

    fn minimal_manifest() -> Manifest {
        Manifest::new(
            VersionConstraint::from_clause(RelationOp::Ge, version("4.3")),
            ManifestTarget::new(version("4.4.0")),
            vec![ManifestDependency::new(
                package("example"),
                VersionConstraint::new(vec![VersionClause::new(RelationOp::Ge, version("1.2.0"))]),
            )],
        )
        .unwrap()
    }

    #[test]
    fn minimal_manifest_composes_to_one_request() {
        let request = compose_resolution_request(minimal_manifest()).unwrap();

        assert_eq!(request.roots.len(), 1);
        assert_eq!(request.roots[0].package.name(), &package("example"));
        assert_eq!(
            request.roots[0].package.constraint(),
            &VersionConstraint::from_clause(RelationOp::Ge, version("1.2.0"))
        );
        assert_eq!(request.target.r_version, version("4.4.0"));
        assert_eq!(
            request.r_requirement,
            VersionConstraint::from_clause(RelationOp::Ge, version("4.3"))
        );
        assert!(request.locked.is_empty());
    }

    #[test]
    fn composition_preserves_owned_lock_identity_mapping() {
        let key = SolverKey::Registry {
            namespace: PackageNamespace::new("cran").unwrap(),
            name: package("example"),
        };
        let identity = ReleaseIdentity::new(
            package("example"),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.2.3"),
            },
        );
        let mut locked = LockedIdentities::new();
        locked.insert(key.clone(), identity.clone());

        let request =
            compose_resolution_request_with_locked(minimal_manifest(), locked.clone()).unwrap();
        assert_eq!(request.locked, locked);
        assert_eq!(request.locked.get(&key), Some(&identity));
    }

    #[test]
    fn manifest_rejects_r_as_a_regular_requirement() {
        let result = Manifest::new(
            VersionConstraint::unconstrained(),
            ManifestTarget::new(version("4.4.0")),
            vec![ManifestDependency::new(
                package("R"),
                VersionConstraint::unconstrained(),
            )],
        );
        assert_eq!(result, Err(ManifestError::RIsNotAPackageRequirement));
    }

    #[test]
    fn manifest_rejects_duplicate_requirements() {
        let result = Manifest::new(
            VersionConstraint::unconstrained(),
            ManifestTarget::new(version("4.4.0")),
            vec![
                ManifestDependency::new(package("example"), VersionConstraint::unconstrained()),
                ManifestDependency::new(package("example"), VersionConstraint::unconstrained()),
            ],
        );
        assert_eq!(
            result,
            Err(ManifestError::DuplicateRequirement {
                name: package("example")
            })
        );
    }
}
