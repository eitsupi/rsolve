use crate::r_versions::RPackageVersion;

/// The exact R version used as the solver's fixed logical target.
///
/// Host operating system and architecture are artifact-compatibility concerns,
/// not axes of the shared logical resolution.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResolutionTarget {
    pub r_version: RPackageVersion,
}

impl ResolutionTarget {
    pub fn new(r_version: RPackageVersion) -> Self {
        Self { r_version }
    }
}
