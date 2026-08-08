use crate::r_versions::RPackageVersion;

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

impl ResolutionTarget {
    pub fn new(r_version: RPackageVersion, platform: Target) -> Self {
        Self {
            r_version,
            platform,
        }
    }
}
