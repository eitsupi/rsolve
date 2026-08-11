use std::error::Error;
use std::fmt;

use nrr_core::{CandidateLoadError, CandidateLoader, Resolution};
use nrr_provider::cran::{CranCandidateLoader, CranCandidateLoaderError, CranRefreshDiagnostic};
use nrr_resolver::{DefaultCandidatePreference, PreferLocked, ResolutionFailure, Resolver};

use crate::manifest::{Manifest, ManifestError, compose_resolution_request};

/// The failure stage of a CRAN-backed resolution orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranResolutionError {
    Composition(ManifestError),
    Provider(CranCandidateLoaderError),
    Refresh(CandidateLoadError),
    Resolution(ResolutionFailure),
}

impl fmt::Display for CranResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Composition(error) => write!(formatter, "manifest composition failed: {error}"),
            Self::Provider(error) => {
                write!(formatter, "CRAN provider construction failed: {error}")
            }
            Self::Refresh(error) => write!(formatter, "CRAN refresh failed: {error}"),
            Self::Resolution(error) => write!(formatter, "resolution failed: {error}"),
        }
    }
}

impl Error for CranResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Composition(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::Refresh(error) => Some(error),
            Self::Resolution(error) => Some(error),
        }
    }
}

/// A concrete CRAN resolution together with its per-package refresh diagnostics.
#[derive(Clone, Debug)]
pub struct CranResolutionOutcome {
    resolution: Resolution,
    diagnostics: Vec<CranRefreshDiagnostic>,
}

impl CranResolutionOutcome {
    pub fn resolution(&self) -> &Resolution {
        &self.resolution
    }

    pub fn diagnostics(&self) -> &[CranRefreshDiagnostic] {
        &self.diagnostics
    }
}

/// Resolve a composed manifest through an injected candidate loader.
///
/// This helper keeps orchestration tests hermetic while exercising the same
/// resolver policy used by the concrete CRAN entry point.
pub fn resolve_with_loader(
    manifest: Manifest,
    loader: &dyn CandidateLoader,
) -> Result<Resolution, CranResolutionError> {
    let request = compose_resolution_request(manifest).map_err(CranResolutionError::Composition)?;
    resolve_request(request, loader)
}

fn resolve_request(
    request: nrr_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
) -> Result<Resolution, CranResolutionError> {
    let preference = DefaultCandidatePreference;
    let lock_policy = PreferLocked;
    Resolver::new(loader, &preference, &lock_policy)
        .resolve(request)
        .map_err(CranResolutionError::Resolution)
}

/// Resolve a manifest against CRAN's synchronous blocking candidate loader.
///
/// This boundary is synchronous; callers running inside an async runtime
/// should invoke it on a blocking worker rather than directly on an async
/// executor thread.
pub fn resolve_from_cran(
    manifest: Manifest,
    base_url: impl AsRef<str>,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    let request = compose_resolution_request(manifest).map_err(CranResolutionError::Composition)?;
    let loader = CranCandidateLoader::new(base_url).map_err(CranResolutionError::Provider)?;
    let roots = request
        .requirements
        .iter()
        .map(|requirement| requirement.name.clone())
        .collect::<Vec<_>>();
    let snapshot = loader
        .refresh_closure(&roots)
        .map_err(CranResolutionError::Refresh)?;
    let resolution = resolve_request(request, &snapshot)?;
    Ok(CranResolutionOutcome {
        resolution,
        diagnostics: loader.diagnostics(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_core::{
        CandidateLoadError, CandidateLoadErrorCategory, PackageName, PackageNamespace,
        PackageRelease, Provenance, RPackageVersion, ReleaseIdentity, ReleaseMetadata,
        ReleaseObservation, SolverKey, VersionConstraint,
    };
    use std::collections::BTreeMap;

    struct FixtureLoader {
        package: PackageRelease,
    }

    impl CandidateLoader for FixtureLoader {
        fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            match package {
                SolverKey::InstalledName(name) if name == self.package.identity().name() => {
                    Ok(vec![self.package.clone()])
                }
                SolverKey::InstalledName(_) => Ok(Vec::new()),
                SolverKey::R => Ok(Vec::new()),
                _ => Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    "fixture has no candidates for this solver key",
                )),
            }
        }
    }

    fn fixture_loader() -> FixtureLoader {
        let package = PackageName::new("fixture").unwrap();
        let version = RPackageVersion::parse("1.0.0").unwrap();
        let identity = ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        );
        let observation = ReleaseObservation {
            identity,
            observed_package: package,
            observed_version: version,
            metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
            dependencies: Vec::new(),
            distributions: Vec::new(),
        };
        FixtureLoader {
            package: PackageRelease::try_from(observation).unwrap(),
        }
    }

    #[test]
    fn injected_loader_exercises_manifest_to_resolution_orchestration() {
        let manifest = Manifest::new(
            VersionConstraint::from_clause(
                nrr_core::RelationOp::Ge,
                RPackageVersion::parse("4.0").unwrap(),
            ),
            crate::manifest::ManifestTarget::new(
                RPackageVersion::parse("4.4.0").unwrap(),
                "linux",
                "x86_64",
            )
            .unwrap(),
            vec![crate::manifest::ManifestDependency::new(
                PackageName::new("fixture").unwrap(),
                VersionConstraint::unconstrained(),
            )],
        )
        .unwrap();
        let loader = fixture_loader();
        let resolution = resolve_with_loader(manifest, &loader).unwrap();
        assert_eq!(
            resolution
                .selected(&PackageName::new("fixture").unwrap())
                .unwrap()
                .version(),
            &RPackageVersion::parse("1.0.0").unwrap()
        );
    }
}
