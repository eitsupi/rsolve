use std::error::Error;
use std::fmt;

use rsolve::{Manifest, ManifestDependency, ManifestTarget, resolve_from_cran};
use rsolve_core::{PackageName, PackageRelease, RPackageVersion, Resolution, VersionConstraint};

const DEFAULT_CRAN_MIRROR: &str = "https://cloud.r-project.org";
const DEFAULT_R_VERSIONS: [&str; 2] = ["4.3.3", "4.4.0"];

#[derive(Clone, Debug, Eq, PartialEq)]
struct Config {
    mirror: Box<str>,
    r_versions: Vec<RPackageVersion>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConfigError {
    EmptyMirror,
    InvalidMirror {
        diagnostic: Box<str>,
    },
    InvalidRVersion {
        input: Box<str>,
        diagnostic: Box<str>,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMirror => formatter.write_str("RSOLVE_CRAN_MIRROR must not be empty"),
            Self::InvalidMirror { diagnostic } => {
                write!(formatter, "invalid CRAN mirror: {diagnostic}")
            }
            Self::InvalidRVersion { input, diagnostic } => {
                write!(
                    formatter,
                    "invalid target R version {input:?}: {diagnostic}"
                )
            }
        }
    }
}

impl Error for ConfigError {}

fn parse_config(mirror: Option<&str>, version_args: &[&str]) -> Result<Config, ConfigError> {
    let mirror = canonical_mirror(mirror.unwrap_or(DEFAULT_CRAN_MIRROR))?;
    let inputs = if version_args.is_empty() {
        DEFAULT_R_VERSIONS.as_slice()
    } else {
        version_args
    };
    let r_versions = inputs
        .iter()
        .map(|input| {
            RPackageVersion::parse(input).map_err(|error| ConfigError::InvalidRVersion {
                input: (*input).into(),
                diagnostic: error.to_string().into(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Config { mirror, r_versions })
}

fn canonical_mirror(input: &str) -> Result<Box<str>, ConfigError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ConfigError::EmptyMirror);
    }
    let mut url = url::Url::parse(input).map_err(|error| ConfigError::InvalidMirror {
        diagnostic: error.to_string().into(),
    })?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::InvalidMirror {
            diagnostic: "mirror URL must not include userinfo".into(),
        });
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ConfigError::InvalidMirror {
            diagnostic: "mirror must use HTTP or HTTPS".into(),
        });
    }
    if url.host_str().is_none() || url.cannot_be_a_base() {
        return Err(ConfigError::InvalidMirror {
            diagnostic: "mirror must be hierarchical and include a host".into(),
        });
    }
    if url.query().is_some() {
        return Err(ConfigError::InvalidMirror {
            diagnostic: "mirror must not include a query".into(),
        });
    }
    if url.fragment().is_some() {
        return Err(ConfigError::InvalidMirror {
            diagnostic: "mirror must not include a fragment".into(),
        });
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.to_string().trim_end_matches('/').into())
}

fn config_from_environment(version_args: &[&str]) -> Result<Config, ConfigError> {
    let mirror = match std::env::var("RSOLVE_CRAN_MIRROR") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ConfigError::InvalidMirror {
                diagnostic: "RSOLVE_CRAN_MIRROR is not valid UTF-8".into(),
            });
        }
    };
    parse_config(mirror.as_deref(), version_args)
}

fn format_identity(release: &PackageRelease) -> String {
    format!(
        "{} @ {} ({:?})",
        release.identity().name(),
        release.version(),
        release.identity().provenance()
    )
}

fn format_resolution(mirror: &str, resolution: &Resolution) -> String {
    let matrix = PackageName::new("Matrix").expect("Matrix is a valid package name");
    let selected_matrix = resolution
        .selected(&matrix)
        .map(format_identity)
        .unwrap_or_else(|| "not selected".to_owned());
    let mut output = format!(
        "mirror: {mirror}\ntarget R: {}\nselected Matrix: {selected_matrix}\ninstallable resolution closure:\n",
        resolution.target().r_version
    );
    let mut packages = resolution.packages().iter().collect::<Vec<_>>();
    packages.sort_by(|left, right| {
        left.name()
            .cmp(right.name())
            .then_with(|| left.version().cmp(right.version()))
    });
    for package in packages {
        output.push_str(&format!("- {}\n", format_identity(package.release())));
    }
    output
}

fn matrix_manifest(r_version: RPackageVersion) -> Result<Manifest, Box<dyn Error>> {
    Ok(Manifest::new(
        VersionConstraint::unconstrained(),
        ManifestTarget::new(r_version),
        vec![ManifestDependency::new(
            PackageName::new("Matrix")?,
            VersionConstraint::unconstrained(),
        )],
    )?)
}

fn run(config: Config) -> Result<(), Box<dyn Error>> {
    for r_version in config.r_versions {
        let manifest = matrix_manifest(r_version.clone())?;
        let outcome = resolve_from_cran(manifest, config.mirror.as_ref())?;
        print!(
            "{}",
            format_resolution(&config.mirror, outcome.resolution())
        );
    }
    Ok(())
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let version_args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let result = config_from_environment(&version_args)
        .map_err(|error| Box::new(error) as Box<dyn Error>)
        .and_then(run);
    if let Err(error) = result {
        eprintln!("cran_matrix: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsolve_core::{
        Provenance, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, ResolutionTarget,
        ResolvedPackage, SolverKey,
    };

    fn version(value: &str) -> RPackageVersion {
        RPackageVersion::parse(value).unwrap()
    }

    #[test]
    fn defaults_are_explicit_and_mirror_is_canonicalized() {
        let config = parse_config(Some(" https://cloud.r-project.org/// "), &[]).unwrap();
        assert_eq!(config.mirror, DEFAULT_CRAN_MIRROR.into());
        assert_eq!(config.r_versions, [version("4.3.3"), version("4.4.0")]);
    }

    #[test]
    fn positional_versions_are_preserved_in_order() {
        let config = parse_config(Some("https://example.test/cran"), &["4.4.0", "4.3.3"]).unwrap();
        assert_eq!(config.r_versions, [version("4.4.0"), version("4.3.3")]);
    }

    #[test]
    fn invalid_mirror_and_versions_fail_without_environment_mutation() {
        assert_eq!(parse_config(Some(""), &[]), Err(ConfigError::EmptyMirror));
        assert!(matches!(
            parse_config(Some("file:///tmp/cran"), &[]),
            Err(ConfigError::InvalidMirror { .. })
        ));
        assert!(matches!(
            parse_config(Some(DEFAULT_CRAN_MIRROR), &["not-a-version"]),
            Err(ConfigError::InvalidRVersion { .. })
        ));
    }

    #[test]
    fn mirror_userinfo_is_rejected_without_network_access() {
        for mirror in [
            "https://username@example.test/cran",
            "https://username:password@example.test/cran",
        ] {
            assert_eq!(
                parse_config(Some(mirror), &[]),
                Err(ConfigError::InvalidMirror {
                    diagnostic: "mirror URL must not include userinfo".into(),
                })
            );
        }
    }

    #[test]
    fn output_is_stable_and_excludes_runtime_provided_base_packages() {
        let matrix = PackageName::new("Matrix").unwrap();
        let methods = PackageName::new("methods").unwrap();
        let matrix_version = version("1.7-0");
        let target = ResolutionTarget::new(version("4.4.0"));
        let metadata = ReleaseMetadata::new(std::collections::BTreeMap::new()).unwrap();
        let matrix_release = PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                matrix.clone(),
                Provenance::RegistryRelease {
                    namespace: rsolve_core::PackageNamespace::new("cran").unwrap(),
                    version: matrix_version.clone(),
                },
            ),
            observed_package: matrix.clone(),
            observed_version: matrix_version,
            metadata: metadata.clone(),
            publication: None,
            declared_dependencies: Vec::new(),
            distributions: Vec::new(),
        })
        .unwrap();
        let methods_release = PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                methods.clone(),
                Provenance::RBasePackage {
                    r_version: version("4.4.0"),
                },
            ),
            observed_package: methods,
            observed_version: version("4.4.0"),
            metadata,
            publication: None,
            declared_dependencies: Vec::new(),
            distributions: Vec::new(),
        })
        .unwrap();
        let resolution = Resolution::new(
            target,
            vec![
                ResolvedPackage::new(SolverKey::InstalledName(matrix), matrix_release),
                ResolvedPackage::new(
                    SolverKey::InstalledName(PackageName::new("methods").unwrap()),
                    methods_release,
                ),
            ],
        );

        let output = format_resolution(DEFAULT_CRAN_MIRROR, &resolution);
        assert!(output.contains("selected Matrix: Matrix @ 1.7-0"));
        assert!(output.contains("- Matrix @ 1.7-0"));
        assert!(!output.contains("methods"));
    }
}
