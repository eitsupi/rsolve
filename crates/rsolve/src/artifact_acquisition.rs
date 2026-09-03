//! Acquisition of source archives for already selected R-universe releases.
//!
//! Candidate selection and repository preparation happen before this boundary.
//! This module only binds one selected release to its validated R-universe
//! source artifact and the repository cache.

use std::fmt;
use std::io::Read;

use rsolve_core::{
    Artifact, ArtifactLocator, Distribution, PackageRelease, Provenance, ResolvedPackage,
    SourceArtifact,
};
use rsolve_repository::{
    ArtifactValidationExpectation, CacheError, CachedArtifact, MaterializationArtifact,
    commit_source_artifact_with_expectation, probe_artifact,
};
use thiserror::Error;
use url::Url;

/// Whether a cache miss may be filled from the selected artifact locator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactAcquisitionMode {
    Offline,
    Online,
}

/// A streaming HTTP response supplied by an artifact fetcher.
pub struct ArtifactFetchResponse {
    pub status: u16,
    pub reader: Box<dyn Read>,
}

/// Injectable source archive transport used by tests and alternate clients.
pub trait ArtifactFetcher {
    fn fetch(&self, locator: &str) -> Result<ArtifactFetchResponse, ArtifactFetchError>;
}

/// Errors reported by an artifact transport before repository validation.
#[derive(Debug, Error)]
pub enum ArtifactFetchError {
    #[error("artifact request failed for {locator}: {reason}")]
    Transport { locator: String, reason: String },
}

/// The production HTTPS artifact fetcher.
pub struct UreqArtifactFetcher {
    agent: ureq::Agent,
}

impl UreqArtifactFetcher {
    pub fn new() -> Self {
        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(tls_config)
            .build();
        Self {
            agent: config.new_agent(),
        }
    }
}

impl Default for UreqArtifactFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactFetcher for UreqArtifactFetcher {
    fn fetch(&self, locator: &str) -> Result<ArtifactFetchResponse, ArtifactFetchError> {
        let response =
            self.agent
                .get(locator)
                .call()
                .map_err(|error| ArtifactFetchError::Transport {
                    locator: locator.to_owned(),
                    reason: error.to_string(),
                })?;
        let status = response.status().as_u16();
        let body = response.into_body();
        if body
            .content_length()
            .is_some_and(|size| size > rsolve_repository::MAX_COMPRESSED_INPUT_BYTES)
        {
            return Err(ArtifactFetchError::Transport {
                locator: locator.to_owned(),
                reason: "response exceeds the artifact size limit".to_owned(),
            });
        }
        let reader = body
            .into_reader()
            .take(rsolve_repository::MAX_COMPRESSED_INPUT_BYTES + 1);
        Ok(ArtifactFetchResponse {
            status,
            reader: Box::new(reader),
        })
    }
}

/// Typed failures at the selected-artifact acquisition boundary.
#[derive(Debug, Error)]
pub enum ArtifactAcquisitionError {
    #[error("selected package {package} is not a Git-backed R-universe release")]
    NotRUniverseRelease { package: String },
    #[error("selected package {package} has no visible R-universe source artifact")]
    NoRUniverseArtifact { package: String },
    #[error("selected package {package} has ambiguous R-universe source artifacts")]
    AmbiguousArtifact { package: String },
    #[error("artifact locator {locator} is not an absolute HTTP(S) URL")]
    InvalidLocator { locator: String },
    #[error("R-universe repository configuration is invalid: {reason}")]
    InvalidRepository { reason: String },
    #[error("offline artifact cache miss for {package}")]
    OfflineMiss { package: String },
    #[error("artifact locator {locator} returned HTTP {status}")]
    HttpStatus { locator: String, status: u16 },
    #[error(transparent)]
    Fetch(#[from] ArtifactFetchError),
    #[error(transparent)]
    Cache(#[from] CacheError),
}

impl ArtifactAcquisitionError {
    fn package_name(package: &rsolve_core::PackageName) -> String {
        package.to_string()
    }
}

/// Acquire and validate the source artifact for one selected package.
pub fn acquire_selected_artifact<F: ArtifactFetcher>(
    cache_root: impl AsRef<std::path::Path>,
    selected: &ResolvedPackage,
    composed: &crate::manifest::ComposedEnvironment,
    mode: ArtifactAcquisitionMode,
    fetcher: &F,
) -> Result<MaterializationArtifact, ArtifactAcquisitionError> {
    let package = selected.name();
    let mut artifact = None;
    for repository_id in selected.visible_repository_ids() {
        let Some(repository) = composed
            .repositories
            .iter()
            .find(|repository| repository.id() == repository_id)
        else {
            continue;
        };
        if !repository.package_allowed(package)
            || !matches!(
                repository.registry(),
                crate::manifest::RegistrySpec::RUniverse
            )
        {
            continue;
        }
        let registry = repository.configured_registry_id().map_err(|error| {
            ArtifactAcquisitionError::InvalidRepository {
                reason: error.to_string(),
            }
        })?;
        let occurrence_artifacts = selected
            .distributions()
            .iter()
            .filter(|distribution| distribution.registry == registry)
            .flat_map(source_artifacts)
            .collect::<Vec<_>>();
        if occurrence_artifacts.is_empty() {
            continue;
        }
        artifact = Some(unique_artifact(package, occurrence_artifacts)?.clone());
        break;
    }
    let artifact = artifact.ok_or_else(|| ArtifactAcquisitionError::NoRUniverseArtifact {
        package: ArtifactAcquisitionError::package_name(package),
    })?;
    let expectation = expectation_for_release(selected.release())?;
    let cached = match probe_artifact(cache_root.as_ref(), &artifact, &expectation)? {
        Some(cached) => cached,
        None if mode == ArtifactAcquisitionMode::Offline => {
            return Err(ArtifactAcquisitionError::OfflineMiss {
                package: package.to_string(),
            });
        }
        None => {
            validate_http_locator(&artifact.locator)?;
            let response = fetcher.fetch(artifact.locator.as_str())?;
            if response.status != 200 {
                return Err(ArtifactAcquisitionError::HttpStatus {
                    locator: artifact.locator.to_string(),
                    status: response.status,
                });
            }
            commit_source_artifact_with_expectation(
                cache_root,
                &artifact,
                &expectation,
                response.reader,
            )?
        }
    };
    Ok(materialization_artifact(selected.release(), cached))
}

fn source_artifacts(distribution: &Distribution) -> Vec<&SourceArtifact> {
    if distribution.channel.as_str() != "source" {
        return Vec::new();
    }
    distribution
        .artifacts
        .iter()
        .map(|artifact| match artifact {
            Artifact::Source(source) => source,
        })
        .collect()
}

fn unique_artifact<'a>(
    package: &rsolve_core::PackageName,
    artifacts: Vec<&'a SourceArtifact>,
) -> Result<&'a SourceArtifact, ArtifactAcquisitionError> {
    let Some(first) = artifacts.first().copied() else {
        return Err(ArtifactAcquisitionError::NoRUniverseArtifact {
            package: ArtifactAcquisitionError::package_name(package),
        });
    };
    if artifacts.iter().skip(1).any(|artifact| *artifact != first) {
        return Err(ArtifactAcquisitionError::AmbiguousArtifact {
            package: ArtifactAcquisitionError::package_name(package),
        });
    }
    Ok(first)
}

fn expectation_for_release(
    release: &PackageRelease,
) -> Result<ArtifactValidationExpectation, ArtifactAcquisitionError> {
    let expectation = ArtifactValidationExpectation::new(
        release.identity().name().clone(),
        release.version().clone(),
    );
    match release.identity().provenance() {
        Provenance::GitCommit {
            repository,
            commit,
            subdirectory,
        } => Ok(expectation.with_git_provenance(
            repository.clone(),
            commit.clone(),
            subdirectory.clone(),
        )),
        _ => Err(ArtifactAcquisitionError::NotRUniverseRelease {
            package: release.identity().name().to_string(),
        }),
    }
}

fn validate_http_locator(locator: &ArtifactLocator) -> Result<(), ArtifactAcquisitionError> {
    let url =
        Url::parse(locator.as_str()).map_err(|_| ArtifactAcquisitionError::InvalidLocator {
            locator: locator.to_string(),
        })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ArtifactAcquisitionError::InvalidLocator {
            locator: locator.to_string(),
        });
    }
    Ok(())
}

fn materialization_artifact(
    release: &PackageRelease,
    artifact: CachedArtifact,
) -> MaterializationArtifact {
    let mut selected = MaterializationArtifact::new(
        release.identity().clone(),
        release.version().clone(),
        artifact,
    )
    .with_metadata(
        release.metadata().clone(),
        release.declared_dependencies().to_vec(),
    );
    if let Some(publication) = release.publication() {
        selected = selected.with_publication(*publication);
    }
    selected
}

impl fmt::Debug for ArtifactFetchResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactFetchResponse")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rsolve_core::{
        DistributionChannel, DistributionMetadata, EnvironmentId, GitCommitId, NormalizedGitUrl,
        PackageName, PackageNamespace, ReleaseIdentity, ReleaseMetadata, ReleaseObservation,
        RepositoryId, ResolutionTarget, Sha256Digest, SolverKey, VersionConstraint,
    };
    use sha2::Digest as _;

    struct FixtureFetcher {
        status: u16,
        bytes: Vec<u8>,
        calls: Cell<usize>,
        locator: String,
        failure: Option<String>,
    }

    impl ArtifactFetcher for FixtureFetcher {
        fn fetch(&self, locator: &str) -> Result<ArtifactFetchResponse, ArtifactFetchError> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(locator, self.locator);
            if let Some(reason) = &self.failure {
                return Err(ArtifactFetchError::Transport {
                    locator: locator.to_owned(),
                    reason: reason.clone(),
                });
            }
            Ok(ArtifactFetchResponse {
                status: self.status,
                reader: Box::new(Cursor::new(self.bytes.clone())),
            })
        }
    }

    fn repository() -> crate::manifest::RepositorySpec {
        repository_named("universe", "https://custom.example/universe/")
    }

    fn repository_named(id: &str, endpoint: &str) -> crate::manifest::RepositorySpec {
        crate::manifest::RepositorySpec::new(
            RepositoryId::new(id).unwrap(),
            crate::manifest::RegistrySpec::RUniverse,
            crate::manifest::Endpoint::new(endpoint).unwrap(),
        )
        .unwrap()
    }

    fn selected(
        locator: &str,
        extra_distribution: Option<Distribution>,
    ) -> (ResolvedPackage, crate::manifest::ComposedEnvironment) {
        selected_with_identity(locator, extra_distribution, true)
    }

    fn selected_with_identity(
        locator: &str,
        extra_distribution: Option<Distribution>,
        git_identity: bool,
    ) -> (ResolvedPackage, crate::manifest::ComposedEnvironment) {
        selected_with_content(
            locator,
            extra_distribution,
            git_identity,
            archive("example", "1.0", ""),
            true,
        )
    }

    fn selected_with_content(
        locator: &str,
        extra_distribution: Option<Distribution>,
        git_identity: bool,
        contents: Vec<u8>,
        include_source: bool,
    ) -> (ResolvedPackage, crate::manifest::ComposedEnvironment) {
        selected_with_version_and_content(
            locator,
            extra_distribution,
            git_identity,
            contents,
            include_source,
            "1.0",
        )
    }

    fn selected_with_version_and_content(
        locator: &str,
        extra_distribution: Option<Distribution>,
        git_identity: bool,
        contents: Vec<u8>,
        include_source: bool,
        version_text: &str,
    ) -> (ResolvedPackage, crate::manifest::ComposedEnvironment) {
        let package = PackageName::new("example").unwrap();
        let version = rsolve_core::RPackageVersion::parse(version_text).unwrap();
        let repository = repository();
        let registry = repository.configured_registry_id().unwrap();
        let identity = if git_identity {
            ReleaseIdentity::new(
                package.clone(),
                Provenance::GitCommit {
                    repository: NormalizedGitUrl::new("https://example.test/project").unwrap(),
                    commit: GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
                    subdirectory: None,
                },
            )
        } else {
            ReleaseIdentity::new(
                package.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            )
        };
        let source = SourceArtifact {
            locator: ArtifactLocator::new(locator).unwrap(),
            upstream_checksums: vec![rsolve_core::UpstreamChecksum::Sha256(
                Sha256Digest::new(hex_lower(&sha2::Sha256::digest(&contents))).unwrap(),
            )],
            size: Some(contents.len() as u64),
        };
        let mut distributions = vec![Distribution {
            registry,
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: None,
            artifacts: if include_source {
                vec![Artifact::Source(source)]
            } else {
                Vec::new()
            },
            observed_metadata: DistributionMetadata::default(),
        }];
        if let Some(distribution) = extra_distribution {
            distributions.push(distribution);
        }
        let release = PackageRelease::try_from(ReleaseObservation {
            identity,
            observed_package: package.clone(),
            observed_version: version.clone(),
            metadata: ReleaseMetadata::from_pairs([("Title", "Example package")]).unwrap(),
            publication: Some(rsolve_core::ReleasePublication::new(
                rsolve_core::PublicationDate::parse("2024-01-02").unwrap(),
            )),
            declared_dependencies: vec![
                rsolve_core::DeclaredDependency::from_parts(
                    rsolve_core::DependencyKind::Imports,
                    PackageName::new("dependency").unwrap(),
                    rsolve_core::DependencySourceConstraint::Any,
                    VersionConstraint::from_clause(
                        rsolve_core::RelationOp::Ge,
                        rsolve_core::RPackageVersion::parse("1.0").unwrap(),
                    ),
                )
                .unwrap(),
            ],
            distributions,
        })
        .unwrap();
        let selected = ResolvedPackage::new(
            SolverKey::InstalledName(package.clone()),
            release,
            Vec::new(),
            vec![repository.id().clone()],
        );
        let composed = crate::manifest::ComposedEnvironment {
            environment: EnvironmentId::new("default").unwrap(),
            r_requirement: VersionConstraint::unconstrained(),
            published_before: None,
            target: ResolutionTarget::new(rsolve_core::RPackageVersion::parse_bare("4.4").unwrap()),
            repositories: vec![repository],
            roots: Vec::new(),
            locked: rsolve_core::LockedIdentities::new(),
        };
        (selected, composed)
    }

    fn selected_with_repository_distributions(
        repositories: &[crate::manifest::RepositorySpec],
        distributions: Vec<Distribution>,
        visible_repository_ids: Vec<RepositoryId>,
    ) -> (ResolvedPackage, crate::manifest::ComposedEnvironment) {
        let package = PackageName::new("example").unwrap();
        let version = rsolve_core::RPackageVersion::parse("1.0").unwrap();
        let identity = ReleaseIdentity::new(
            package.clone(),
            Provenance::GitCommit {
                repository: NormalizedGitUrl::new("https://example.test/project").unwrap(),
                commit: GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
                subdirectory: None,
            },
        );
        let release = PackageRelease::try_from(ReleaseObservation {
            identity,
            observed_package: package.clone(),
            observed_version: version.clone(),
            metadata: ReleaseMetadata::from_pairs([("Title", "Example package")]).unwrap(),
            publication: None,
            declared_dependencies: Vec::new(),
            distributions,
        })
        .unwrap();
        let selected = ResolvedPackage::new(
            SolverKey::InstalledName(package.clone()),
            release,
            Vec::new(),
            visible_repository_ids,
        );
        let composed = crate::manifest::ComposedEnvironment {
            environment: EnvironmentId::new("default").unwrap(),
            r_requirement: VersionConstraint::unconstrained(),
            published_before: None,
            target: ResolutionTarget::new(rsolve_core::RPackageVersion::parse_bare("4.4").unwrap()),
            repositories: repositories.to_vec(),
            roots: Vec::new(),
            locked: rsolve_core::LockedIdentities::new(),
        };
        (selected, composed)
    }

    fn occurrence_distribution(
        repository: &crate::manifest::RepositorySpec,
        locator: &str,
        contents: &[u8],
    ) -> Distribution {
        Distribution {
            registry: repository.configured_registry_id().unwrap(),
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: None,
            artifacts: vec![Artifact::Source(SourceArtifact {
                locator: ArtifactLocator::new(locator).unwrap(),
                upstream_checksums: vec![rsolve_core::UpstreamChecksum::Sha256(
                    Sha256Digest::new(hex_lower(&sha2::Sha256::digest(contents))).unwrap(),
                )],
                size: Some(contents.len() as u64),
            })],
            observed_metadata: DistributionMetadata::default(),
        }
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn archive(package: &str, version: &str, remote: &str) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};
        use tar::{Builder, Header};
        let mut output = Vec::new();
        let encoder = GzEncoder::new(&mut output, Compression::default());
        let mut builder = Builder::new(encoder);
        let contents = format!(
            "Package: {package}\nVersion: {version}\nRemoteUrl: https://example.test/project\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\n{remote}"
        );
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "example/DESCRIPTION", contents.as_bytes())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();
        output
    }

    fn root() -> std::path::PathBuf {
        static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rsolve-artifact-test-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn online_stream_fetch_commits_and_preserves_locator_and_release_facts() {
        let locator = "https://download.example/custom/pkg.tar.gz";
        let bytes = archive("example", "1.0", "");
        let expected_size = bytes.len() as u64;
        let (selected_release, composed) = selected(locator, None);
        let fetcher = FixtureFetcher {
            status: 200,
            bytes,
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        let cache = root();
        let result = acquire_selected_artifact(
            &cache,
            &selected_release,
            &composed,
            ArtifactAcquisitionMode::Online,
            &fetcher,
        )
        .unwrap();
        assert_eq!(result.package().as_str(), "example");
        assert_eq!(result.artifact.sha256.as_str().len(), 64);
        assert_eq!(result.artifact.size, expected_size);
        assert_eq!(
            result.metadata.fields().get("Title"),
            Some(&"Example package".to_owned())
        );
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].package.name().as_str(), "dependency");
        assert_eq!(
            result
                .publication()
                .map(|publication| publication.date().to_string()),
            Some("2024-01-02".to_owned())
        );
        let cached = acquire_selected_artifact(
            &cache,
            &selected_release,
            &composed,
            ArtifactAcquisitionMode::Online,
            &fetcher,
        )
        .unwrap();
        assert_eq!(cached.artifact.sha256, result.artifact.sha256);
        assert_eq!(fetcher.calls.get(), 1);
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn equivalent_release_versions_reuse_r_universe_cache_entry() {
        let locator = "https://download.example/version-alias.tar.gz";
        let bytes = archive("example", "1.7-0", "");
        let (selected_release, composed) =
            selected_with_version_and_content(locator, None, true, bytes.clone(), true, "1.7.0");
        let (alias_release, alias_composed) =
            selected_with_version_and_content(locator, None, true, bytes.clone(), true, "1.7-0");
        let fetcher = FixtureFetcher {
            status: 200,
            bytes,
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        let cache = root();
        let committed = acquire_selected_artifact(
            &cache,
            &selected_release,
            &composed,
            ArtifactAcquisitionMode::Online,
            &fetcher,
        )
        .unwrap();
        let probed = acquire_selected_artifact(
            &cache,
            &alias_release,
            &alias_composed,
            ArtifactAcquisitionMode::Offline,
            &fetcher,
        )
        .unwrap();
        assert_eq!(probed.artifact.sha256, committed.artifact.sha256);
        assert_eq!(fetcher.calls.get(), 1);
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn semantically_different_release_version_is_rejected_before_publication() {
        let locator = "https://download.example/version-mismatch.tar.gz";
        let bytes = archive("example", "1.7.1", "");
        let (selected_release, composed) =
            selected_with_version_and_content(locator, None, true, bytes.clone(), true, "1.7.0");
        let fetcher = FixtureFetcher {
            status: 200,
            bytes,
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        let cache = root();
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected_release,
                &composed,
                ArtifactAcquisitionMode::Online,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::Cache(
                CacheError::DescriptionFieldMismatch {
                    field: "Version",
                    ..
                }
            ))
        ));
        assert_eq!(fetcher.calls.get(), 1);
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected_release,
                &composed,
                ArtifactAcquisitionMode::Offline,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::OfflineMiss { .. })
        ));
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn missing_source_artifact_is_typed_without_fetching() {
        let locator = "https://download.example/pkg.tar.gz";
        let bytes = archive("example", "1.0", "");
        let (selected, composed) = selected_with_content(locator, None, true, bytes, false);
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: Vec::new(),
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected,
                &composed,
                ArtifactAcquisitionMode::Online,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::NoRUniverseArtifact { .. })
        ));
        assert_eq!(fetcher.calls.get(), 0);
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn invalid_locator_is_rejected_before_fetch() {
        let locator = "fixture://download.example/pkg.tar.gz";
        let bytes = archive("example", "1.0", "");
        let (selected, composed) = selected_with_content(locator, None, true, bytes, true);
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: Vec::new(),
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected,
                &composed,
                ArtifactAcquisitionMode::Online,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::InvalidLocator { .. })
        ));
        assert_eq!(fetcher.calls.get(), 0);
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn invalid_description_identity_is_cache_error_without_cache_hit() {
        let locator = "https://download.example/pkg.tar.gz";
        let bytes = archive("other", "1.0", "");
        let (selected, composed) = selected_with_content(locator, None, true, bytes.clone(), true);
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes,
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected,
                &composed,
                ArtifactAcquisitionMode::Online,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::Cache(_))
        ));
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected,
                &composed,
                ArtifactAcquisitionMode::Offline,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::OfflineMiss { .. })
        ));
        assert_eq!(fetcher.calls.get(), 1);
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn offline_miss_and_http_transport_failures_are_typed_without_fetching_or_fallback() {
        let locator = "https://download.example/pkg.tar.gz";
        let (selected, composed) = selected(locator, None);
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: Vec::new(),
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected,
                &composed,
                ArtifactAcquisitionMode::Offline,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::OfflineMiss { .. })
        ));
        assert_eq!(fetcher.calls.get(), 0);
        let status_fetcher = FixtureFetcher {
            status: 404,
            bytes: Vec::new(),
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected,
                &composed,
                ArtifactAcquisitionMode::Online,
                &status_fetcher,
            ),
            Err(ArtifactAcquisitionError::HttpStatus { status: 404, .. })
        ));
        let transport_fetcher = FixtureFetcher {
            status: 200,
            bytes: Vec::new(),
            calls: Cell::new(0),
            locator: locator.into(),
            failure: Some("offline fixture".into()),
        };
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected,
                &composed,
                ArtifactAcquisitionMode::Online,
                &transport_fetcher,
            ),
            Err(ArtifactAcquisitionError::Fetch(_))
        ));
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn only_visible_r_universe_source_is_eligible_and_ambiguous_evidence_fails_closed() {
        let locator = "https://download.example/pkg.tar.gz";
        let (selected_release, composed) = selected(locator, None);
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: archive("example", "1.0", ""),
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        assert!(
            acquire_selected_artifact(
                &cache,
                &selected_release,
                &composed,
                ArtifactAcquisitionMode::Online,
                &fetcher,
            )
            .is_ok()
        );
        let repository = repository();
        let extra_registry = repository.configured_registry_id().unwrap();
        let extra = Distribution {
            registry: extra_registry,
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: None,
            artifacts: vec![Artifact::Source(SourceArtifact {
                locator: ArtifactLocator::new("https://download.example/other.tar.gz").unwrap(),
                upstream_checksums: Vec::new(),
                size: None,
            })],
            observed_metadata: DistributionMetadata::default(),
        };
        let (ambiguous, composed) = selected(locator, Some(extra));
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &ambiguous,
                &composed,
                ArtifactAcquisitionMode::Offline,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::AmbiguousArtifact { .. })
        ));
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn occurrence_artifact_selection_honors_priority_fallback_and_qualification() {
        let first_repo = repository_named("first", "https://custom.example/first/");
        let second_repo = repository_named("second", "https://custom.example/second/");
        let first_bytes = archive("example", "1.0", "Description: first\n");
        let second_bytes = archive("example", "1.0", "Description: second\n");
        let first_locator = "https://download.example/first.tar.gz";
        let second_locator = "https://download.example/second.tar.gz";
        let repositories = [first_repo.clone(), second_repo.clone()];
        let first_distribution = occurrence_distribution(&first_repo, first_locator, &first_bytes);
        let second_distribution =
            occurrence_distribution(&second_repo, second_locator, &second_bytes);

        let (selected, composed) = selected_with_repository_distributions(
            &repositories,
            vec![first_distribution.clone(), second_distribution.clone()],
            vec![first_repo.id().clone(), second_repo.id().clone()],
        );
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: first_bytes.clone(),
            calls: Cell::new(0),
            locator: first_locator.into(),
            failure: None,
        };
        let first_result = acquire_selected_artifact(
            &cache,
            &selected,
            &composed,
            ArtifactAcquisitionMode::Online,
            &fetcher,
        )
        .unwrap();
        assert_eq!(
            first_result.artifact.sha256.as_str(),
            hex_lower(&sha2::Sha256::digest(&first_bytes))
        );
        assert_eq!(fetcher.calls.get(), 1);
        std::fs::remove_dir_all(&cache).unwrap();

        let (selected, composed) = selected_with_repository_distributions(
            &repositories,
            vec![first_distribution.clone(), second_distribution.clone()],
            vec![second_repo.id().clone(), first_repo.id().clone()],
        );
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: second_bytes.clone(),
            calls: Cell::new(0),
            locator: second_locator.into(),
            failure: None,
        };
        let reversed = acquire_selected_artifact(
            &cache,
            &selected,
            &composed,
            ArtifactAcquisitionMode::Online,
            &fetcher,
        )
        .unwrap();
        assert_eq!(
            reversed.artifact.sha256.as_str(),
            hex_lower(&sha2::Sha256::digest(&second_bytes))
        );
        assert_eq!(fetcher.calls.get(), 1);
        std::fs::remove_dir_all(&cache).unwrap();

        let (selected, composed) = selected_with_repository_distributions(
            &repositories,
            vec![second_distribution.clone()],
            vec![first_repo.id().clone(), second_repo.id().clone()],
        );
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: second_bytes.clone(),
            calls: Cell::new(0),
            locator: second_locator.into(),
            failure: None,
        };
        let second_result = acquire_selected_artifact(
            &cache,
            &selected,
            &composed,
            ArtifactAcquisitionMode::Online,
            &fetcher,
        )
        .unwrap();
        assert_eq!(
            second_result.artifact.sha256.as_str(),
            hex_lower(&sha2::Sha256::digest(&second_bytes))
        );
        std::fs::remove_dir_all(&cache).unwrap();

        let (selected, composed) = selected_with_repository_distributions(
            &repositories,
            vec![first_distribution, second_distribution],
            vec![second_repo.id().clone()],
        );
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: second_bytes,
            calls: Cell::new(0),
            locator: second_locator.into(),
            failure: None,
        };
        let qualified = acquire_selected_artifact(
            &cache,
            &selected,
            &composed,
            ArtifactAcquisitionMode::Online,
            &fetcher,
        )
        .unwrap();
        assert_eq!(
            qualified.artifact.sha256.as_str(),
            hex_lower(&sha2::Sha256::digest(&fetcher.bytes))
        );
        assert_eq!(fetcher.calls.get(), 1);
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn occurrence_artifact_ambiguity_does_not_fall_back_to_lower_priority() {
        let first_repo = repository_named("first", "https://custom.example/first/");
        let second_repo = repository_named("second", "https://custom.example/second/");
        let first_bytes = archive("example", "1.0", "Description: first\n");
        let second_bytes = archive("example", "1.0", "Description: second\n");
        let first_distributions = vec![
            occurrence_distribution(
                &first_repo,
                "https://download.example/first-a.tar.gz",
                &first_bytes,
            ),
            occurrence_distribution(
                &first_repo,
                "https://download.example/first-b.tar.gz",
                &first_bytes,
            ),
        ];
        let second_distribution = occurrence_distribution(
            &second_repo,
            "https://download.example/second.tar.gz",
            &second_bytes,
        );
        let repositories = [first_repo, second_repo];
        let (selected, composed) = selected_with_repository_distributions(
            &repositories,
            first_distributions
                .into_iter()
                .chain([second_distribution])
                .collect(),
            vec![repositories[0].id().clone(), repositories[1].id().clone()],
        );
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: second_bytes,
            calls: Cell::new(0),
            locator: "https://download.example/second.tar.gz".into(),
            failure: None,
        };
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected,
                &composed,
                ArtifactAcquisitionMode::Online,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::AmbiguousArtifact { .. })
        ));
        assert_eq!(fetcher.calls.get(), 0);
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn ordinary_cran_release_is_not_downloaded_as_r_universe_artifact() {
        let locator = "https://download.example/pkg.tar.gz";
        let (selected, composed) = selected_with_identity(locator, None, false);
        let cache = root();
        let fetcher = FixtureFetcher {
            status: 200,
            bytes: archive("example", "1.0", ""),
            calls: Cell::new(0),
            locator: locator.into(),
            failure: None,
        };
        assert!(matches!(
            acquire_selected_artifact(
                &cache,
                &selected,
                &composed,
                ArtifactAcquisitionMode::Online,
                &fetcher,
            ),
            Err(ArtifactAcquisitionError::NotRUniverseRelease { .. })
        ));
        assert_eq!(fetcher.calls.get(), 0);
        std::fs::remove_dir_all(cache).unwrap();
    }
}
