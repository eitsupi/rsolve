use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;

use flate2::{Compression, write::GzEncoder};
use rsolve::manifest::{ComposedEnvironment, Endpoint, RegistrySpec, RepositorySpec};
use rsolve::{
    ArtifactAcquisitionError, ArtifactAcquisitionMode, ArtifactFetchError, ArtifactFetchResponse,
    ArtifactFetcher, RepositoryPreparationError, prepare_r_universe_project_repository,
    prepare_r_universe_project_repository_with_fetcher,
};
use rsolve_core::{
    Artifact, Distribution, DistributionChannel, DistributionMetadata, EnvironmentId, GitCommitId,
    LockedIdentities, NormalizedGitUrl, PackageName, PackageRelease, Provenance, RPackageVersion,
    ReleaseAggregation, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, RepositoryId,
    Resolution, ResolutionTarget, Sha256Digest, SolverKey, SourceArtifact, VersionConstraint,
};
use sha2::{Digest, Sha256};
use tar::{Builder, Header};

struct FixtureFetcher {
    archives: BTreeMap<String, Vec<u8>>,
    calls: Cell<usize>,
}

impl ArtifactFetcher for FixtureFetcher {
    fn fetch(&self, locator: &str) -> Result<ArtifactFetchResponse, ArtifactFetchError> {
        self.calls.set(self.calls.get() + 1);
        let Some(bytes) = self.archives.get(locator) else {
            return Err(ArtifactFetchError::Transport {
                locator: locator.to_owned(),
                reason: "fixture archive is missing".to_owned(),
            });
        };
        Ok(ArtifactFetchResponse {
            status: 200,
            reader: Box::new(Cursor::new(bytes.clone())),
        })
    }
}

fn repository() -> RepositorySpec {
    RepositorySpec::new(
        RepositoryId::new("universe").unwrap(),
        RegistrySpec::RUniverse,
        Endpoint::new("https://universe.example/").unwrap(),
    )
    .unwrap()
}

fn composed(repository: &RepositorySpec) -> ComposedEnvironment {
    composed_repositories(std::slice::from_ref(repository))
}

fn composed_repositories(repositories: &[RepositorySpec]) -> ComposedEnvironment {
    ComposedEnvironment {
        environment: EnvironmentId::new("default").unwrap(),
        r_requirement: VersionConstraint::unconstrained(),
        published_before: None,
        target: ResolutionTarget::new(RPackageVersion::parse_bare("4.4").unwrap()),
        repositories: repositories.to_vec(),
        roots: Vec::new(),
        locked: LockedIdentities::new(),
    }
}

fn archive(package: &str, version: &str) -> Vec<u8> {
    archive_with_description(package, version, "fixture")
}

fn archive_with_description(package: &str, version: &str, description: &str) -> Vec<u8> {
    archive_with_description_and_remote(
        package,
        version,
        description,
        &format!("https://example.test/{package}"),
    )
}

fn archive_with_description_and_remote(
    package: &str,
    version: &str,
    description: &str,
    remote_url: &str,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    let encoder = GzEncoder::new(&mut encoded, Compression::default());
    let mut builder = Builder::new(encoder);
    let contents = format!(
        "Package: {package}\nVersion: {version}\nDescription: {description}\nRemoteUrl: {remote_url}\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\n"
    );
    let mut header = Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(
            &mut header,
            format!("{package}/DESCRIPTION"),
            contents.as_bytes(),
        )
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap();
    encoded
}

fn release_for_occurrence(
    repository: &RepositorySpec,
    package: &str,
    locator: &str,
    bytes: &[u8],
    repository_metadata: &str,
) -> PackageRelease {
    let package_name = PackageName::new(package).unwrap();
    let version = RPackageVersion::parse("1.0.0").unwrap();
    let source = SourceArtifact {
        locator: rsolve_core::ArtifactLocator::new(locator).unwrap(),
        upstream_checksums: vec![rsolve_core::UpstreamChecksum::Sha256(
            Sha256Digest::new(hex(&Sha256::digest(bytes))).unwrap(),
        )],
        size: Some(bytes.len() as u64),
    };
    PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            package_name.clone(),
            Provenance::GitCommit {
                repository: NormalizedGitUrl::new("https://example.test/shared").unwrap(),
                commit: GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
                subdirectory: None,
            },
        ),
        observed_package: package_name,
        observed_version: version,
        metadata: ReleaseMetadata::from_pairs([("Title", "shared fixture")]).unwrap(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: vec![Distribution {
            registry: repository.configured_registry_id().unwrap(),
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: None,
            artifacts: vec![Artifact::Source(source)],
            observed_metadata: DistributionMetadata {
                fields: [("Repository".into(), repository_metadata.into())].into(),
            },
        }],
    })
    .unwrap()
}

fn selected(
    repository: &RepositorySpec,
    package: &str,
    locator: &str,
    bytes: &[u8],
) -> rsolve_core::ResolvedPackage {
    selected_with_source(repository, package, locator, bytes, true)
}

fn selected_without_source(
    repository: &RepositorySpec,
    package: &str,
    locator: &str,
    bytes: &[u8],
) -> rsolve_core::ResolvedPackage {
    selected_with_source(repository, package, locator, bytes, false)
}

fn selected_with_source(
    repository: &RepositorySpec,
    package: &str,
    locator: &str,
    bytes: &[u8],
    include_source: bool,
) -> rsolve_core::ResolvedPackage {
    let package_name = PackageName::new(package).unwrap();
    let version = RPackageVersion::parse("1.0.0").unwrap();
    let identity = ReleaseIdentity::new(
        package_name.clone(),
        Provenance::GitCommit {
            repository: NormalizedGitUrl::new(format!("https://example.test/{package}")).unwrap(),
            commit: GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
            subdirectory: None,
        },
    );
    let registry = repository.configured_registry_id().unwrap();
    let source = SourceArtifact {
        locator: rsolve_core::ArtifactLocator::new(locator).unwrap(),
        upstream_checksums: vec![rsolve_core::UpstreamChecksum::Sha256(
            Sha256Digest::new(hex(&Sha256::digest(bytes))).unwrap(),
        )],
        size: Some(bytes.len() as u64),
    };
    let release = PackageRelease::try_from(ReleaseObservation {
        identity,
        observed_package: package_name.clone(),
        observed_version: version,
        metadata: ReleaseMetadata::from_pairs([("Title", format!("{package} fixture"))]).unwrap(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: if include_source {
            vec![Distribution {
                registry,
                channel: DistributionChannel::new("source").unwrap(),
                snapshot: None,
                artifacts: vec![Artifact::Source(source)],
                observed_metadata: DistributionMetadata::default(),
            }]
        } else {
            Vec::new()
        },
    })
    .unwrap();
    rsolve_core::ResolvedPackage::new(
        SolverKey::InstalledName(package_name),
        release,
        Vec::new(),
        vec![repository.id().clone()],
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn prepares_nested_project_repository_and_reuses_online_artifacts_offline() {
    let repository = repository();
    let first_bytes = archive("alpha", "1.0.0");
    let second_bytes = archive("beta", "1.0.0");
    let first_locator = "https://download.example/alpha.tar.gz";
    let second_locator = "https://download.example/beta.tar.gz";
    let resolution = Resolution::new(
        ResolutionTarget::new(RPackageVersion::parse_bare("4.4").unwrap()),
        vec![
            selected(&repository, "alpha", first_locator, &first_bytes),
            selected(&repository, "beta", second_locator, &second_bytes),
        ],
    );
    let fetcher = FixtureFetcher {
        archives: BTreeMap::from([
            (first_locator.to_owned(), first_bytes),
            (second_locator.to_owned(), second_bytes),
        ]),
        calls: Cell::new(0),
    };
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("nested/project");
    let cache = root.path().join("cache");
    let composed = composed(&repository);

    let state = prepare_r_universe_project_repository_with_fetcher(
        &project,
        &cache,
        &resolution,
        &composed,
        ArtifactAcquisitionMode::Online,
        &fetcher,
    )
    .unwrap();
    assert_eq!(state.records().len(), 2);
    assert_eq!(fetcher.calls.get(), 2);
    let packages = project.join(".rsolve/repository/src/contrib/PACKAGES");
    let packages = fs::read_to_string(packages).unwrap();
    assert!(packages.contains("Package: alpha"));
    assert!(packages.contains("Package: beta"));
    assert!(packages.contains("Title: alpha fixture"));

    let offline_project = root.path().join("nested/offline-project");
    prepare_r_universe_project_repository(
        &offline_project,
        &cache,
        &resolution,
        &composed,
        ArtifactAcquisitionMode::Offline,
    )
    .unwrap();
    assert_eq!(fetcher.calls.get(), 2);
    assert!(
        offline_project
            .join(".rsolve/repository/src/contrib/PACKAGES")
            .exists()
    );
}

#[test]
fn acquisition_failure_keeps_package_context_and_does_not_materialize_partial_results() {
    let repository = repository();
    let bytes = archive("alpha", "1.0.0");
    let selected = selected(
        &repository,
        "alpha",
        "https://download.example/alpha.tar.gz",
        &bytes,
    );
    let resolution = Resolution::new(
        ResolutionTarget::new(RPackageVersion::parse_bare("4.4").unwrap()),
        vec![selected],
    );
    let fetcher = FixtureFetcher {
        archives: BTreeMap::new(),
        calls: Cell::new(0),
    };
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let composed = composed(&repository);
    let error = prepare_r_universe_project_repository_with_fetcher(
        &project,
        root.path().join("cache"),
        &resolution,
        &composed,
        ArtifactAcquisitionMode::Online,
        &fetcher,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RepositoryPreparationError::Acquisition { package, .. } if package == "alpha"
    ));
    assert!(!project.join(".rsolve/repository").exists());
}

#[test]
fn selected_package_without_r_universe_artifact_is_not_silently_omitted() {
    let repository = repository();
    let valid_bytes = archive("alpha", "1.0.0");
    let missing_bytes = archive("zeta", "1.0.0");
    let valid_locator = "https://download.example/alpha.tar.gz";
    let missing_locator = "https://download.example/zeta.tar.gz";
    let resolution = Resolution::new(
        ResolutionTarget::new(RPackageVersion::parse_bare("4.4").unwrap()),
        vec![
            selected(&repository, "alpha", valid_locator, &valid_bytes),
            selected_without_source(&repository, "zeta", missing_locator, &missing_bytes),
        ],
    );
    let fetcher = FixtureFetcher {
        archives: BTreeMap::from([(valid_locator.to_owned(), valid_bytes)]),
        calls: Cell::new(0),
    };
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let error = prepare_r_universe_project_repository_with_fetcher(
        &project,
        root.path().join("cache"),
        &resolution,
        &composed(&repository),
        ArtifactAcquisitionMode::Online,
        &fetcher,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RepositoryPreparationError::Acquisition {
            package,
            source: ArtifactAcquisitionError::NoRUniverseArtifact { .. },
        } if package == "zeta"
    ));
    assert_eq!(fetcher.calls.get(), 1);
    assert!(!project.join(".rsolve/repository").exists());
}

#[test]
fn materialization_failure_is_typed_after_successful_acquisition() {
    let repository = repository();
    let bytes = archive("alpha", "1.0.0");
    let locator = "https://download.example/alpha.tar.gz";
    let resolution = Resolution::new(
        ResolutionTarget::new(RPackageVersion::parse_bare("4.4").unwrap()),
        vec![selected(&repository, "alpha", locator, &bytes)],
    );
    let fetcher = FixtureFetcher {
        archives: BTreeMap::from([(locator.to_owned(), bytes)]),
        calls: Cell::new(0),
    };
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let repository_path = project.join(".rsolve/repository");
    fs::create_dir_all(&repository_path).unwrap();
    let sentinel = repository_path.join("sentinel");
    fs::write(&sentinel, "keep existing repository").unwrap();
    let error = prepare_r_universe_project_repository_with_fetcher(
        &project,
        root.path().join("cache"),
        &resolution,
        &composed(&repository),
        ArtifactAcquisitionMode::Online,
        &fetcher,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RepositoryPreparationError::Materialization {
            source: rsolve_repository::MaterializationError::ExistingConflict { .. },
        }
    ));
    assert_eq!(fetcher.calls.get(), 1);
    assert_eq!(
        fs::read_to_string(sentinel).unwrap(),
        "keep existing repository"
    );
}

#[test]
fn materializes_first_priority_artifact_from_merged_r_universe_occurrences() {
    let first = RepositorySpec::new(
        RepositoryId::new("first").unwrap(),
        RegistrySpec::RUniverse,
        Endpoint::new("https://universe.example/first/").unwrap(),
    )
    .unwrap();
    let second = RepositorySpec::new(
        RepositoryId::new("second").unwrap(),
        RegistrySpec::RUniverse,
        Endpoint::new("https://universe.example/second/").unwrap(),
    )
    .unwrap();
    let first_bytes = archive_with_description_and_remote(
        "alpha",
        "1.0.0",
        "first",
        "https://example.test/shared",
    );
    let second_bytes = archive_with_description_and_remote(
        "alpha",
        "1.0.0",
        "second and longer",
        "https://example.test/shared",
    );
    let first_locator = "https://download.example/alpha-first.tar.gz";
    let second_locator = "https://download.example/alpha-second.tar.gz";
    assert_ne!(first_bytes.len(), second_bytes.len());
    let first_release = release_for_occurrence(
        &first,
        "alpha",
        first_locator,
        &first_bytes,
        "https://universe.example/first",
    );
    let second_release = release_for_occurrence(
        &second,
        "alpha",
        second_locator,
        &second_bytes,
        "https://universe.example/second",
    );
    let mut aggregation = ReleaseAggregation::new();
    aggregation.observe_release(first_release).unwrap();
    aggregation.observe_release(second_release).unwrap();
    let merged = aggregation.releases().next().unwrap().clone();
    assert_eq!(merged.distributions().len(), 2);
    assert_eq!(merged.metadata().fields().len(), 1);

    let selected = rsolve_core::ResolvedPackage::new(
        SolverKey::InstalledName(PackageName::new("alpha").unwrap()),
        merged,
        Vec::new(),
        vec![first.id().clone(), second.id().clone()],
    );
    let resolution = Resolution::new(
        ResolutionTarget::new(RPackageVersion::parse_bare("4.4").unwrap()),
        vec![selected],
    );
    let fetcher = FixtureFetcher {
        archives: BTreeMap::from([(first_locator.to_owned(), first_bytes.clone())]),
        calls: Cell::new(0),
    };
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let state = prepare_r_universe_project_repository_with_fetcher(
        &project,
        root.path().join("cache"),
        &resolution,
        &composed_repositories(&[first, second]),
        ArtifactAcquisitionMode::Online,
        &fetcher,
    )
    .unwrap();
    let first_sha = hex(&Sha256::digest(&first_bytes));
    assert_eq!(fetcher.calls.get(), 1);
    assert_eq!(state.records().len(), 1);
    assert_eq!(state.records()[0].artifact_sha256, first_sha);
    assert_eq!(state.records()[0].size, first_bytes.len() as u64);
    let packages =
        fs::read_to_string(project.join(".rsolve/repository/src/contrib/PACKAGES")).unwrap();
    assert!(packages.contains("Package: alpha"));
}
