use super::*;
use rsolve_core::{Artifact, PackageRelease, Provenance, UpstreamChecksum};

fn release_for<'a>(releases: &'a [PackageRelease], version: &str) -> &'a PackageRelease {
    releases
        .iter()
        .find(|release| release.version().as_str() == version)
        .unwrap_or_else(|| panic!("missing fixture release {version}"))
}

fn source_artifact(release: &PackageRelease) -> &rsolve_core::SourceArtifact {
    release
        .distributions()
        .iter()
        .flat_map(|distribution| distribution.artifacts.iter())
        .map(|artifact| match artifact {
            Artifact::Source(source) => source,
        })
        .next()
        .expect("published fixture release should have a source artifact")
}

#[test]
fn runtime_loader_caches_each_package_provider_and_its_candidates() {
    let transport = FixtureTransport::fallback(Vec::new(), 404);
    let requests = Rc::clone(&transport.requests);
    let loader = runtime_loader(transport);
    let package = SolverKey::InstalledName(PackageName::new("Matrix").unwrap());

    assert_eq!(loader.releases(&package).unwrap().len(), 2);
    assert!(matches!(
        loader.diagnostics()[0].status_detail(),
        CranFastPathStatus::Unsupported { status: 404 }
    ));
    assert_eq!(requests.borrow().len(), 4);
    assert_eq!(requests.borrow()[0], fast_url());
    assert_eq!(requests.borrow()[1], history_url());
    assert_eq!(requests.borrow()[2], old_url());
    assert_eq!(requests.borrow()[3], new_url());

    assert_eq!(loader.releases(&package).unwrap().len(), 2);
    assert_eq!(requests.borrow().len(), 4);
}

#[test]
fn runtime_loader_invalid_fast_path_falls_back_to_history() {
    let transport = FixtureTransport::fallback(WRONG_ROOT.to_vec(), 200);
    let requests = Rc::clone(&transport.requests);
    let loader = runtime_loader(transport);
    let package = SolverKey::InstalledName(PackageName::new("Matrix").unwrap());

    assert_eq!(loader.releases(&package).unwrap().len(), 2);
    assert!(matches!(
        loader.diagnostics()[0].status_detail(),
        CranFastPathStatus::Invalid { status: 200, .. }
    ));
    assert_eq!(requests.borrow().len(), 4);
    assert_eq!(requests.borrow()[0], fast_url());
    assert_eq!(requests.borrow()[1], history_url());
}

#[test]
fn runtime_loader_preserves_quarantined_archive_history_versions() {
    let mut transport = FixtureTransport::fallback(Vec::new(), 404);
    transport.responses.insert(
        history_url(),
        TransportResponse {
            status: 200,
            body: FOREIGN_NESTED_HISTORY.to_vec(),
            ..TransportResponse::default()
        },
    );
    transport.responses.insert(
        "https://cran.invalid/src/contrib/Archive/calibFit/PACKAGES.rds".to_owned(),
        TransportResponse::new(404, Vec::new()),
    );
    let loader = CranRuntimeLoader::new(transport, "https://cran.invalid");
    let package = PackageName::new("calibFit").unwrap();
    let result = loader
        .load(&SolverKey::InstalledName(package))
        .expect("quarantined history remains loadable");
    assert!(result.candidates().is_empty());
    assert_eq!(result.quarantined().len(), 1);
    assert_eq!(result.quarantined()[0].version().as_str(), "0.1.02");
    assert!(
        result.quarantined()[0]
            .diagnostic()
            .contains("calibFit/Ancestry")
    );
}

#[test]
fn persisted_snapshot_replays_quarantined_xml_candidates_offline() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let package = PackageName::new("XML").unwrap();
    let mut transport = session_transport(
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(
            200,
            b"Package: XML\nVersion: 3.99-0.19\nDepends: R (>= 3.6.0)\nLicense: RSOLVE Fictional Terms XML\nMD5sum: 00000000000000000000000000000043\nNeedsCompilation: yes\n".to_vec(),
        ),
    );
    transport.responses.insert(
        fast_url_for("XML"),
        TransportResponse::new(200, XML_QUARANTINED_ARCHIVE.to_vec()),
    );
    let online = crate::cran::provider::refresh_and_publish_with_transport(
        &store,
        transport,
        "https://cran.invalid",
        std::slice::from_ref(&package),
    )
    .expect("online fixture refresh must publish");
    let online_result = online
        .load(&SolverKey::InstalledName(package.clone()))
        .expect("online snapshot must load XML");
    let offline = store
        .read_latest_view()
        .expect("published snapshot must be readable offline");
    let offline_result = offline
        .load(&SolverKey::InstalledName(package))
        .expect("offline snapshot must load XML");
    assert_eq!(
        online_result
            .candidates()
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>(),
        vec!["3.99-0.19"]
    );
    assert_eq!(
        online_result
            .quarantined()
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>(),
        vec!["0.2", "0.3-3"]
    );
    assert_eq!(
        offline_result
            .candidates()
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>(),
        online_result
            .candidates()
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        offline_result
            .quarantined()
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>(),
        online_result
            .quarantined()
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn refresh_session_falls_back_to_plain_current_and_freezes_without_network() {
    let current = b"Package: Matrix\nVersion: 1.8-0\nLicense: RSOLVE Fictional Current\n";
    let transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: current.to_vec(),
            ..TransportResponse::default()
        },
    );
    let requests = Rc::clone(&transport.requests);
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    let before = requests.borrow().len();
    let releases = snapshot
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    assert_eq!(releases.len(), 3);
    assert_eq!(requests.borrow().len(), before);
    assert_eq!(requests.borrow()[0], current_gzip_url());
    assert_eq!(requests.borrow()[1], current_rds_url());
    assert_eq!(requests.borrow()[2], current_plain_url());
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|url| *url == &history_url())
            .count(),
        1
    );
    assert!(
        !requests
            .borrow()
            .iter()
            .any(|url| url.url.contains("/Archive/methods/PACKAGES.rds"))
    );
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source()
            == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::PlainDcf)
    }));
}

#[test]
fn runtime_loader_size_mismatch_is_a_hard_acquisition_error() {
    let mut transport = FixtureTransport::fallback(Vec::new(), 404);
    transport.responses.get_mut(&old_url()).unwrap().body.pop();
    let loader = runtime_loader(transport);
    let error = loader
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::TransportFailure
    );
    assert!(error.diagnostic().contains("size mismatch"));
}

#[test]
fn production_refresh_publishes_fixture_evidence_and_preserves_old_generation_on_failure() {
    let current = b"Package: Matrix\nVersion: 1.8-0\nLicense: RSOLVE Fictional Current\n";
    let transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: current.to_vec(),
            ..TransportResponse::default()
        },
    );
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let loader = crate::cran::provider::refresh_and_publish_with_transport(
        &store,
        transport,
        "https://cran.invalid",
        &[PackageName::new("Matrix").unwrap()],
    )
    .expect("fixture acquisition should publish a snapshot");
    let releases = loader
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    let old = source_artifact(release_for(&releases, "1.6-5"));
    assert_eq!(
        old.locator.as_str(),
        "https://cran.invalid/src/contrib/Archive/Matrix/Matrix_1.6-5.tar.gz"
    );
    assert_eq!(old.size, Some(OLD_TAR.len() as u64));
    assert!(old.upstream_checksums.is_empty());
    assert!(
        !loader
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap()
            ))
            .unwrap()
            .is_empty()
    );
    let generation = loader.header().generation.clone();

    let failed = FixtureTransport {
        responses: HashMap::new(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let result = crate::cran::provider::refresh_and_publish_with_transport(
        &store,
        failed,
        "https://cran.invalid",
        &[PackageName::new("Matrix").unwrap()],
    );
    assert!(matches!(
        result,
        Err(crate::cran::CranSnapshotPublishError::Acquisition(_))
    ));
    assert_eq!(
        store.read_latest_view().unwrap().header().generation,
        generation
    );
}

#[test]
fn production_refresh_publishes_current_and_archive_index_evidence() {
    let current = b"Package: Matrix\nVersion: 1.8-0\nLicense: RSOLVE Fictional Current\n";
    let mut transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: current.to_vec(),
            ..TransportResponse::default()
        },
    );
    transport.responses.insert(
        fast_url(),
        TransportResponse {
            status: 200,
            body: FAST.to_vec(),
            ..TransportResponse::default()
        },
    );
    let requests = Rc::clone(&transport.requests);
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let loader = crate::cran::provider::refresh_and_publish_with_transport(
        &store,
        transport,
        "https://cran.invalid",
        &[PackageName::new("Matrix").unwrap()],
    )
    .expect("current and archive-index fixtures should publish");
    let releases = loader
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    let current = source_artifact(release_for(&releases, "1.8-0"));
    assert_eq!(
        current.locator.as_str(),
        "https://cran.invalid/src/contrib/Matrix_1.8-0.tar.gz"
    );
    assert_eq!(current.size, None);
    assert!(current.upstream_checksums.is_empty());
    for (version, checksum) in [
        ("1.6-5", "00000000000000000000000000000021"),
        ("1.7-0", "00000000000000000000000000000022"),
    ] {
        let artifact = source_artifact(release_for(&releases, version));
        assert_eq!(
            artifact.locator.as_str(),
            format!("https://cran.invalid/src/contrib/Archive/Matrix/Matrix_{version}.tar.gz")
        );
        assert_eq!(artifact.size, None);
        assert_eq!(
            artifact.upstream_checksums,
            vec![UpstreamChecksum::Md5(checksum.into())]
        );
    }
    assert!(
        loader
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap()
            ))
            .unwrap()
            .len()
            >= 2
    );
    assert!(
        requests
            .borrow()
            .iter()
            .any(|request| request == &current_plain_url())
    );
    assert!(
        requests
            .borrow()
            .iter()
            .any(|request| request == &fast_url())
    );
    assert!(!requests.borrow().iter().any(|url| url == &history_url()));
    assert!(!requests.borrow().iter().any(|url| url == &old_url()));
}

#[test]
fn production_refresh_propagates_configured_registry_id_to_header_and_loader() {
    let transport = session_transport(
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
        TransportResponse {
            status: 200,
            body: b"Package: Matrix\nVersion: 1.8-0\n".to_vec(),
            ..TransportResponse::default()
        },
    );
    let directory = tempfile::tempdir().unwrap();
    let registry = rsolve_core::RegistryId::new("configured-cran-mirror").unwrap();
    let store = crate::snapshot::SnapshotStore::open(directory.path(), registry.clone()).unwrap();
    let loader = crate::cran::provider::refresh_and_publish_with_transport(
        &store,
        transport,
        "https://cran.invalid",
        &[PackageName::new("Matrix").unwrap()],
    )
    .expect("configured registry publication should succeed");
    assert_eq!(loader.header().registry_id, registry.as_str());
    assert_eq!(
        store.read_latest_view().unwrap().header().registry_id,
        registry.as_str()
    );
    let releases = loader
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    assert!(!releases.is_empty());
    for release in releases {
        match release.identity().provenance() {
            Provenance::RegistryRelease { namespace, .. } => {
                assert_eq!(namespace.as_str(), "cran")
            }
            provenance => panic!("unexpected CRAN identity provenance: {provenance:?}"),
        }
        assert!(!release.distributions().is_empty());
        assert!(
            release
                .distributions()
                .iter()
                .all(|distribution| distribution.registry.as_str() == registry.as_str())
        );
    }
}
