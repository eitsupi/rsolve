use super::*;
use crate::cran::provider::raw_cache::{RawCacheLookup, RawCacheRepresentation, RawCacheWrite};
use flate2::{Compression, write::GzEncoder};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

#[derive(Clone)]
struct FileCountingTransport {
    inner: FixtureTransport,
    counter: PathBuf,
}

impl FileCountingTransport {
    fn count(&self) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.counter)
            .unwrap();
        writeln!(file, "request").unwrap();
    }
}

impl Transport for FileCountingTransport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        self.get_with_validators(url, &TransportValidators::default())
    }

    fn get_with_validators(
        &self,
        url: &str,
        validators: &TransportValidators,
    ) -> Result<TransportResponse, TransportError> {
        self.count();
        self.inner.get_with_validators(url, validators)
    }
}

fn wait_for_child_file(path: &Path) {
    for _ in 0..500 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("child did not create {} within timeout", path.display());
}

fn wait_for_child(mut child: Child) -> std::process::ExitStatus {
    for _ in 0..500 {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    panic!("child did not finish within timeout");
}

fn spawn_persistent_child(root: &Path, mode: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("cran::provider::tests::current::persistent_refresh_child_probe")
        .arg("--nocapture")
        .env("RSOLVE_PERSISTENT_CHILD_ROOT", root)
        .env("RSOLVE_PERSISTENT_CHILD_MODE", mode)
        .spawn()
        .unwrap()
}

fn seed_previous_projection(root: &Path) -> PathBuf {
    let store =
        crate::snapshot::SnapshotStore::open(root, rsolve_core::RegistryId::new("cran").unwrap())
            .unwrap();
    let feed = "https://feed.invalid/ALLPACKAGES.zst";
    let raw_cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = raw_cache
        .key(feed, RawCacheRepresentation::AllPackagesZstd)
        .unwrap();
    let digest = "0".repeat(64);
    let previous = raw_cache
        .projection_path_for_hex_digest(&key, &digest)
        .unwrap();
    std::fs::write(&previous, b"previous").unwrap();
    std::fs::write(
        root.join("raw-cache/v1/projections/newer-orphan.redb"),
        b"orphan",
    )
    .unwrap();
    let record = crate::cran::provider::qualification::Record {
        status: crate::cran::provider::qualification::Status::Positive,
        repository_endpoint: "https://cloud.r-project.org".into(),
        feed_endpoint: feed.into(),
        feed_digest: digest,
        ..Default::default()
    };
    crate::cran::provider::qualification::publish(&raw_cache.qualification_path(), &record)
        .unwrap();
    previous
}

fn append_counter(root: &Path, name: &str) {
    let path = root.join(name);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(file, "event").unwrap();
}

fn projection_files(root: &Path) -> Vec<PathBuf> {
    let directory = root.join("raw-cache/v1/projections");
    std::fs::read_dir(directory)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("redb"))
        .collect()
}

#[test]
fn persistent_refresh_child_probe() {
    let Ok(root) = std::env::var("RSOLVE_PERSISTENT_CHILD_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let mode = std::env::var("RSOLVE_PERSISTENT_CHILD_MODE").unwrap();
    let owner = mode.ends_with("owner");
    let forced = mode.starts_with("forced");
    let failure = mode == "failure-owner";
    let store =
        crate::snapshot::SnapshotStore::open(&root, rsolve_core::RegistryId::new("cran").unwrap())
            .unwrap();
    let feed = "https://feed.invalid/ALLPACKAGES.zst";
    let now = "2026-08-25T00:00:00Z".parse().unwrap();
    let pre_wait = crate::cran::provider::refresher::observe_persistent_refresh_probe(&store);
    std::fs::write(
        root.join(if forced {
            if owner {
                "forced-owner-probed"
            } else {
                "forced-waiter-probed"
            }
        } else if owner {
            "normal-owner-probed"
        } else {
            "normal-waiter-probed"
        }),
        b"ready",
    )
    .unwrap();
    if !mode.starts_with("failure") {
        wait_for_child_file(&root.join(if forced {
            if owner {
                "forced-owner-start"
            } else {
                "forced-waiter-start"
            }
        } else if owner {
            "normal-owner-start"
        } else {
            "normal-waiter-start"
        }));
    }

    if !owner {
        std::fs::write(
            root.join(format!(
                "{}-waiter-attempting-lock",
                mode.split('-').next().unwrap()
            )),
            b"waiting",
        )
        .unwrap();
    }
    let guard = store.begin_refresh().unwrap();
    if owner {
        std::fs::write(
            root.join(if failure {
                "failure-owner-locked"
            } else {
                "persistent-owner-locked"
            }),
            b"ready",
        )
        .unwrap();
        wait_for_child_file(&root.join(format!(
            "{}-waiter-attempting-lock",
            mode.split('-').next().unwrap()
        )));
        if failure {
            panic!("intentional acquisition failure after lock ownership");
        }
    }

    let capture_cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let capture_session = CranRefreshSession::new_with_clock(
        Rc::new(FixtureTransport {
            responses: HashMap::new(),
            requests: Rc::new(RefCell::new(Vec::new())),
        }),
        CranMetadataConfig::new("https://cloud.r-project.org", feed),
        Some(now),
        Some(capture_cache),
    );
    let captured_previous = capture_session.previous_allpackages_projection_path();
    drop(capture_session);

    let mut locked_policy = CranSnapshotCachePolicy::at(now)
        .with_expected_endpoint("https://cloud.r-project.org")
        .with_allowed_auxiliary_endpoint(feed);
    locked_policy.refresh_metadata = false;
    let locked_result = crate::cran::provider::inspect_cran_snapshot_cache_with_refresh_guard(
        &guard,
        &locked_policy,
    );
    let locked_revision = match &locked_result {
        CranSnapshotCacheResult::Compatible { diagnostic, .. }
        | CranSnapshotCacheResult::Rejected(diagnostic) => diagnostic
            .revision_token()
            .map(ToOwned::to_owned)
            .map(String::into_boxed_str),
    };
    let locked_compatible = matches!(&locked_result, CranSnapshotCacheResult::Compatible { .. });
    let satisfied = if forced {
        crate::cran::provider::refresher::refresh_completed_after_wait(
            &pre_wait,
            locked_revision.as_deref(),
        )
    } else {
        locked_compatible
    };
    if satisfied {
        let CranSnapshotCacheResult::Compatible { loader, .. } = &locked_result else {
            panic!("waiter must reopen the published current snapshot");
        };
        assert!(!loader.header().generation.is_empty());
    }
    if !satisfied {
        let raw_cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
        let projection_directory = root.join("raw-cache/v1/projections");
        let previous = captured_previous.expect("positive qualification must bind previous");
        let orphan = projection_directory.join("newer-orphan.redb");
        let generated_before = projection_files(&root)
            .into_iter()
            .filter(|path| path != &previous && path != &orphan)
            .count();
        let transport = FileCountingTransport {
            inner: super::archive_cache::allpackages_transport(
                super::archive_cache::allpackages_fixture_body(
                    &super::archive_cache::matrix_history_entries(),
                    true,
                    None,
                ),
                false,
            ),
            counter: root.join("persistent-request-count"),
        };
        let mut config = CranMetadataConfig::new("https://cloud.r-project.org", feed);
        config.refresh_metadata = forced;
        let mut session = CranRefreshSession::new_with_clock(
            Rc::new(transport),
            config,
            Some(now),
            Some(raw_cache),
        );
        let observations = session
            .refresh_snapshot_observations(&[PackageName::new("Matrix").unwrap()])
            .unwrap();
        drop(session);
        let mut context = crate::cran::publish::default_context(store.registry_id().clone());
        context.created_at = "2026-08-25T00:00:00Z".into();
        crate::cran::publish::publish_snapshot_with_endpoint_and_refresh_guard(
            &guard,
            context,
            observations,
            "https://cloud.r-project.org",
        )
        .unwrap();
        let generated_after = projection_files(&root)
            .into_iter()
            .filter(|path| path != &previous && path != &orphan)
            .count();
        if generated_before == 0 && generated_after > 0 {
            append_counter(&root, "persistent-refresh-count");
            append_counter(&root, "persistent-projection-build-count");
        }
        let active = projection_files(&root)
            .into_iter()
            .find(|path| path != &previous && path != &orphan)
            .unwrap();
        crate::cran::provider::raw_cache::RawCache::open(&store)
            .unwrap()
            .retain_projections(&active, Some(&previous))
            .unwrap();
    }
}

#[test]
fn persistent_refresh_child_processes_coalesce_normal_refresh() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let previous = seed_previous_projection(root);
    let owner = spawn_persistent_child(root, "normal-owner");
    wait_for_child_file(&root.join("normal-owner-probed"));
    std::fs::write(root.join("normal-owner-start"), b"go").unwrap();
    wait_for_child_file(&root.join("persistent-owner-locked"));
    let waiter = spawn_persistent_child(root, "normal-waiter");
    wait_for_child_file(&root.join("normal-waiter-probed"));
    std::fs::write(root.join("normal-waiter-start"), b"go").unwrap();
    wait_for_child_file(&root.join("normal-waiter-attempting-lock"));
    assert!(wait_for_child(owner).success());
    assert!(previous.exists());
    assert_eq!(projection_files(root).len(), 2);
    assert!(wait_for_child(waiter).success());
    assert_eq!(
        std::fs::read_to_string(root.join("persistent-request-count"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    assert_eq!(
        std::fs::read_to_string(root.join("persistent-refresh-count"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(root.join("persistent-projection-build-count"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert!(
        !root
            .join("raw-cache/v1/projections/newer-orphan.redb")
            .exists()
    );
    let validation: crate::snapshot::CurrentValidationV2 =
        serde_json::from_slice(&std::fs::read(root.join("current-validation")).unwrap()).unwrap();
    assert_eq!(validation.refresh_sequence, 1);
}

#[test]
fn persistent_refresh_child_processes_coalesce_forced_refresh_and_retry_after_panic() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let previous = seed_previous_projection(root);
    let owner = spawn_persistent_child(root, "forced-owner");
    wait_for_child_file(&root.join("forced-owner-probed"));
    std::fs::write(root.join("forced-owner-start"), b"go").unwrap();
    wait_for_child_file(&root.join("persistent-owner-locked"));
    let waiter = spawn_persistent_child(root, "forced-waiter");
    wait_for_child_file(&root.join("forced-waiter-probed"));
    std::fs::write(root.join("forced-waiter-start"), b"go").unwrap();
    wait_for_child_file(&root.join("forced-waiter-attempting-lock"));
    assert!(wait_for_child(owner).success());
    assert!(previous.exists());
    assert_eq!(projection_files(root).len(), 2);
    assert!(wait_for_child(waiter).success());
    assert_eq!(
        std::fs::read_to_string(root.join("persistent-refresh-count"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(root.join("persistent-request-count"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    let validation: crate::snapshot::CurrentValidationV2 =
        serde_json::from_slice(&std::fs::read(root.join("current-validation")).unwrap()).unwrap();
    assert_eq!(validation.refresh_sequence, 1);

    let failure_directory = tempfile::tempdir().unwrap();
    let failure_root = failure_directory.path();
    seed_previous_projection(failure_root);
    let failure_owner = spawn_persistent_child(failure_root, "failure-owner");
    wait_for_child_file(&failure_root.join("failure-owner-locked"));
    let retry = spawn_persistent_child(failure_root, "failure-waiter");
    wait_for_child_file(&failure_root.join("failure-waiter-attempting-lock"));
    assert!(!wait_for_child(failure_owner).success());
    assert!(wait_for_child(retry).success());
    let failure_validation: crate::snapshot::CurrentValidationV2 =
        serde_json::from_slice(&std::fs::read(failure_root.join("current-validation")).unwrap())
            .unwrap();
    assert_eq!(failure_validation.refresh_sequence, 1);
}

#[test]
fn persistent_refresh_drop_releases_lock_for_a_following_transaction() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let refresher = CranSnapshotRefresher::new(CranMetadataConfig::new(
        "https://cran.invalid",
        "https://feed.invalid/allpackages.zst",
    ))
    .unwrap();

    let transaction = refresher.begin_persistent_refresh(&store).unwrap();
    drop(transaction);
    refresher.begin_persistent_refresh(&store).unwrap();
}

#[test]
fn previous_projection_requires_positive_record_bound_to_current_endpoints() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let repository = "https://cran.invalid";
    let feed = "https://feed.invalid/allpackages.zst";
    let raw_cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = raw_cache
        .key(feed, RawCacheRepresentation::AllPackagesZstd)
        .unwrap();
    let digest = "00".repeat(32);
    let projection = raw_cache
        .projection_path_for_hex_digest(&key, &digest)
        .unwrap();
    std::fs::File::create(&projection).unwrap();

    let mut record = crate::cran::provider::qualification::Record {
        status: crate::cran::provider::qualification::Status::Positive,
        repository_endpoint: repository.into(),
        feed_endpoint: feed.into(),
        feed_digest: digest,
        ..Default::default()
    };
    crate::cran::provider::qualification::publish(&raw_cache.qualification_path(), &record)
        .unwrap();
    let transport = FixtureTransport {
        responses: HashMap::new(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new(repository, feed),
        None,
        Some(raw_cache),
    );
    assert_eq!(
        session.previous_allpackages_projection_path(),
        Some(projection)
    );

    let raw_cache = session.raw_cache.as_ref().unwrap();
    record.repository_endpoint = "https://other.invalid".into();
    crate::cran::provider::qualification::publish(&raw_cache.qualification_path(), &record)
        .unwrap();
    assert_eq!(session.previous_allpackages_projection_path(), None);
}

#[test]
fn current_index_import_projects_catalog_and_evidence_from_one_parse() {
    crate::cran::archive_index::reset_archive_import_count();
    let (catalog, observations) = CranRefreshSession::<FixtureTransport>::parse_current_body(
        CranCurrentIndexRepresentation::Rds,
        NATIVE_UTF8_CURRENT,
    )
    .unwrap();
    assert!(!catalog.is_empty());
    assert!(!observations.is_empty());
    assert_eq!(crate::cran::archive_index::archive_import_count(), 1);

    let plain = b"Package: Matrix\nVersion: 1.7-0\nLicense: BSD\n";
    crate::cran::catalog::reset_packages_import_count();
    let (catalog, observations) = CranRefreshSession::<FixtureTransport>::parse_current_body(
        CranCurrentIndexRepresentation::PlainDcf,
        plain,
    )
    .unwrap();
    assert_eq!(catalog.candidate_count(), 1);
    assert_eq!(observations.len(), 1);
    assert_eq!(crate::cran::catalog::packages_import_count(), 1);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plain).unwrap();
    let gzip = encoder.finish().unwrap();
    crate::cran::catalog::reset_packages_import_count();
    let (_, observations) = CranRefreshSession::<FixtureTransport>::parse_current_body(
        CranCurrentIndexRepresentation::Gzip,
        &gzip,
    )
    .unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(crate::cran::catalog::packages_import_count(), 1);
}

#[test]
fn current_rds_provider_path_assumes_utf8_for_native_format_two_strings() {
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
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
    );
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let catalog = session
        .ensure_current()
        .expect("provider CRAN UTF-8 contract should accept native format-2 strings");
    assert_eq!(
        catalog.candidates_named("Matrix").unwrap()[0]
            .metadata()
            .fields()
            .get("License")
            .map(String::as_str),
        Some("RSOLVE UTF-8 fixture ™")
    );
}

#[test]
fn current_rds_provider_path_rejects_invalid_native_utf8() {
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: INVALID_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
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
    );
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let error = session
        .ensure_current()
        .expect_err("invalid native UTF-8 must fail closed");
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
}

#[test]
fn concrete_loader_validates_and_canonicalizes_base_without_requests() {
    assert_eq!(
        canonical_base_url(" https://cran.invalid/mirror/// ").unwrap(),
        "https://cran.invalid/mirror".into()
    );
    assert!(
        CranSnapshotRefresher::new(CranMetadataConfig::for_repository(
            "https://cran.invalid/mirror///",
        ))
        .is_ok()
    );
    for input in [
        "",
        "ftp://cran.invalid",
        "https://",
        "https://cran.invalid?mirror=1",
        "https://cran.invalid/#mirror",
    ] {
        assert!(matches!(
            CranSnapshotRefresher::new(CranMetadataConfig::for_repository(input)),
            Err(CranSnapshotRefresherError::InvalidBaseUrl { .. })
        ));
    }
}

#[test]
fn refresher_preserves_refresh_metadata_configuration() {
    let refresher = CranSnapshotRefresher::new(
        CranMetadataConfig::for_repository("https://cran.invalid").with_refresh_metadata(),
    )
    .unwrap();
    assert!(refresher.refresh_metadata_enabled());
}

#[test]
fn refresher_preserves_custom_allpackages_feed_endpoint() {
    let refresher = CranSnapshotRefresher::new(CranMetadataConfig::new(
        "https://cran.invalid",
        "https://feed.invalid/custom-ALLPACKAGES.zst",
    ))
    .unwrap();
    assert_eq!(
        refresher.allpackages_feed_endpoint().as_ref(),
        "https://feed.invalid/custom-ALLPACKAGES.zst"
    );
}

#[test]
fn refresher_preserves_publication_cutoff_history_policy() {
    let refresher = CranSnapshotRefresher::new(
        CranMetadataConfig::for_repository("https://cran.invalid").without_allpackages_history(),
    )
    .unwrap();
    assert!(!refresher.allpackages_history_enabled());
}

#[test]
fn current_index_is_authoritative_over_same_identity_archive_metadata() {
    let consistent = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: RSOLVE Fictional Terms Matrix\nNeedsCompilation: yes\n";
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
            body: consistent.to_vec(),
            ..TransportResponse::default()
        },
    );
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    let releases = snapshot
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    assert_eq!(releases.len(), 2);
    assert_eq!(
        releases
            .iter()
            .find(|release| release.version().to_string() == "1.7-0")
            .and_then(|release| release.metadata().fields().get("License"))
            .map(String::as_str),
        Some("RSOLVE Fictional Terms Matrix")
    );

    let conflicting = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: conflicting\nNeedsCompilation: yes\n";
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
            body: conflicting.to_vec(),
            ..TransportResponse::default()
        },
    );
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let snapshot = session
        .refresh_packages(&[PackageName::new("Matrix").unwrap()])
        .unwrap();
    let releases = snapshot
        .releases(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap(),
        ))
        .unwrap();
    assert_eq!(releases.len(), 2);
    assert_eq!(
        releases
            .iter()
            .find(|release| release.version().to_string() == "1.7-0")
            .and_then(|release| release.metadata().fields().get("License"))
            .map(String::as_str),
        Some("conflicting")
    );
}

#[test]
fn recommended_overlay_does_not_invalidate_unrelated_current_candidates() {
    let current = b"Package: rlang\nVersion: 1.1.0\nLicense: MIT\n\n\
Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.1.0)\nMD5sum: root\n\n\
Package: survival\nVersion: 3.8-11\nDepends: R (>= 4.7)\nMD5sum: overlay\nPath: 4.7.0/Recommended\n";
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
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let catalog = session
        .ensure_current()
        .expect("a Recommended overlay must not make the complete current index invalid");
    assert_eq!(catalog.candidates_named("rlang").unwrap().len(), 1);
    assert_eq!(catalog.candidates_named("survival").unwrap().len(), 1);

    let evidence = session.evidence.borrow();
    let survival = evidence
        .iter()
        .filter(|observation| observation.package.as_str() == "survival")
        .collect::<Vec<_>>();
    assert_eq!(survival.len(), 2);
    let overlay = survival
        .iter()
        .find(|observation| {
            observation
                .fields
                .iter()
                .any(|field| field.name.eq_ignore_ascii_case("Path"))
        })
        .expect("Recommended overlay evidence");
    assert!(matches!(
        overlay.scope,
        crate::cran::catalog::CranCatalogRecordScope::RecommendedOverlay { .. }
    ));
    assert_eq!(
        overlay.artifact.as_ref().unwrap().locator,
        "https://cran.invalid/src/contrib/4.7.0/Recommended/survival_3.8-11.tar.gz"
    );
    let root = survival
        .iter()
        .find(|observation| {
            !observation
                .fields
                .iter()
                .any(|field| field.name.eq_ignore_ascii_case("Path"))
        })
        .expect("CRAN root evidence");
    assert!(matches!(
        root.scope,
        crate::cran::catalog::CranCatalogRecordScope::Root
    ));
    assert_eq!(
        root.artifact.as_ref().unwrap().locator,
        "https://cran.invalid/src/contrib/survival_3.8-11.tar.gz"
    );
}

#[test]
fn current_index_transport_or_status_failures_remain_transport_failures() {
    for responses in [
        HashMap::new(),
        HashMap::from([
            (
                current_rds_url(),
                TransportResponse {
                    status: 404,
                    body: Vec::new(),
                    ..TransportResponse::default()
                },
            ),
            (
                current_gzip_url(),
                TransportResponse {
                    status: 410,
                    body: Vec::new(),
                    ..TransportResponse::default()
                },
            ),
            (
                current_plain_url(),
                TransportResponse {
                    status: 503,
                    body: Vec::new(),
                    ..TransportResponse::default()
                },
            ),
        ]),
    ] {
        let transport = FixtureTransport {
            responses,
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let mut session = CranRefreshSession::new(
            Rc::new(transport),
            CranMetadataConfig::new("https://cran.invalid", ""),
        );
        let error = session.ensure_current().unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::TransportFailure
        );
    }
}

#[test]
fn current_index_http_success_with_invalid_schema_is_metadata_invalid() {
    let mut responses = HashMap::new();
    responses.insert(
        current_rds_url(),
        TransportResponse {
            status: 200,
            body: WRONG_ROOT.to_vec(),
            ..TransportResponse::default()
        },
    );
    responses.insert(
        current_gzip_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    responses.insert(
        current_plain_url(),
        TransportResponse {
            status: 503,
            body: Vec::new(),
            ..TransportResponse::default()
        },
    );
    let transport = FixtureTransport {
        responses,
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let mut session = CranRefreshSession::new(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
    );
    let error = session.ensure_current().unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
}

#[test]
fn persistent_current_rds_cache_reuse_avoids_a_second_request() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "max-age=3600".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let first_requests = first_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    first.ensure_current().unwrap();
    assert_eq!(
        first_requests
            .borrow()
            .iter()
            .filter(|request| request.url == current_rds_url())
            .count(),
        1
    );

    let second_transport = FixtureTransport {
        responses: HashMap::new(),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let second_requests = second_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    second.ensure_current().unwrap();
    assert!(second_requests.borrow().is_empty());
}

#[test]
fn refresh_metadata_revalidates_a_fresh_raw_cache_entry() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = session_transport(
        TransportResponse::new(200, NATIVE_UTF8_CURRENT.to_vec()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    first.ensure_current().unwrap();

    let second_transport = session_transport(
        TransportResponse::new(200, NATIVE_UTF8_CURRENT.to_vec()),
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let requests = second_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", "").with_refresh_metadata(),
        Some(t0),
        Some(cache),
    );
    assert!(second.refresh_metadata);
    second.ensure_current().unwrap();
    assert_eq!(
        requests
            .borrow()
            .iter()
            .filter(|request| request.url == current_rds_url())
            .count(),
        1
    );
}

#[test]
fn persistent_refresh_path_uses_current_cache_across_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    crate::cran::provider::refresh_and_publish_with_transport(
        &store,
        first_transport,
        "https://cran.invalid",
        &[PackageName::new("Matrix").unwrap()],
    )
    .unwrap();

    let second_transport = FixtureTransport::fallback(FAST.to_vec(), 200);
    let requests = second_transport.requests.clone();
    crate::cran::provider::refresh_and_publish_with_transport(
        &store,
        second_transport,
        "https://cran.invalid",
        &[PackageName::new("Matrix").unwrap()],
    )
    .unwrap();
    assert!(
        !requests
            .borrow()
            .iter()
            .any(|request| request.url == current_rds_url())
    );
}

#[test]
fn stale_current_cache_revalidates_with_validators_and_304() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let etag = "\"current-etag\"";
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                etag: Some(etag.into()),
                last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".into()),
                retry_after: None,
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "no-cache".into(),
                ),
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    first.ensure_current().unwrap();

    let second_transport = session_transport(
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: TransportResponseHeaders {
                etag: Some("\"refreshed-etag\"".into()),
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "max-age=120".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let second_requests = second_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_rds_url(), RawCacheRepresentation::CurrentRds)
        .unwrap();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(cache),
    );
    second.ensure_current().unwrap();
    let requests = second_requests.borrow();
    let request = requests
        .iter()
        .find(|request| request.url == current_rds_url())
        .unwrap();
    assert_eq!(request.validators.if_none_match.as_deref(), Some(etag));
    assert_eq!(
        request.validators.if_modified_since.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    drop(requests);
    let evidence = second.evidence.borrow();
    let source = &evidence[0].source;
    assert_eq!(source.observed_at, "2026-08-23T00:00:00Z");
    assert_eq!(source.etag.as_deref(), Some("\"refreshed-etag\""));
    assert_eq!(
        source.last_modified.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    let RawCacheLookup::Hit(entry) = RawCache::open(&store).unwrap().lookup(&key) else {
        panic!("expected revalidated raw cache entry")
    };
    assert_eq!(entry.observed_at, t0);
    assert_eq!(entry.validated_at, "2026-08-23T00:00:01Z".parse().unwrap());
    assert_eq!(entry.etag.as_deref(), Some("\"refreshed-etag\""));
    assert_eq!(
        entry.last_modified.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    assert_eq!(
        entry.cache_control,
        crate::cran::provider::cache_policy::CacheControlHeader::Valid("max-age=120".into())
    );
}

#[test]
fn stale_current_cache_304_no_store_evicts_entry_after_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                etag: Some("\"current-etag\"".into()),
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "no-cache".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    first.ensure_current().unwrap();

    let second_transport = session_transport(
        TransportResponse {
            status: 304,
            body: Vec::new(),
            headers: TransportResponseHeaders {
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "no-store".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    second
        .ensure_current()
        .expect("validated cached body remains usable for this refresh");
    let key = crate::cran::provider::raw_cache::RawCache::open(&store)
        .unwrap()
        .key(&current_rds_url(), RawCacheRepresentation::CurrentRds)
        .unwrap();
    assert!(matches!(
        crate::cran::provider::raw_cache::RawCache::open(&store)
            .unwrap()
            .lookup(&key),
        RawCacheLookup::Missing
    ));
}

#[test]
fn fresh_semantically_invalid_current_cache_recovers_unconditionally() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_rds_url(), RawCacheRepresentation::CurrentRds)
        .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    cache
        .publish(
            &key,
            RawCacheWrite {
                status: 200,
                body: WRONG_ROOT.to_vec(),
                observed_at: t0,
                validated_at: t0,
                etag: None,
                last_modified: None,
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "max-age=3600".into(),
                ),
            },
        )
        .unwrap();
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let requests = transport.requests.clone();
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    session.ensure_current().unwrap();
    let requests = requests.borrow();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url == current_rds_url())
            .count(),
        1
    );
}

#[test]
fn stale_current_cache_without_validators_uses_unconditional_request() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let t0 = "2026-08-23T00:00:00Z".parse().unwrap();
    let first_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            headers: TransportResponseHeaders {
                cache_control: crate::cran::provider::cache_policy::CacheControlHeader::Valid(
                    "no-cache".into(),
                ),
                ..TransportResponseHeaders::default()
            },
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut first = CranRefreshSession::new_with_clock(
        Rc::new(first_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some(t0),
        Some(cache),
    );
    first.ensure_current().unwrap();

    let second_transport = session_transport(
        TransportResponse {
            status: 200,
            body: NATIVE_UTF8_CURRENT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let requests = second_transport.requests.clone();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let mut second = CranRefreshSession::new_with_clock(
        Rc::new(second_transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:01Z".parse().unwrap()),
        Some(cache),
    );
    second.ensure_current().unwrap();
    let request = requests
        .borrow()
        .iter()
        .find(|request| request.url == current_rds_url())
        .unwrap()
        .clone();
    assert_eq!(request.validators, TransportValidators::default());
}

#[test]
fn invalid_network_current_response_is_not_persisted() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::snapshot::SnapshotStore::open(
        directory.path(),
        rsolve_core::RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    let cache = crate::cran::provider::raw_cache::RawCache::open(&store).unwrap();
    let key = cache
        .key(&current_rds_url(), RawCacheRepresentation::CurrentRds)
        .unwrap();
    let transport = session_transport(
        TransportResponse {
            status: 200,
            body: WRONG_ROOT.to_vec(),
            ..TransportResponse::default()
        },
        TransportResponse::new(404, Vec::new()),
        TransportResponse::new(404, Vec::new()),
    );
    let mut session = CranRefreshSession::new_with_clock(
        Rc::new(transport),
        CranMetadataConfig::new("https://cran.invalid", ""),
        Some("2026-08-23T00:00:00Z".parse().unwrap()),
        Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
    );
    assert!(session.ensure_current().is_err());
    assert!(matches!(
        crate::cran::provider::raw_cache::RawCache::open(&store)
            .unwrap()
            .lookup(&key),
        RawCacheLookup::Missing
    ));
}

#[test]
fn current_absence_with_absent_archive_sources_is_empty() {
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
            body: b"Package: other\nVersion: 1.0.0\n".to_vec(),
            ..TransportResponse::default()
        },
    );
    transport.responses.insert(
        history_url(),
        TransportResponse {
            status: 404,
            body: Vec::new(),
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
        .expect("empty current result");
    assert!(
        snapshot
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap()
            ))
            .unwrap()
            .is_empty()
    );
    assert_eq!(requests.borrow().len(), 5);
    assert!(requests.borrow().iter().any(|url| url == &fast_url()));
    assert!(requests.borrow().iter().any(|url| url == &history_url()));
    assert!(session.diagnostics.iter().any(|diagnostic| {
        diagnostic.source() == CranRefreshSource::ArchiveHistory
            && matches!(
                diagnostic.status_detail(),
                CranFastPathStatus::Absent { status: 404 }
            )
    }));
}
