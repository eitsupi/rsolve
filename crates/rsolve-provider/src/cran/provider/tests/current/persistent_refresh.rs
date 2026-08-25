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
    let now: jiff::Timestamp = "2026-08-25T00:00:00Z".parse().unwrap();
    let pre_wait = crate::cran::provider::refresher::observe_persistent_refresh_probe(&store);
    // Keep the child fixture's ordering identical to the production
    // preflight: the opaque observation precedes the non-blocking cache probe.
    // In the waiter process this probe runs while the owner holds the lock and
    // therefore returns `None` without turning the test into a busy wait.
    let initial_policy = CranSnapshotCachePolicy::at(now)
        .with_expected_endpoint("https://cloud.r-project.org")
        .with_allowed_auxiliary_endpoint(feed);
    let _initial_cache =
        crate::cran::provider::inspect_cran_snapshot_cache_without_wait(&store, &initial_policy);
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
    let policy = CranSnapshotCachePolicy::at(jiff::Timestamp::now())
        .with_expected_endpoint("https://cran.invalid")
        .with_allowed_auxiliary_endpoint("https://feed.invalid/allpackages.zst");

    let transaction = refresher
        .begin_persistent_refresh(refresher.preflight_refresh(&store, &policy))
        .unwrap();
    drop(transaction);
    refresher
        .begin_persistent_refresh(refresher.preflight_refresh(&store, &policy))
        .unwrap();
}

#[test]
fn previous_projection_requires_positive_record_bound_to_current_endpoints() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let previous = seed_previous_projection(root);
    let store =
        crate::snapshot::SnapshotStore::open(root, rsolve_core::RegistryId::new("cran").unwrap())
            .unwrap();
    let feed = "https://feed.invalid/ALLPACKAGES.zst";
    let make_session = || {
        CranRefreshSession::new_with_clock(
            Rc::new(super::archive_cache::empty_transport()),
            CranMetadataConfig::new("https://cloud.r-project.org", feed),
            Some("2026-08-25T00:00:00Z".parse().unwrap()),
            Some(crate::cran::provider::raw_cache::RawCache::open(&store).unwrap()),
        )
    };

    assert_eq!(
        make_session().previous_allpackages_projection_path(),
        Some(previous)
    );

    let qualification_path = crate::cran::provider::raw_cache::RawCache::open(&store)
        .unwrap()
        .qualification_path();
    let mut record = crate::cran::provider::qualification::load_result(&qualification_path)
        .unwrap()
        .expect("seeded qualification");
    record.status = crate::cran::provider::qualification::Status::Unknown;
    crate::cran::provider::qualification::publish(&qualification_path, &record).unwrap();
    assert!(
        make_session()
            .previous_allpackages_projection_path()
            .is_none()
    );

    record.status = crate::cran::provider::qualification::Status::Positive;
    record.repository_endpoint = "https://other.invalid".into();
    crate::cran::provider::qualification::publish(&qualification_path, &record).unwrap();
    assert!(
        make_session()
            .previous_allpackages_projection_path()
            .is_none()
    );

    record.repository_endpoint = "https://cloud.r-project.org".into();
    record.feed_endpoint = "https://other.invalid/ALLPACKAGES.zst".into();
    crate::cran::provider::qualification::publish(&qualification_path, &record).unwrap();
    assert!(
        make_session()
            .previous_allpackages_projection_path()
            .is_none()
    );
}
use super::*;
use std::path::PathBuf;
