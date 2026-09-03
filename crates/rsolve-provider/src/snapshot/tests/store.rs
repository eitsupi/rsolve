use super::*;

fn view_path(store: &SnapshotStore) -> std::path::PathBuf {
    std::fs::read_dir(store.root().join("views"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().and_then(|extension| extension.to_str()) == Some("json"))
        .expect("published snapshot view head")
}

#[test]
fn read_latest_view_optional_distinguishes_missing_head_from_corruption() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    assert!(store.read_latest_view_optional().unwrap().is_none());
    std::fs::write(store.root().join("views/broken.json"), b"not-json").unwrap();
    assert!(store.read_latest_view_optional().is_err());
}

#[test]
fn endpoint_view_lookup_skips_an_invalid_unrelated_head() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let input = present_input();
    let endpoint = input.sources[0].endpoint.clone();
    store
        .build_and_publish_with_endpoint(input, endpoint.as_str())
        .unwrap();
    std::fs::write(store.root().join("views/broken.json"), b"not-json").unwrap();

    let selected = store.read_view_for_endpoint(&endpoint).unwrap();
    assert!(selected.is_some());
}

#[test]
fn endpoint_revision_probe_skips_an_invalid_unrelated_head() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    store
        .build_and_publish_with_endpoint(present_input(), "https://mirror-a.example")
        .unwrap();
    std::fs::write(store.root().join("views/broken.json"), b"not-json").unwrap();

    let revision = store
        .read_view_validation_revision_for_endpoint_unlocked("https://mirror-a.example")
        .unwrap();
    assert!(revision.is_some());
}

#[test]
fn endpoint_revision_probe_ignores_malformed_views_until_a_match_exists() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    store
        .build_and_publish_with_endpoint(present_input(), "https://mirror-b.example")
        .unwrap();
    std::fs::write(store.root().join("views/broken.json"), b"not-json").unwrap();

    let before = store
        .read_view_validation_revision_for_endpoint_unlocked("https://mirror-a.example")
        .unwrap();
    assert!(before.is_none());
    store
        .build_and_publish_with_endpoint(present_input(), "https://mirror-a.example")
        .unwrap();
    let after = store
        .read_view_validation_revision_for_endpoint_unlocked("https://mirror-a.example")
        .unwrap();
    assert!(after.is_some());
}

#[test]
fn publishing_rejects_an_invalid_existing_view_head() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    store.build_and_publish(present_input()).unwrap();
    std::fs::write(view_path(&store), b"not-json").unwrap();

    let staged_path = store.root().join("tmp/next.redb");
    let next = SnapshotGenerationBuilder::new(present_input(), &staged_path)
        .build()
        .unwrap();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    assert!(store.publish_generation(&lock, next).is_err());
}

#[test]
fn build_and_publish_returns_the_generation_it_pinned_before_unlock() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let input = present_input();
    let reference =
        SnapshotGenerationBuilder::new(input.clone(), dir.path().join("reference-generation.redb"))
            .build()
            .unwrap();
    let expected_generation = reference.generation().to_owned();

    let returned = store.build_and_publish(input).unwrap();
    assert_eq!(returned.header().generation, expected_generation);
    assert_eq!(
        returned
            .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.read_latest_view().unwrap().header().generation,
        expected_generation
    );
}

#[test]
fn combined_build_and_publish_validates_the_staged_generation_once() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    reset_validation_count();

    store.build_and_publish(present_input()).unwrap();

    assert_eq!(validation_count(), 1);
}

#[test]
fn publish_rejects_a_corrupt_staged_generation_without_publishing() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let staged_path = store.root().join("tmp/corrupt-staged.redb");
    let generation = SnapshotGenerationBuilder::new(present_input(), &staged_path)
        .build()
        .unwrap();
    corrupt_stored_history(&staged_path, "foo");

    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    assert!(store.publish_generation(&lock, generation).is_err());
    drop(lock);

    assert!(staged_path.exists());
    assert!(store.read_latest_view_optional().unwrap().is_none());
}

#[test]
fn build_and_publish_returns_a_even_if_b_publishes_before_return() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let returned = store
        .build_and_publish_with_test_hook(present_input(), |store| {
            let mut second_input = present_input();
            second_input.sources[0].content_sha256 = [9; 32];
            second_input.coverage.source_ids =
                vec![source_observation(&second_input.sources[0]).unwrap().id];
            let second_path = store.root().join("tmp/interleaving-second.redb");
            let second = SnapshotGenerationBuilder::new(second_input, &second_path)
                .build()
                .unwrap();
            let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
            store.publish_generation(&lock, second).unwrap();
            drop(lock);
        })
        .unwrap();
    let selected = store.read_latest_view().unwrap();

    assert_ne!(returned.header().generation, selected.header().generation);
    assert_eq!(
        returned
            .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        selected
            .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn store_publishes_strict_view_head_and_pins_readers() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let first_path = store.root().join("tmp/first.redb");
    let first = SnapshotGenerationBuilder::new(present_input(), &first_path)
        .build()
        .unwrap();
    let first_generation = first.generation().to_owned();
    let first_header_sha256 = hex(&Sha256::digest(first.header_bytes()));
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&lock, first).unwrap();
    drop(lock);
    assert!(!first_path.exists());
    let first_view = view_path(&store);
    let view = std::fs::read(&first_view).unwrap();
    assert!(
        String::from_utf8(view)
            .unwrap()
            .contains("\"format\":\"rsolve-metadata-view\"")
    );
    assert!(
        std::fs::read_to_string(&first_view)
            .unwrap()
            .contains(&first_generation)
    );
    assert!(
        std::fs::read_to_string(&first_view)
            .unwrap()
            .contains(&first_header_sha256)
    );
    let old_reader = store.read_latest_view().unwrap();
    let old_reader_2 = store.read_latest_view().unwrap();

    let mut reuse_input = present_input();
    reuse_input.created_at = "2026-08-24T00:00:00Z".into();
    reuse_input.producer = "different-producer".into();
    reuse_input.sources[0].endpoint = "https://mirror.example.test/PACKAGES.gz".into();
    reuse_input.sources[0].etag = Some("different-etag".into());
    let reuse_path = store.root().join("tmp/reuse.redb");
    let reuse = SnapshotGenerationBuilder::new(reuse_input, &reuse_path)
        .build()
        .unwrap();
    assert_eq!(reuse.generation(), first_generation);
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&lock, reuse).unwrap();
    drop(lock);
    assert!(!reuse_path.exists());
    assert!(first_view.exists());

    let mut second_input = present_input();
    second_input.sources[0].content_sha256 = [9; 32];
    second_input.coverage.source_ids =
        vec![source_observation(&second_input.sources[0]).unwrap().id];
    let second_path = store.root().join("tmp/second.redb");
    let second = SnapshotGenerationBuilder::new(second_input, &second_path)
        .build()
        .unwrap();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&lock, second).unwrap();
    drop(lock);
    assert!(!second_path.exists());
    let view_count = std::fs::read_dir(store.root().join("views"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
        .count();
    assert!(view_count >= 2);
    let new_reader = store.read_latest_view().unwrap();
    assert_ne!(
        old_reader.header().generation,
        new_reader.header().generation
    );
    let cleanup_lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.cleanup(&cleanup_lock, &[]).unwrap();
    drop(cleanup_lock);
    assert_eq!(
        old_reader
            .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        old_reader_2
            .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        new_reader
            .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn store_repairs_corrupt_same_generation_before_republishing_view_head() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let initial_path = store.root().join("tmp/initial.redb");
    let initial = SnapshotGenerationBuilder::new(present_input(), &initial_path)
        .build()
        .unwrap();
    let generation_id = initial.generation().to_owned();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&lock, initial).unwrap();
    drop(lock);
    let final_path = store
        .root()
        .join(format!("generations/{generation_id}.redb"));

    corrupt_stored_history(&final_path, "foo");
    assert!(validate_generation(&final_path, &RegistryId::new("cran").unwrap()).is_err());

    let replacement_path = store.root().join("tmp/replacement.redb");
    let replacement = SnapshotGenerationBuilder::new(present_input(), &replacement_path)
        .build()
        .unwrap();
    assert_eq!(replacement.generation(), generation_id);
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&lock, replacement).unwrap();
    drop(lock);

    assert!(!replacement_path.exists());
    assert!(view_path(&store).exists());
    let loader = store.read_latest_view().unwrap();
    assert_eq!(loader.header().generation, generation_id);
    assert_eq!(
        loader
            .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
            .unwrap()
            .len(),
        1
    );
    assert!(validate_generation(&final_path, &RegistryId::new("cran").unwrap()).is_ok());
}

#[test]
fn store_repairs_corrupt_generation_while_old_reader_is_pinned() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let initial_path = store.root().join("tmp/initial.redb");
    let initial = SnapshotGenerationBuilder::new(present_input(), &initial_path)
        .build()
        .unwrap();
    let generation_id = initial.generation().to_owned();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&lock, initial).unwrap();
    drop(lock);

    let final_path = store
        .root()
        .join(format!("generations/{generation_id}.redb"));
    let old_reader = store.read_latest_view().unwrap();
    let corrupt_path = store.root().join("tmp/corrupt.redb");
    std::fs::copy(&final_path, &corrupt_path).unwrap();
    corrupt_stored_history(&corrupt_path, "foo");
    replace_file(&corrupt_path, &final_path).unwrap();
    assert!(validate_generation(&final_path, &RegistryId::new("cran").unwrap()).is_err());

    let replacement_path = store.root().join("tmp/replacement.redb");
    let replacement = SnapshotGenerationBuilder::new(present_input(), &replacement_path)
        .build()
        .unwrap();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&lock, replacement).unwrap();
    drop(lock);

    let package = SolverKey::InstalledName(PackageName::new("foo").unwrap());
    assert_eq!(old_reader.releases(&package).unwrap().len(), 1);
    let new_reader = store.read_latest_view().unwrap();
    assert_eq!(new_reader.header().generation, generation_id);
    assert_eq!(new_reader.releases(&package).unwrap().len(), 1);
    assert!(validate_generation(&final_path, &RegistryId::new("cran").unwrap()).is_ok());
}

#[test]
fn store_rejects_a_semantic_collision_without_overwrite() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let staged = store.root().join("tmp/original.redb");
    let original = SnapshotGenerationBuilder::new(input(), &staged)
        .build()
        .unwrap();
    let mut changed = input();
    changed.sources[0].content_sha256 = [9; 32];
    changed.coverage.source_ids = vec![source_observation(&changed.sources[0]).unwrap().id];
    let replacement_path = store.root().join("tmp/replacement.redb");
    let replacement = SnapshotGenerationBuilder::new(changed, &replacement_path)
        .build()
        .unwrap();
    let final_path = store
        .root()
        .join(format!("generations/{}.redb", replacement.generation()));
    std::fs::copy(&staged, &final_path).unwrap();
    let before = stored_header(&final_path);
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    assert!(store.publish_generation(&lock, replacement).is_err());
    drop(lock);
    assert!(replacement_path.exists());
    assert_eq!(stored_header(&final_path), before);
    assert_eq!(stored_header(&final_path), original.header_bytes());
}

#[test]
fn store_refresh_lock_is_advisory_and_released_on_drop() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    assert!(matches!(
        store.acquire_refresh_lock(RefreshLockMode::Try),
        Err(SnapshotStoreError::Busy)
    ));
    drop(lock);
    let _lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
}

#[test]
fn refresh_lock_contention_is_visible_to_a_child_process() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let _lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("snapshot::tests::store::refresh_lock_child_probe")
        .arg("--nocapture")
        .env("RSOLVE_REFRESH_LOCK_CHILD_ROOT", dir.path())
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn refresh_lock_child_probe() {
    let Ok(root) = std::env::var("RSOLVE_REFRESH_LOCK_CHILD_ROOT") else {
        return;
    };
    let store = SnapshotStore::open(root, RegistryId::new("cran").unwrap()).unwrap();
    assert!(matches!(
        store.acquire_refresh_lock(RefreshLockMode::Try),
        Err(SnapshotStoreError::Busy)
    ));
}

#[test]
fn read_latest_view_serializes_generation_open_with_cleanup() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let staged_path = store.root().join("tmp/view-lock.redb");
    let generation = SnapshotGenerationBuilder::new(present_input(), &staged_path)
        .build()
        .unwrap();
    let publish_lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&publish_lock, generation).unwrap();
    drop(publish_lock);
    let lock = store
        .acquire_refresh_lock(RefreshLockMode::Blocking)
        .unwrap();

    let ready_path = dir.path().join("read-view-child-ready");
    let attempt_path = dir.path().join("read-view-child-attempt");
    let go_path = dir.path().join("read-view-child-go");
    let done_path = dir.path().join("read-view-child-done");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("snapshot::tests::store::read_latest_view_lock_child_probe")
        .arg("--nocapture")
        .env("RSOLVE_READ_VIEW_CHILD_ROOT", dir.path())
        .env("RSOLVE_READ_VIEW_CHILD_READY", &ready_path)
        .env("RSOLVE_READ_VIEW_CHILD_ATTEMPT", &attempt_path)
        .env("RSOLVE_READ_VIEW_CHILD_GO", &go_path)
        .env("RSOLVE_READ_VIEW_CHILD_DONE", &done_path)
        .spawn()
        .unwrap();

    let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready_path.exists() {
        assert!(
            std::time::Instant::now() < wait_deadline,
            "child did not become ready"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    // Keep the refresh lock held while the child enters read_latest_view.  A
    // cleanup/publish operation cannot remove the selected generation until
    // the loader has been opened and validated.
    std::fs::write(&go_path, b"").unwrap();
    while !attempt_path.exists() {
        assert!(
            std::time::Instant::now() < wait_deadline,
            "child did not attempt read_latest_view"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let blocked_deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
    while std::time::Instant::now() < blocked_deadline {
        assert!(
            !done_path.exists(),
            "read_latest_view completed while the refresh lock was held"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    drop(lock);
    assert!(child.wait().unwrap().success());
    assert!(done_path.exists());
}

#[test]
fn read_latest_view_lock_child_probe() {
    let Ok(root) = std::env::var("RSOLVE_READ_VIEW_CHILD_ROOT") else {
        return;
    };
    let ready = PathBuf::from(std::env::var_os("RSOLVE_READ_VIEW_CHILD_READY").unwrap());
    let attempt = PathBuf::from(std::env::var_os("RSOLVE_READ_VIEW_CHILD_ATTEMPT").unwrap());
    let go = PathBuf::from(std::env::var_os("RSOLVE_READ_VIEW_CHILD_GO").unwrap());
    let done = PathBuf::from(std::env::var_os("RSOLVE_READ_VIEW_CHILD_DONE").unwrap());
    let store = SnapshotStore::open(root, RegistryId::new("cran").unwrap()).unwrap();
    std::fs::write(ready, b"").unwrap();
    while !go.exists() {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    std::fs::write(attempt, b"").unwrap();
    assert!(store.read_latest_view().is_ok());
    std::fs::write(done, b"").unwrap();
}

#[test]
fn read_view_candidates_serializes_generation_open_with_refresh() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let staged_path = store.root().join("tmp/candidates-lock.redb");
    let generation = SnapshotGenerationBuilder::new(present_input(), &staged_path)
        .build()
        .unwrap();
    let publish_lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&publish_lock, generation).unwrap();
    drop(publish_lock);
    let lock = store
        .acquire_refresh_lock(RefreshLockMode::Blocking)
        .unwrap();

    let ready_path = dir.path().join("read-candidates-child-ready");
    let attempt_path = dir.path().join("read-candidates-child-attempt");
    let go_path = dir.path().join("read-candidates-child-go");
    let done_path = dir.path().join("read-candidates-child-done");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("snapshot::tests::store::read_view_candidates_lock_child_probe")
        .arg("--nocapture")
        .env("RSOLVE_CANDIDATES_CHILD_ROOT", dir.path())
        .env("RSOLVE_CANDIDATES_CHILD_READY", &ready_path)
        .env("RSOLVE_CANDIDATES_CHILD_ATTEMPT", &attempt_path)
        .env("RSOLVE_CANDIDATES_CHILD_GO", &go_path)
        .env("RSOLVE_CANDIDATES_CHILD_DONE", &done_path)
        .spawn()
        .unwrap();

    let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready_path.exists() {
        assert!(
            std::time::Instant::now() < wait_deadline,
            "child did not become ready"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    std::fs::write(&go_path, b"").unwrap();
    while !attempt_path.exists() {
        assert!(
            std::time::Instant::now() < wait_deadline,
            "child did not attempt read_view_candidates"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let blocked_deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
    while std::time::Instant::now() < blocked_deadline {
        assert!(
            !done_path.exists(),
            "read_view_candidates completed while the refresh lock was held"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    drop(lock);
    assert!(child.wait().unwrap().success());
    assert!(done_path.exists());
}

#[test]
fn read_view_candidates_lock_child_probe() {
    let Ok(root) = std::env::var("RSOLVE_CANDIDATES_CHILD_ROOT") else {
        return;
    };
    let ready = PathBuf::from(std::env::var_os("RSOLVE_CANDIDATES_CHILD_READY").unwrap());
    let attempt = PathBuf::from(std::env::var_os("RSOLVE_CANDIDATES_CHILD_ATTEMPT").unwrap());
    let go = PathBuf::from(std::env::var_os("RSOLVE_CANDIDATES_CHILD_GO").unwrap());
    let done = PathBuf::from(std::env::var_os("RSOLVE_CANDIDATES_CHILD_DONE").unwrap());
    let store = SnapshotStore::open(root, RegistryId::new("cran").unwrap()).unwrap();
    std::fs::write(ready, b"").unwrap();
    while !go.exists() {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    std::fs::write(attempt, b"").unwrap();
    assert!(store.read_view_candidates().is_ok());
    std::fs::write(done, b"").unwrap();
}

#[test]
fn cleanup_preserves_retained_final_orphan_and_view() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let old_path = store.root().join("tmp/old.redb");
    let old = SnapshotGenerationBuilder::new(present_input(), &old_path)
        .build()
        .unwrap();
    let old_generation = old.generation().to_owned();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&lock, old).unwrap();
    drop(lock);
    let old_reader = store.read_latest_view().unwrap();
    assert_eq!(old_reader.header().generation, old_generation);

    let new_path = store.root().join("tmp/new.redb");
    let mut changed = present_input();
    changed.sources[0].content_sha256 = [9; 32];
    changed.coverage.source_ids = vec![source_observation(&changed.sources[0]).unwrap().id];
    let new = SnapshotGenerationBuilder::new(changed, &new_path)
        .build()
        .unwrap();
    let new_generation = new.generation().to_owned();
    let new_final = store
        .root()
        .join(format!("generations/{new_generation}.redb"));
    std::fs::copy(&new_path, &new_final).unwrap();
    assert_eq!(
        store.read_latest_view().unwrap().header().generation,
        old_generation
    );

    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.cleanup(&lock, &[&new_generation]).unwrap();
    drop(lock);
    assert!(new_final.exists());
    assert!(
        store
            .root()
            .join(format!("generations/{old_generation}.redb"))
            .exists()
    );
    assert!(!new_path.exists());

    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.cleanup(&lock, &[]).unwrap();
    drop(lock);
    assert!(!new_final.exists());
    assert!(
        store
            .root()
            .join(format!("generations/{old_generation}.redb"))
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn cleanup_preserves_generation_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let target = store.root().join("generations/symlink-target");
    let link = store
        .root()
        .join("generations/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.redb");
    std::fs::write(&target, b"target").unwrap();
    symlink(&target, &link).unwrap();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.cleanup(&lock, &[]).unwrap();
    drop(lock);
    assert!(link.exists());
    assert!(target.exists());
}

#[test]
fn cleanup_removes_unclean_child_generation_temp() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("snapshot::tests::store::unclean_generation_child_probe")
        .arg("--nocapture")
        .env("RSOLVE_UNCLEAN_GENERATION_CHILD_ROOT", dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(store.root().join("tmp/unclean.redb").exists());
    let unclean_generation = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let unclean_final = store
        .root()
        .join(format!("generations/{unclean_generation}.redb"));
    std::fs::copy(store.root().join("tmp/unclean.redb"), &unclean_final).unwrap();
    std::fs::write(store.root().join("views/broken.json"), b"not-json").unwrap();
    let error = store.read_latest_view().err().unwrap();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );
    std::fs::remove_file(store.root().join("views/broken.json")).unwrap();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.cleanup(&lock, &[]).unwrap();
    drop(lock);
    assert!(!store.root().join("tmp/unclean.redb").exists());
    assert!(!unclean_final.exists());
}

#[test]
fn unclean_generation_child_probe() {
    let Ok(root) = std::env::var("RSOLVE_UNCLEAN_GENERATION_CHILD_ROOT") else {
        return;
    };
    let path = PathBuf::from(root).join("tmp/unclean.redb");
    let database = Database::create(&path).unwrap();
    let write = database.begin_write().unwrap();
    let mut table = write.open_table(SNAPSHOT_HEADER).unwrap();
    table.insert(HEADER_KEY, b"partial".as_slice()).unwrap();
    std::process::exit(0);
}

#[test]
fn store_rejects_broken_view_and_cleans_orphans_without_touching_valid_views() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let path = store.root().join("tmp/view-head.redb");
    let generation = SnapshotGenerationBuilder::new(present_input(), &path)
        .build()
        .unwrap();
    let generation_id = generation.generation().to_owned();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.publish_generation(&lock, generation).unwrap();
    drop(lock);
    let orphan_tmp = store.root().join("tmp/orphan.tmp");
    std::fs::write(&orphan_tmp, b"orphan").unwrap();
    let orphan_generation = store
        .root()
        .join("generations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.redb");
    std::fs::write(&orphan_generation, b"orphan").unwrap();
    let unknown_generation = store.root().join("generations/not-a-generation.redb");
    std::fs::write(&unknown_generation, b"unknown").unwrap();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.cleanup(&lock, &[]).unwrap();
    drop(lock);
    assert!(
        store
            .root()
            .join(format!("generations/{generation_id}.redb"))
            .exists()
    );
    assert!(!orphan_tmp.exists());
    assert!(!orphan_generation.exists());
    assert!(unknown_generation.exists());

    let final_path = store
        .root()
        .join(format!("generations/{generation_id}.redb"));
    delete_stored_history(&final_path, "foo");
    let error = store.read_latest_view().err().unwrap();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );

    let view = view_path(&store);
    let mut head_bytes = std::fs::read(&view).unwrap();
    let marker = b"\"header_sha256\":\"";
    let start = head_bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap()
        + marker.len();
    head_bytes[start..start + 64].fill(b'0');
    std::fs::write(&view, head_bytes).unwrap();
    let error = store.read_latest_view().err().unwrap();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );

    std::fs::write(&view, b"{\"format\":\"broken\"}").unwrap();
    let error = store.read_latest_view().err().unwrap();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );
    std::fs::write(&view, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let error = store.read_latest_view().err().unwrap();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );
    std::fs::write(&view, b"{").unwrap();
    let error = store.read_latest_view().err().unwrap();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );

    std::fs::remove_file(&view).unwrap();
    assert!(store.read_latest_view().is_err());
}

#[test]
fn store_rejects_generation_headers_over_the_read_limit() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let generation = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let path = store.root().join(format!("generations/{generation}.redb"));
    let header = vec![b'x'; HEADER_LIMIT + 1];
    let database = Database::create(&path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(SNAPSHOT_HEADER).unwrap();
        table.insert(HEADER_KEY, header.as_slice()).unwrap();
    }
    write.commit().unwrap();
    drop(database);
    std::fs::write(
        store.root().join("views/broken.json"),
        vec![b'x'; 1024 * 1024 + 1],
    )
    .unwrap();
    let error = store.read_latest_view().err().unwrap();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );
}

#[test]
fn store_cleanup_can_recover_before_first_view() {
    let dir = tempdir().unwrap();
    let store = SnapshotStore::open(dir.path(), RegistryId::new("cran").unwrap()).unwrap();
    let staged = store.root().join("tmp/orphan.redb");
    let generation = SnapshotGenerationBuilder::new(input(), &staged)
        .build()
        .unwrap();
    let final_path = store
        .root()
        .join(format!("generations/{}.redb", generation.generation()));
    std::fs::copy(&staged, &final_path).unwrap();
    let lock = store.acquire_refresh_lock(RefreshLockMode::Try).unwrap();
    store.cleanup(&lock, &[]).unwrap();
    drop(lock);
    assert!(!staged.exists());
    assert!(!final_path.exists());
}
