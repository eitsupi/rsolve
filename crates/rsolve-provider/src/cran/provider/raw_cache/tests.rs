use super::super::MAX_RESPONSE_BYTES;
use super::*;
use crate::cran::provider::transport::TransportResponseHeaders;
use crate::snapshot::SnapshotStore;
use rsolve_core::RegistryId;
use std::fs;
use std::ops::Deref;
use tempfile::{TempDir, tempdir};

struct StoreFixture {
    _directory: TempDir,
    store: SnapshotStore,
}

impl Deref for StoreFixture {
    type Target = SnapshotStore;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

fn store() -> StoreFixture {
    let directory = tempdir().unwrap();
    let store = SnapshotStore::open(
        directory.path().to_path_buf(),
        RegistryId::new("cran").unwrap(),
    )
    .unwrap();
    StoreFixture {
        _directory: directory,
        store,
    }
}

fn key(store: &SnapshotStore) -> RawCacheKey {
    RawCacheKey::new(
        store.registry_id(),
        "https://cran.invalid/src/contrib/PACKAGES.rds",
        RawCacheRepresentation::CurrentRds,
    )
    .unwrap()
}

fn write(body: &[u8]) -> RawCacheWrite {
    let timestamp = "2026-08-23T00:00:00Z".parse().unwrap();
    RawCacheWrite {
        status: 200,
        body: body.to_vec(),
        observed_at: timestamp,
        validated_at: timestamp,
        etag: Some("\"tag\"".into()),
        last_modified: None,
        cache_control: CacheControlHeader::Valid("max-age=120".into()),
    }
}

#[test]
fn raw_cache_round_trip_and_304_timestamp_update() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Missing));
    assert!(matches!(
        cache.publish(&key, write(b"body")).unwrap(),
        RawCachePublishOutcome::Stored
    ));
    cache.publish(&key, write(b"replacement")).unwrap();
    assert_eq!(fs::read_dir(&cache.directory).unwrap().count(), 2);
    let RawCacheLookup::Hit(entry) = cache.lookup(&key) else {
        panic!("expected hit")
    };
    assert_eq!(entry.body, b"replacement");
    let later = "2026-08-23T00:00:10Z".parse().unwrap();
    cache.update_validated_at(&key, later).unwrap();
    let RawCacheLookup::Hit(entry) = cache.lookup(&key) else {
        panic!("expected updated hit")
    };
    assert_eq!(entry.observed_at, "2026-08-23T00:00:00Z".parse().unwrap());
    assert_eq!(entry.validated_at, later);
}

#[test]
fn raw_cache_preserves_validated_response_headers() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    let mut response = write(b"body");
    response.last_modified = Some("Wed, 21 Oct 2015 07:28:00 GMT".into());
    cache.publish(&key, response).unwrap();
    let RawCacheLookup::Hit(entry) = cache.lookup(&key) else {
        panic!("expected hit")
    };
    assert_eq!(entry.etag.as_deref(), Some("\"tag\""));
    assert_eq!(
        entry.last_modified.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    assert_eq!(
        entry.cache_control,
        CacheControlHeader::Valid("max-age=120".into())
    );
}

#[test]
fn raw_cache_304_no_store_evicts_without_republishing() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    cache.publish(&key, write(b"body")).unwrap();
    cache
        .update_validated_at_with_headers(
            &key,
            "2026-08-23T00:00:10Z".parse().unwrap(),
            &TransportResponseHeaders {
                cache_control: CacheControlHeader::Valid("no-store".into()),
                ..TransportResponseHeaders::default()
            },
        )
        .unwrap();
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Missing));
}

#[test]
fn raw_cache_key_separates_endpoint_and_representation_and_rejects_unsafe_urls() {
    let store = store();
    let first = key(&store);
    let second = RawCacheKey::new(
        store.registry_id(),
        "https://cran.invalid/src/contrib/PACKAGES.gz",
        RawCacheRepresentation::CurrentGzip,
    )
    .unwrap();
    assert_ne!(first.digest(), second.digest());
    for endpoint in [
        "https://user:pass@cran.invalid/PACKAGES",
        "https://cran.invalid/PACKAGES?x=1",
        "https://cran.invalid/PACKAGES#fragment",
        "file:///tmp/PACKAGES",
    ] {
        assert!(
            RawCacheKey::new(
                store.registry_id(),
                endpoint,
                RawCacheRepresentation::CurrentRds,
            )
            .is_err()
        );
    }
}

#[test]
fn raw_cache_no_store_evicts_existing_entry() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    cache.publish(&key, write(b"old")).unwrap();
    let mut response = write(b"body");
    response.cache_control = CacheControlHeader::Valid("no-store".into());
    assert!(matches!(
        cache.publish(&key, response).unwrap(),
        RawCachePublishOutcome::NoStore
    ));
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Missing));
}

#[test]
fn raw_cache_rejects_invalid_cache_control_without_replacing_entry() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    cache.publish(&key, write(b"old")).unwrap();
    let oversized = "x".repeat(8 * 1024 + 1);
    for value in [
        " max-age=120".to_owned(),
        "max-age=120 ".to_owned(),
        "max-age=120\n".to_owned(),
        oversized,
    ] {
        let mut response = write(b"new");
        response.cache_control = CacheControlHeader::Valid(value.into_boxed_str());
        assert!(cache.publish(&key, response).is_err());
        let RawCacheLookup::Hit(entry) = cache.lookup(&key) else {
            panic!("invalid cache-control replaced the existing entry")
        };
        assert_eq!(entry.body, b"old");
    }
}

fn rewrite_header<F>(cache: &RawCache, key: &RawCacheKey, mutate: F)
where
    F: FnOnce(&mut RawCacheHeaderV1),
{
    let path = cache.entry_path(key);
    let bytes = fs::read(&path).unwrap();
    let header_length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let mut header: RawCacheHeaderV1 =
        serde_json::from_slice(&bytes[4..4 + header_length]).unwrap();
    mutate(&mut header);
    let header_bytes = serde_json::to_vec(&header).unwrap();
    let mut rewritten = (header_bytes.len() as u32).to_le_bytes().to_vec();
    rewritten.extend_from_slice(&header_bytes);
    rewritten.extend_from_slice(&bytes[4 + header_length..]);
    fs::write(path, rewritten).unwrap();
}

#[test]
fn raw_cache_rejects_wrong_registry_key_and_header_identity() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let wrong_key = RawCacheKey::new(
        &RegistryId::new("other").unwrap(),
        "https://cran.invalid/src/contrib/PACKAGES.rds",
        RawCacheRepresentation::CurrentRds,
    )
    .unwrap();
    assert!(cache.publish(&wrong_key, write(b"body")).is_err());

    let key = key(&store);
    cache.publish(&key, write(b"body")).unwrap();
    rewrite_header(&cache, &key, |header| header.registry_id = "other".into());
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
    cache.publish(&key, write(b"body")).unwrap();
    rewrite_header(&cache, &key, |header| header.key_sha256 = "0".repeat(64));
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
}

#[test]
fn raw_cache_rejects_wrong_length_or_digest_without_returning_body() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    cache.publish(&key, write(b"body")).unwrap();
    rewrite_header(&cache, &key, |header| header.body_length += 1);
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
    cache.publish(&key, write(b"body")).unwrap();
    rewrite_header(&cache, &key, |header| header.body_sha256 = "0".repeat(64));
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
}

#[test]
fn raw_cache_rejects_oversized_headers_and_bodies() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    cache.publish(&key, write(b"body")).unwrap();
    let path = cache.entry_path(&key);
    let mut bytes = fs::read(&path).unwrap();
    bytes[..HEADER_LENGTH_BYTES].copy_from_slice(&((MAX_HEADER_BYTES as u32) + 1).to_le_bytes());
    fs::write(&path, bytes).unwrap();
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));

    cache.publish(&key, write(b"body")).unwrap();
    rewrite_header(&cache, &key, |header| {
        header.body_length = MAX_RESPONSE_BYTES + 1;
    });
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
}

#[test]
fn raw_cache_rejects_noncanonical_validators() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    cache.publish(&key, write(b"body")).unwrap();
    rewrite_header(&cache, &key, |header| {
        header.etag = Some("unquoted".into());
    });
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));

    cache.publish(&key, write(b"body")).unwrap();
    rewrite_header(&cache, &key, |header| {
        header.etag = Some("\"é\"".into());
    });
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));

    cache.publish(&key, write(b"body")).unwrap();
    rewrite_header(&cache, &key, |header| {
        header.last_modified = Some("Wed, 21 Oct 2015 07:28:00 UTC".into());
    });
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
}

#[cfg(unix)]
#[test]
fn raw_cache_rejects_entry_symlinks() {
    use std::os::unix::fs::symlink;
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    let target = cache.directory.join("outside");
    fs::write(&target, b"not-an-entry").unwrap();
    symlink(&target, cache.entry_path(&key)).unwrap();
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
}

#[cfg(unix)]
#[test]
fn raw_cache_rejects_symlink_namespaces() {
    use std::os::unix::fs::symlink;

    let first_store = store();
    let namespace = first_store.root().join(RAW_CACHE_DIRECTORY);
    fs::create_dir(&namespace).unwrap();
    fs::remove_dir(&namespace).unwrap();
    symlink(first_store.root().join("generations"), &namespace).unwrap();
    assert!(RawCache::open(&first_store).is_err());

    let second_store = store();
    let cache = RawCache::open(&second_store).unwrap();
    let version = cache.directory;
    fs::remove_dir_all(&version).unwrap();
    symlink(second_store.root().join("generations"), &version).unwrap();
    assert!(RawCache::open(&second_store).is_err());
}

#[test]
fn raw_cache_corruption_never_returns_body() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    cache.publish(&key, write(b"body")).unwrap();
    let path = cache.entry_path(&key);
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop();
    fs::write(path, bytes).unwrap();
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
}

#[test]
fn raw_cache_rejects_noncanonical_header_json() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let key = key(&store);
    cache.publish(&key, write(b"body")).unwrap();
    let path = cache.entry_path(&key);
    let bytes = fs::read(&path).unwrap();
    let header_length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let header = &bytes[4..4 + header_length];
    let mut rewritten = ((header_length + 1) as u32).to_le_bytes().to_vec();
    rewritten.push(b' ');
    rewritten.extend_from_slice(header);
    rewritten.extend_from_slice(&bytes[4 + header_length..]);
    fs::write(path, rewritten).unwrap();
    assert!(matches!(cache.lookup(&key), RawCacheLookup::Corrupt(_)));
}

#[test]
fn semantic_snapshot_namespace_is_untouched() {
    let store = store();
    let before = fs::read_dir(store.root().join("generations"))
        .unwrap()
        .count();
    let cache = RawCache::open(&store).unwrap();
    cache.publish(&key(&store), write(b"body")).unwrap();
    assert_eq!(
        fs::read_dir(store.root().join("generations"))
            .unwrap()
            .count(),
        before
    );
    assert!(!store.root().join("current").exists());
}

#[test]
fn projection_retention_keeps_only_a_bounded_recent_set() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let projections = cache
        .projection_namespace_path(ProjectionNamespace::Auxiliary)
        .join("a".repeat(64));
    fs::create_dir_all(&projections).unwrap();
    for index in 0..4 {
        fs::write(
            projections.join(format!("projection-{index}.redb")),
            [index as u8],
        )
        .unwrap();
    }
    fs::write(projections.join("crash.tmp"), [4_u8]).unwrap();
    fs::write(projections.join("unclassified"), [5_u8]).unwrap();
    fs::write(projections.join(".redb"), [6_u8]).unwrap();
    let active = projections.join("projection-0.redb");
    let previous = projections.join("projection-1.redb");
    cache.retain_projections(&active, Some(&previous)).unwrap();
    let retained = fs::read_dir(&projections).unwrap().count();
    assert_eq!(retained, 2);
    assert!(active.exists());
    assert!(previous.exists());
    assert!(!projections.join("projection-2.redb").exists());
    assert!(!projections.join("crash.tmp").exists());
    assert!(!projections.join("unclassified").exists());
    assert!(!projections.join(".redb").exists());
}

#[test]
fn projection_retention_does_not_delete_other_source_namespaces() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let projections = cache.directory.join(PROJECTION_DIRECTORY);
    let current = projections.join("current").join("current.redb");
    fs::create_dir_all(current.parent().unwrap()).unwrap();
    fs::write(&current, b"current").unwrap();
    let auxiliary = projections.join("auxiliary").join("a".repeat(64));
    fs::create_dir_all(&auxiliary).unwrap();
    let active = auxiliary.join("active.redb");
    let previous = auxiliary.join("previous.redb");
    fs::write(&active, b"active").unwrap();
    fs::write(&previous, b"previous").unwrap();

    cache.retain_projections(&active, Some(&previous)).unwrap();

    assert!(current.exists());
    assert!(active.exists());
    assert!(previous.exists());
}

#[cfg(unix)]
#[test]
fn projection_namespace_rejects_symlink_parent() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let outside = tempdir().unwrap();
    let namespace = cache.directory.join(PROJECTION_DIRECTORY).join("current");
    std::os::unix::fs::symlink(outside.path(), &namespace).unwrap();
    let error = cache
        .prepare_projection_path(ProjectionNamespace::Current, &key(&store))
        .expect_err("a symlink namespace must fail closed");
    assert!(error.to_string().contains("namespace"));
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn projection_retention_is_scoped_to_one_raw_cache_key() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let current = cache.projection_namespace_path(ProjectionNamespace::Current);
    let first = current.join("a".repeat(64));
    let second = current.join("b".repeat(64));
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    let active = first.join("active.redb");
    let orphan = first.join("orphan.tmp");
    let other_key = second.join("other.redb");
    fs::write(&active, b"active").unwrap();
    fs::write(&orphan, b"orphan").unwrap();
    fs::write(&other_key, b"other").unwrap();

    cache
        .retain_projection_namespace(ProjectionNamespace::Current, &active, None)
        .unwrap();

    assert!(active.exists());
    assert!(!orphan.exists());
    assert!(other_key.exists());
}

#[test]
fn projection_retention_rejects_previous_outside_parent_before_matching_basename() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let projections = cache.projection_namespace_path(ProjectionNamespace::Current);
    let key_directory = projections.join("f".repeat(64));
    fs::create_dir_all(&key_directory).unwrap();
    let active = key_directory.join("active.redb");
    let inside_same_name = key_directory.join("previous.redb");
    fs::write(&active, b"active").unwrap();
    fs::write(&inside_same_name, b"inside").unwrap();
    let outside = tempdir().unwrap();
    let outside_previous = outside.path().join("previous.redb");
    fs::write(&outside_previous, b"outside").unwrap();

    let error = cache
        .retain_projection_namespace(
            ProjectionNamespace::Current,
            &active,
            Some(&outside_previous),
        )
        .expect_err("previous projection outside the target directory must fail closed");
    assert!(error.to_string().contains("direct children"));
    assert!(inside_same_name.exists());
}

#[cfg(unix)]
#[test]
fn projection_retention_removes_non_utf8_redb_orphans() {
    use std::os::unix::ffi::OsStrExt;

    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let namespace = cache.projection_namespace_path(ProjectionNamespace::Current);
    let key_directory = namespace.join("7".repeat(64));
    fs::create_dir_all(&key_directory).unwrap();
    let active = key_directory.join("active.redb");
    let orphan = key_directory.join(std::ffi::OsStr::from_bytes(b"orphan-\xff.redb"));
    fs::write(&active, b"active").unwrap();
    fs::write(&orphan, b"orphan").unwrap();

    cache
        .retain_projection_namespace(ProjectionNamespace::Current, &active, None)
        .unwrap();

    assert!(active.exists());
    assert!(!orphan.exists());
}

#[cfg(unix)]
#[test]
fn projection_retention_rejects_symlinked_raw_key_directory() {
    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let outside = tempdir().unwrap();
    let outside_active = outside.path().join("active.redb");
    let outside_orphan = outside.path().join("orphan.redb");
    fs::write(&outside_active, b"active").unwrap();
    fs::write(&outside_orphan, b"orphan").unwrap();

    let namespace = cache.projection_namespace_path(ProjectionNamespace::Current);
    let key_directory = namespace.join("c".repeat(64));
    std::fs::create_dir_all(&namespace).unwrap();
    std::os::unix::fs::symlink(outside.path(), &key_directory).unwrap();
    let active = key_directory.join("active.redb");
    let error = cache
        .retain_projection_namespace(ProjectionNamespace::Current, &active, None)
        .expect_err("a symlinked raw-key directory must fail closed");
    assert!(error.to_string().contains("raw-key directory"));
    assert!(outside_orphan.exists());
}

#[cfg(unix)]
#[test]
fn projection_retention_keeps_deletion_on_open_directory_after_path_swap() {
    use std::os::unix::fs::symlink;

    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let namespace = cache.projection_namespace_path(ProjectionNamespace::Current);
    let key_directory = namespace.join("d".repeat(64));
    fs::create_dir_all(&key_directory).unwrap();
    let active = key_directory.join("active.redb");
    let orphan = key_directory.join("orphan.redb");
    fs::write(&active, b"active").unwrap();
    fs::write(&orphan, b"orphan").unwrap();

    let outside = tempdir().unwrap();
    let outside_active = outside.path().join("active.redb");
    let outside_orphan = outside.path().join("orphan.redb");
    fs::write(&outside_active, b"outside-active").unwrap();
    fs::write(&outside_orphan, b"outside-orphan").unwrap();
    let moved_directory = namespace.join("moved-key-directory");
    let hook_directory = key_directory.clone();
    let hook_moved_directory = moved_directory.clone();
    let hook_outside = outside.path().to_path_buf();
    set_retention_before_delete_hook(Some(Box::new(move |directory| {
        assert_eq!(directory, hook_directory);
        fs::rename(directory, &hook_moved_directory).unwrap();
        symlink(&hook_outside, directory).unwrap();
    })));

    cache
        .retain_projection_namespace(ProjectionNamespace::Current, &active, None)
        .unwrap();

    assert!(moved_directory.join("active.redb").exists());
    assert!(!moved_directory.join("orphan.redb").exists());
    assert!(outside_active.exists());
    assert!(outside_orphan.exists());
}

#[cfg(unix)]
#[test]
fn projection_retention_keeps_deletion_on_open_namespace_after_path_swap() {
    use std::os::unix::fs::symlink;

    let store = store();
    let cache = RawCache::open(&store).unwrap();
    let namespace = cache.projection_namespace_path(ProjectionNamespace::Current);
    let key_name = "e".repeat(64);
    let key_directory = namespace.join(&key_name);
    fs::create_dir_all(&key_directory).unwrap();
    let active = key_directory.join("active.redb");
    fs::write(&active, b"active").unwrap();

    let outside = tempdir().unwrap();
    let outside_key_directory = outside.path().join(&key_name);
    fs::create_dir(&outside_key_directory).unwrap();
    let outside_orphan = outside_key_directory.join("orphan.redb");
    fs::write(&outside_orphan, b"outside-orphan").unwrap();
    let moved_namespace = namespace.with_file_name("moved-current");
    let hook_namespace = namespace.clone();
    let hook_moved_namespace = moved_namespace.clone();
    let hook_outside = outside.path().to_path_buf();
    set_retention_before_delete_hook(Some(Box::new(move |directory| {
        assert_eq!(directory, key_directory);
        fs::rename(&hook_namespace, &hook_moved_namespace).unwrap();
        symlink(&hook_outside, &hook_namespace).unwrap();
    })));

    cache
        .retain_projection_namespace(ProjectionNamespace::Current, &active, None)
        .unwrap();

    assert!(moved_namespace.join(&key_name).join("active.redb").exists());
    assert!(outside_orphan.exists());
}
