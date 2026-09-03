use super::*;
use std::collections::HashSet;

#[test]
fn rejects_unsafe_entries_and_collisions() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        publish(
            root.path().join("view"),
            [TreeEntry::regular("../bad", vec![])]
        )
        .unwrap_err(),
        TreeError::UnsafePath
    );
    assert_eq!(
        publish(
            root.path().join("collision"),
            [
                TreeEntry::regular("A", vec![]),
                TreeEntry::regular("a", vec![])
            ]
        )
        .unwrap_err(),
        TreeError::PathCollision
    );
    for entries in [
        vec![
            TreeEntry::regular("a", vec![]),
            TreeEntry::regular("a/b", vec![]),
        ],
        vec![
            TreeEntry::regular("a/b", vec![]),
            TreeEntry::regular("a", vec![]),
        ],
    ] {
        assert_eq!(
            publish(root.path().join("prefix"), entries).unwrap_err(),
            TreeError::PathCollision
        );
    }
}

#[test]
fn partial_cleanup_bounds_cover_valid_tree_shape_without_unbounded_depth() {
    let worst_case_nodes = MAX_ENTRIES * (MAX_PATH_DEPTH + 1) + 2;
    assert!(MAX_CLEANUP_NODES >= worst_case_nodes);
    assert_eq!(MAX_CLEANUP_DEPTH, MAX_PATH_DEPTH + 2);
    assert!(MAX_CLEANUP_NODES.checked_add(1).is_some());
}

#[test]
fn byte_limit_allows_empty_entry_at_exact_limit_but_rejects_nonempty_entry() {
    let mut builder = TreeBuilder::new();
    builder.total = MAX_TOTAL_BYTES;
    assert_eq!(builder.add(TreeEntry::regular("empty", Vec::new())), Ok(()));
    assert_eq!(
        builder.add(TreeEntry::regular("nonempty", vec![1])),
        Err(TreeError::TotalLimit)
    );
}

#[test]
fn directory_sync_helper_is_platform_safe() {
    let root = tempfile::tempdir().unwrap();
    sync_directory(root.path()).unwrap();
}

#[test]
fn publishes_complete_marker_and_reuses_view() {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("view");
    let first = publish(
        &destination,
        [
            TreeEntry::regular("DESCRIPTION", b"Package: x\n".to_vec()),
            TreeEntry::regular("source.toml", b"tree payload\n".to_vec()),
        ],
    )
    .unwrap();
    let second = publish(&destination, std::iter::empty()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.path(), destination.join("tree").as_path());
    let root_names = fs::read_dir(&destination)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<HashSet<_>>();
    assert_eq!(root_names.len(), 2);
    assert!(root_names.contains(std::ffi::OsStr::new("tree")));
    assert!(root_names.contains(std::ffi::OsStr::new("source.toml")));
    assert_eq!(
        fs::read(destination.join("tree/DESCRIPTION")).unwrap(),
        b"Package: x\n"
    );
    assert_eq!(
        fs::read(destination.join("tree/source.toml")).unwrap(),
        b"tree payload\n"
    );
}

#[test]
fn detects_tampered_marker_and_extra_or_missing_files() {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("view");
    publish(
        &destination,
        [TreeEntry::regular("DESCRIPTION", vec![1, 2, 3])],
    )
    .unwrap();
    fs::write(destination.join("source.toml"), "schema = 1\n").unwrap();
    assert!(matches!(
        publish(&destination, std::iter::empty()),
        Err(TreeError::InvalidMarker { .. })
    ));

    let destination = root.path().join("canonical-marker");
    publish(&destination, [TreeEntry::regular("DESCRIPTION", vec![1])]).unwrap();
    let marker = fs::read_to_string(destination.join("source.toml")).unwrap();
    let digest_start = marker.find("tree_digest = \"").unwrap() + "tree_digest = \"".len();
    let mut marker_bytes = marker.into_bytes();
    marker_bytes[digest_start] = b'A';
    fs::write(destination.join("source.toml"), marker_bytes).unwrap();
    assert!(matches!(
        publish(&destination, std::iter::empty()),
        Err(TreeError::InvalidMarker { .. })
    ));

    let destination = root.path().join("extra");
    publish(&destination, [TreeEntry::regular("DESCRIPTION", vec![1])]).unwrap();
    fs::write(destination.join("extra"), [2]).unwrap();
    assert!(matches!(
        publish(&destination, std::iter::empty()),
        Err(TreeError::InvalidMarker { .. })
    ));

    let destination = root.path().join("empty-dir");
    publish(&destination, [TreeEntry::regular("DESCRIPTION", vec![1])]).unwrap();
    fs::create_dir(destination.join("tree/empty")).unwrap();
    assert!(matches!(
        publish(&destination, std::iter::empty()),
        Err(TreeError::InvalidMarker { .. })
    ));

    let destination = root.path().join("large");
    publish(&destination, [TreeEntry::regular("DESCRIPTION", vec![1])]).unwrap();
    let large = File::create(destination.join("tree/large.bin")).unwrap();
    large.set_len(MAX_BLOB_BYTES + 1).unwrap();
    assert_eq!(
        publish(&destination, std::iter::empty()).unwrap_err(),
        TreeError::BlobLimit
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlink_in_final_view() {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("view");
    publish(&destination, [TreeEntry::regular("DESCRIPTION", vec![1])]).unwrap();
    std::os::unix::fs::symlink(root.path().join("missing"), destination.join("tree/link")).unwrap();
    assert!(matches!(
        publish(&destination, std::iter::empty()),
        Err(TreeError::InvalidMarker { .. })
    ));
}

#[test]
fn concurrent_publishers_converge_on_one_validated_view() {
    use std::sync::{Arc, Barrier};
    let root = tempfile::tempdir().unwrap();
    let destination = Arc::new(root.path().join("converged"));
    let binding = Arc::new(ViewBinding::new("fixture", &[("revision", "one")]).unwrap());
    let barrier = Arc::new(Barrier::new(4));
    let workers = (0..4)
        .map(|_| {
            let destination = Arc::clone(&destination);
            let binding = Arc::clone(&binding);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                publish_with_binding(
                    &*destination,
                    [TreeEntry::regular("DESCRIPTION", b"Package: x\n".to_vec())],
                    &binding,
                )
                .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let views = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert!(views.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(destination.join("source.toml").is_file());
    assert!(!root.path().join(".converged.partial").exists());
}

#[cfg(unix)]
#[test]
fn rejects_preexisting_lock_symlink() {
    let root = tempfile::tempdir().unwrap();
    let lock = root.path().join("lock");
    std::os::unix::fs::symlink(root.path().join("target"), &lock).unwrap();
    assert!(matches!(
        AdvisoryLock::acquire(&lock),
        Err(TreeError::InvalidMarker { .. })
    ));
}

#[test]
fn retries_regular_partial_but_keeps_symlink_partial() {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("retry");
    let partial = root.path().join(".retry.partial");
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("stale"), b"stale").unwrap();
    publish(&destination, [TreeEntry::regular("DESCRIPTION", vec![1])]).unwrap();
    assert!(!partial.exists());

    let destination = root.path().join("symlink");
    let partial = root.path().join(".symlink.partial");
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.path().join("target"), &partial).unwrap();
    #[cfg(unix)]
    assert!(matches!(
        publish(&destination, [TreeEntry::regular("DESCRIPTION", vec![1])]),
        Err(TreeError::InvalidMarker { .. })
    ));
}

#[test]
fn process_publishers_converge_on_one_validated_view() {
    if let Ok(destination) = std::env::var("RSOLVE_TREE_CHILD_DESTINATION") {
        let binding = ViewBinding::new("fixture", &[("revision", "one")]).unwrap();
        publish_with_binding(
            Path::new(&destination),
            [TreeEntry::regular("DESCRIPTION", b"Package: x\n".to_vec())],
            &binding,
        )
        .unwrap();
        return;
    }

    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("process-converged");
    let executable = std::env::current_exe().unwrap();
    let mut children = Vec::new();
    for _ in 0..4 {
        children.push(
            std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "source_control::tree::tests::process_publishers_converge_on_one_validated_view",
                    "--nocapture",
                ])
                .env("RSOLVE_TREE_CHILD_DESTINATION", &destination)
                .spawn()
                .unwrap(),
        );
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    assert!(destination.join("source.toml").is_file());
    assert!(!root.path().join(".process-converged.partial").exists());
}
