use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::{Compression, write::GzEncoder};
use rsolve_core::{ArtifactLocator, SourceArtifact};
use rsolve_repository::commit_source_artifact;
use tar::{Builder, Header};

fn archive_bytes() -> Vec<u8> {
    let mut encoded = Vec::new();
    let encoder = GzEncoder::new(&mut encoded, Compression::default());
    let mut builder = Builder::new(encoder);
    let body = b"contention fixture\n";
    let mut header = Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "example/DESCRIPTION", &body[..])
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap();
    encoded
}

fn artifact() -> SourceArtifact {
    SourceArtifact {
        locator: ArtifactLocator::new("fixture://contention/example").unwrap(),
        upstream_checksums: Vec::new(),
        size: None,
    }
}

fn count_prefix(root: &Path, prefix: &str) -> usize {
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                count_prefix(&path, prefix)
            } else if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
            {
                1
            } else {
                0
            }
        })
        .sum()
}

fn count_suffix(root: &Path, suffix: &str) -> usize {
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                count_suffix(&path, suffix)
            } else if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(suffix))
            {
                1
            } else {
                0
            }
        })
        .sum()
}

#[test]
fn contention_parent() {
    if std::env::var_os("RSOLVE_CONTENTION_CHILD").is_some() {
        return;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("rsolve-contention-{nonce}"));
    let gate = root.join("start-gate");
    let ready_dir = root.join("ready");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&ready_dir).unwrap();
    let executable = std::env::current_exe().unwrap();
    let mut children = Vec::new();
    for id in 0..2 {
        children.push(
            Command::new(&executable)
                .arg("--exact")
                .arg("contention_child")
                .arg("--nocapture")
                .env("RSOLVE_CONTENTION_CHILD", "1")
                .env("RSOLVE_CONTENTION_ROOT", &root)
                .env("RSOLVE_CONTENTION_GATE", &gate)
                .env(
                    "RSOLVE_CONTENTION_READY",
                    ready_dir.join(format!("ready-{id}")),
                )
                .spawn()
                .unwrap(),
        );
    }
    for _ in 0..500 {
        if (0..2).all(|id| ready_dir.join(format!("ready-{id}")).exists()) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!((0..2).all(|id| ready_dir.join(format!("ready-{id}")).exists()));
    fs::write(&gate, b"go").unwrap();
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(count_suffix(&root.join("artifacts"), ".json"), 1);
    assert_eq!(count_prefix(&root.join("objects"), ".partial."), 0);
    let mut objects = Vec::new();
    collect_object_files(&root.join("objects/sources/sha256"), &mut objects);
    assert_eq!(objects.len(), 1);
    assert_eq!(fs::read(&objects[0]).unwrap(), archive_bytes());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn contention_child() {
    let (Some(root), Some(gate), Some(ready)) = (
        std::env::var_os("RSOLVE_CONTENTION_ROOT"),
        std::env::var_os("RSOLVE_CONTENTION_GATE"),
        std::env::var_os("RSOLVE_CONTENTION_READY"),
    ) else {
        return;
    };
    let gate = PathBuf::from(gate);
    let ready = PathBuf::from(ready);
    fs::write(&ready, b"ready").unwrap();
    for _ in 0..200 {
        if gate.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(gate.exists(), "contention parent did not open gate");
    commit_source_artifact(root, &artifact(), Cursor::new(archive_bytes())).unwrap();
}

fn collect_object_files(root: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_object_files(&path, files);
        } else if !path.file_name().unwrap().to_string_lossy().starts_with('.') {
            files.push(path);
        }
    }
}
