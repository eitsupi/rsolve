use super::*;
use crate::cran::provider::raw_cache::RawCacheRepresentation;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

#[derive(Clone)]
pub(in crate::cran::provider::tests) struct FileCountingTransport {
    pub(in crate::cran::provider::tests) inner: FixtureTransport,
    pub(in crate::cran::provider::tests) counter: PathBuf,
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

pub(in crate::cran::provider::tests) fn wait_for_child_file(path: &Path) {
    for _ in 0..500 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("child did not create {} within timeout", path.display());
}

pub(in crate::cran::provider::tests) fn wait_for_child(
    mut child: Child,
) -> std::process::ExitStatus {
    for _ in 0..500 {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    panic!("child did not finish within timeout");
}

pub(in crate::cran::provider::tests) fn spawn_persistent_child(root: &Path, mode: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("cran::provider::tests::current::persistent_refresh::persistent_refresh_child_probe")
        .arg("--nocapture")
        .env("RSOLVE_PERSISTENT_CHILD_ROOT", root)
        .env("RSOLVE_PERSISTENT_CHILD_MODE", mode)
        .spawn()
        .unwrap()
}

pub(in crate::cran::provider::tests) fn seed_previous_projection(root: &Path) -> PathBuf {
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

pub(in crate::cran::provider::tests) fn append_counter(root: &Path, name: &str) {
    let path = root.join(name);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(file, "event").unwrap();
}

pub(in crate::cran::provider::tests) fn projection_files(root: &Path) -> Vec<PathBuf> {
    let directory = root.join("raw-cache/v1/projections");
    std::fs::read_dir(directory)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("redb"))
        .collect()
}
