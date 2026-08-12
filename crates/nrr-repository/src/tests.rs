use crate::*;
use flate2::{Compression, write::GzEncoder};
use md5::{Digest as Md5Digest, Md5};
use nrr_core::{
    BioconductorRelease, PackageName, PackageNamespace, Provenance, RPackageVersion,
    ReleaseIdentity, UpstreamChecksum,
};
use sha2::Sha256;
use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::Cursor;
use std::io::Write;
use tar::{Builder, Header};

fn temporary_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "nrr-repository-{label}-{}-{}",
        std::process::id(),
        unique_nonce()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn artifact(checksums: Vec<UpstreamChecksum>, size: Option<u64>) -> SourceArtifact {
    SourceArtifact {
        locator: nrr_core::ArtifactLocator::new("fixture://source/example").unwrap(),
        upstream_checksums: checksums,
        size,
    }
}

fn md5(bytes: &[u8]) -> String {
    hex_lower(&Md5::digest(bytes))
}

fn archive_bytes() -> Vec<u8> {
    archive_bytes_with("fixture source\n", "example/DESCRIPTION")
}

fn archive_bytes_with(contents: &str, name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    let encoder = GzEncoder::new(&mut encoded, Compression::default());
    let mut builder = Builder::new(encoder);
    let contents = contents.as_bytes();
    let mut header = Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, name, contents).unwrap();
    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap();
    encoded
}

fn empty_archive_bytes() -> Vec<u8> {
    let mut encoded = Vec::new();
    let encoder = GzEncoder::new(&mut encoded, Compression::default());
    Builder::new(encoder)
        .into_inner()
        .unwrap()
        .finish()
        .unwrap();
    encoded
}

fn registry_selected(
    package: &str,
    version: &str,
    cached: CachedArtifact,
) -> MaterializationArtifact {
    let version = RPackageVersion::parse(version).unwrap();
    MaterializationArtifact::new(
        ReleaseIdentity::new(
            PackageName::new(package).unwrap(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        ),
        version,
        cached,
    )
}

#[test]
fn rejects_provenance_version_mismatches() {
    let cache_root = temporary_root("materialize-version-mismatch-cache");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let selected_version = RPackageVersion::parse("2.0.0").unwrap();
    let provenance_version = RPackageVersion::parse("1.0.0").unwrap();
    let identities = [
        (
            "registry",
            PackageName::new("registrypkg").unwrap(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: provenance_version.clone(),
            },
        ),
        (
            "bioconductor",
            PackageName::new("biocpkg").unwrap(),
            Provenance::BioconductorRelease {
                namespace: PackageNamespace::new("bioc").unwrap(),
                release: BioconductorRelease::new("3.20").unwrap(),
                version: provenance_version.clone(),
            },
        ),
        (
            "r-base",
            PackageName::new("R").unwrap(),
            Provenance::RBasePackage {
                r_version: provenance_version,
            },
        ),
    ];
    for (label, package, provenance) in identities {
        let project_root = temporary_root(&format!("materialize-version-mismatch-{label}"));
        let selected = MaterializationArtifact::new(
            ReleaseIdentity::new(package, provenance),
            selected_version.clone(),
            cached.clone(),
        );
        assert!(matches!(
            materialize(MaterializationRequest::new(
                &project_root,
                std::slice::from_ref(&selected),
            )),
            Err(MaterializationError::ProvenanceVersionMismatch { .. })
        ));
        fs::remove_dir_all(project_root).unwrap();
    }
    fs::remove_dir_all(cache_root).unwrap();
}

#[test]
fn canonicalizes_set_order_for_state_and_reruns() {
    let cache_root = temporary_root("materialize-order-cache");
    let first_project = temporary_root("materialize-order-first");
    let second_project = temporary_root("materialize-order-second");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let alpha = registry_selected("alpha", "1.0.0", cached.clone());
    let zeta = registry_selected("zeta", "2.0.0", cached);
    let reverse = [zeta.clone(), alpha.clone()];
    let forward = [alpha, zeta];

    let reverse_state = materialize(MaterializationRequest::new(&first_project, &reverse)).unwrap();
    let forward_state =
        materialize(MaterializationRequest::new(&second_project, &forward)).unwrap();
    assert_eq!(reverse_state, forward_state);
    assert_eq!(
        fs::read(first_project.join(".nrr/materialization.toml")).unwrap(),
        fs::read(second_project.join(".nrr/materialization.toml")).unwrap()
    );

    let rerun = materialize(MaterializationRequest::new(&first_project, &forward)).unwrap();
    assert_eq!(rerun, reverse_state);

    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(first_project).unwrap();
    fs::remove_dir_all(second_project).unwrap();
}

#[test]
fn materializes_with_local_gitignore_state_and_independent_bytes() {
    let cache_root = temporary_root("materialize-cache");
    let project_root = temporary_root("materialize-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes.clone()),
    )
    .unwrap();
    let version = RPackageVersion::parse("1.2-3").unwrap();
    let identity = ReleaseIdentity::new(
        PackageName::new("example").unwrap(),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version.clone(),
        },
    );
    let selected = MaterializationArtifact::new(identity, version, cached.clone());
    let state = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();
    assert_eq!(
        fs::read(project_root.join(".nrr/.gitignore")).unwrap(),
        b"*\n"
    );
    assert_eq!(state.records().len(), 1);
    assert!(matches!(
        state.records()[0].method,
        MaterializationMethod::Clone | MaterializationMethod::Copy
    ));
    let destination = project_root.join(".nrr/repository/src/contrib/example_1.2-3.tar.gz");
    assert_eq!(fs::read(&destination).unwrap(), bytes);
    let rerun = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ))
    .unwrap();
    assert_eq!(rerun, state);

    let mut output = OpenOptions::new().write(true).open(&destination).unwrap();
    output.write_all(b"changed project view").unwrap();
    assert_eq!(fs::read(cached.path()).unwrap(), archive_bytes());

    let rerun = materialize(MaterializationRequest::new(
        &project_root,
        std::slice::from_ref(&selected),
    ));
    assert!(matches!(
        rerun,
        Err(MaterializationError::ExistingConflict { .. })
    ));
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

#[test]
fn materialization_rejects_duplicate_packages_and_existing_repository() {
    let cache_root = temporary_root("materialize-duplicate-cache");
    let project_root = temporary_root("materialize-duplicate-project");
    let bytes = archive_bytes();
    let cached = commit_source_artifact(
        &cache_root,
        &artifact(vec![], Some(bytes.len() as u64)),
        Cursor::new(bytes),
    )
    .unwrap();
    let package = PackageName::new("example").unwrap();
    let first_version = RPackageVersion::parse("1.0.0").unwrap();
    let second_version = RPackageVersion::parse("2.0.0").unwrap();
    let first = MaterializationArtifact::new(
        ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: first_version.clone(),
            },
        ),
        first_version,
        cached.clone(),
    );
    let second = MaterializationArtifact::new(
        ReleaseIdentity::new(
            package,
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: second_version.clone(),
            },
        ),
        second_version,
        cached,
    );
    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            &[first.clone(), second],
        )),
        Err(MaterializationError::DuplicatePackage { .. })
    ));
    fs::create_dir_all(project_root.join(".nrr/repository")).unwrap();
    assert!(matches!(
        materialize(MaterializationRequest::new(
            &project_root,
            std::slice::from_ref(&first),
        )),
        Err(MaterializationError::ExistingConflict { .. })
    ));
    fs::remove_dir_all(cache_root).unwrap();
    fs::remove_dir_all(project_root).unwrap();
}

fn contains_file_named(root: &Path, suffix: &str) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if path.is_dir() {
            contains_file_named(&path, suffix)
        } else {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(suffix))
        }
    })
}

fn contains_file_prefix(root: &Path, prefix: &str) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if path.is_dir() {
            contains_file_prefix(&path, prefix)
        } else {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
        }
    })
}

#[test]
fn commits_and_reuses_without_reading_a_hit_stream() {
    let root = temporary_root("hit");
    let bytes = archive_bytes();
    let artifact = artifact(
        vec![UpstreamChecksum::Md5(md5(&bytes).into())],
        Some(bytes.len() as u64),
    );
    let first = commit_source_artifact(&root, &artifact, Cursor::new(bytes.clone())).unwrap();
    let reads = Cell::new(false);
    let mut reader = TrackingReader { reads: &reads };
    let second = commit_artifact(ArtifactCommitRequest {
        cache_root: &root,
        artifact: &artifact,
        reader: &mut reader,
    })
    .unwrap();
    assert_eq!(first, second);
    assert!(!reads.get());
    assert!(
        fs::metadata(&first.object_path)
            .unwrap()
            .permissions()
            .readonly()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_mismatches_and_does_not_commit_metadata() {
    for (label, checksums, size) in [
        (
            "md5",
            vec![UpstreamChecksum::Md5(
                "00000000000000000000000000000000".into(),
            )],
            None,
        ),
        (
            "sha256",
            vec![UpstreamChecksum::Sha256(
                Sha256Digest::new("0".repeat(64)).unwrap(),
            )],
            None,
        ),
        ("size", vec![], Some(99)),
    ] {
        let root = temporary_root(label);
        let descriptor = artifact(checksums, size);
        let error =
            commit_source_artifact(&root, &descriptor, Cursor::new(archive_bytes())).unwrap_err();
        assert!(matches!(
            error,
            CacheError::ChecksumMismatch { .. } | CacheError::SizeMismatch { .. }
        ));
        assert!(!contains_file_named(&root.join("artifacts"), ".json"));
        assert!(!contains_file_prefix(
            &root.join("objects/sources/sha256"),
            PARTIAL_PREFIX
        ));
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn rejects_malformed_and_unsupported_checksums() {
    let root = temporary_root("checksum");
    let malformed = artifact(vec![UpstreamChecksum::Md5("bad".into())], None);
    assert!(matches!(
        commit_source_artifact(&root, &malformed, Cursor::new(archive_bytes())),
        Err(CacheError::MalformedChecksum { .. })
    ));
    let unsupported = artifact(
        vec![UpstreamChecksum::Other {
            algorithm: "sha1".into(),
            value: "anything".into(),
        }],
        None,
    );
    assert!(matches!(
        commit_source_artifact(&root, &unsupported, Cursor::new(archive_bytes())),
        Err(CacheError::UnsupportedChecksum { .. })
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepts_case_insensitive_duplicate_md5_declarations() {
    let root = temporary_root("md5-case");
    let bytes = archive_bytes();
    let digest = md5(&bytes);
    let descriptor = artifact(
        vec![
            UpstreamChecksum::Md5(digest.to_ascii_uppercase().into()),
            UpstreamChecksum::Md5(digest.into()),
        ],
        Some(bytes.len() as u64),
    );
    assert!(commit_source_artifact(&root, &descriptor, Cursor::new(bytes)).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_invalid_and_empty_archives() {
    let root = temporary_root("archive-shape");
    let descriptor = artifact(vec![], None);
    for bytes in [b"not gzip".to_vec(), empty_archive_bytes()] {
        assert!(matches!(
            commit_source_artifact(&root, &descriptor, Cursor::new(bytes)),
            Err(CacheError::InvalidArchive { .. })
        ));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn hit_revalidates_upstream_sha_when_metadata_points_to_another_object() {
    let root = temporary_root("tampered-metadata");
    let first_bytes = archive_bytes();
    let first_sha = Sha256::digest(&first_bytes);
    let first = artifact(
        vec![UpstreamChecksum::Sha256(
            Sha256Digest::new(hex_lower(&first_sha)).unwrap(),
        )],
        Some(first_bytes.len() as u64),
    );
    let committed =
        commit_source_artifact(&root, &first, Cursor::new(first_bytes.clone())).unwrap();
    let other_bytes = archive_bytes_with("different fixture\n", "other/DESCRIPTION");
    let other =
        commit_source_artifact(&root, &artifact(vec![], None), Cursor::new(other_bytes)).unwrap();
    let mut metadata = fs::read_to_string(&committed.metadata_path).unwrap();
    metadata = metadata.replace(
        &format!("\"object_sha256\": \"{}\"", committed.sha256.as_str()),
        &format!("\"object_sha256\": \"{}\"", other.sha256.as_str()),
    );
    fs::write(&committed.metadata_path, metadata).unwrap();
    let reads = Cell::new(false);
    let mut reader = TrackingReader { reads: &reads };
    let error = commit_artifact(ArtifactCommitRequest {
        cache_root: &root,
        artifact: &first,
        reader: &mut reader,
    })
    .unwrap_err();
    assert!(matches!(error, CacheError::ChecksumMismatch { .. }));
    assert!(!reads.get());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovers_from_an_unrelated_stale_partial() {
    let root = temporary_root("stale");
    let descriptor = artifact(vec![], None);
    let key = descriptor_key(
        &descriptor,
        &Checksums {
            md5: None,
            sha256: None,
        },
    );
    let paths = CachePaths::new(&root, &key);
    create_cache_directories(&paths).unwrap();
    fs::write(paths.object_dir.join(".partial.dead-process"), b"stale").unwrap();
    let bytes = archive_bytes();
    let result = commit_source_artifact(&root, &descriptor, Cursor::new(bytes.clone()));
    assert!(result.is_ok());
    assert!(paths.object_dir.join(".partial.dead-process").exists());
    let committed = result.unwrap();
    fs::remove_file(&committed.metadata_path).unwrap();
    let repaired = commit_source_artifact(&root, &descriptor, Cursor::new(bytes)).unwrap();
    assert_eq!(committed.object_path, repaired.object_path);
    assert!(repaired.metadata_path.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn metadata_is_strict_json_and_rejects_unknown_fields() {
    let root = temporary_root("strict-metadata");
    let descriptor = artifact(vec![], None);
    let bytes = archive_bytes();
    let committed = commit_source_artifact(&root, &descriptor, Cursor::new(bytes.clone())).unwrap();
    let mut metadata = fs::read_to_string(&committed.metadata_path).unwrap();
    let end = metadata.rfind('}').unwrap();
    metadata.insert_str(end, ",\n  \"unexpected\": true\n");
    fs::write(&committed.metadata_path, metadata).unwrap();
    let error = commit_source_artifact(&root, &descriptor, Cursor::new(bytes)).unwrap_err();
    assert!(matches!(error, CacheError::InvalidMetadata { .. }));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn hit_rejects_tampered_metadata_size_before_returning_a_handle() {
    let root = temporary_root("tampered-size");
    let bytes = archive_bytes();
    let digest = Sha256::digest(&bytes);
    let descriptor = artifact(
        vec![UpstreamChecksum::Sha256(
            Sha256Digest::new(hex_lower(&digest)).unwrap(),
        )],
        Some(bytes.len() as u64),
    );
    let committed = commit_source_artifact(&root, &descriptor, Cursor::new(bytes.clone())).unwrap();
    let mut metadata = fs::read_to_string(&committed.metadata_path).unwrap();
    metadata = metadata.replace(
        &format!("\"size\": {}", bytes.len()),
        &format!("\"size\": {}", bytes.len() + 1),
    );
    fs::write(&committed.metadata_path, metadata).unwrap();
    let reads = Cell::new(false);
    let mut reader = TrackingReader { reads: &reads };
    let error = commit_artifact(ArtifactCommitRequest {
        cache_root: &root,
        artifact: &descriptor,
        reader: &mut reader,
    })
    .unwrap_err();
    assert!(matches!(error, CacheError::InvalidMetadata { .. }));
    assert!(!reads.get());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bounded_copy_checks_exact_boundary_and_stops_on_first_excess_byte() {
    for (input, expected, result, written, reads) in [
        (b"abc".as_slice(), Some(3), Ok(3), b"abc".as_slice(), 2),
        (
            b"abcd".as_slice(),
            Some(3),
            Err(CacheError::SizeMismatch {
                expected: 3,
                actual: 4,
            }),
            b"abcd".as_slice(),
            2,
        ),
        (
            b"ab".as_slice(),
            Some(3),
            Err(CacheError::SizeMismatch {
                expected: 3,
                actual: 2,
            }),
            b"ab".as_slice(),
            2,
        ),
    ] {
        let mut reader = CountingReader::new(input);
        let mut output = Vec::new();
        let mut sha256 = Sha256::new();
        let mut md5 = Md5::new();
        let actual = copy_compressed_input(
            &mut reader,
            &mut output,
            expected,
            3,
            Path::new("test-partial"),
            &mut sha256,
            &mut md5,
        );
        match result {
            Ok(size) => assert_eq!(actual.unwrap(), size),
            Err(expected_error) => {
                assert_eq!(actual.unwrap_err().to_string(), expected_error.to_string())
            }
        }
        assert_eq!(output, written);
        assert_eq!(reader.reads.get(), reads);
    }
}

#[test]
fn bounded_copy_reports_unbounded_limit_and_handles_u64_max_without_overflow() {
    let mut reader = CountingReader::new(b"abcd");
    let mut output = Vec::new();
    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    let error = copy_compressed_input(
        &mut reader,
        &mut output,
        None,
        3,
        Path::new("test-partial"),
        &mut sha256,
        &mut md5,
    )
    .unwrap_err();
    assert!(matches!(error, CacheError::InputTooLarge { limit: 3 }));
    assert_eq!(output, b"abcd");
    assert_eq!(reader.reads.get(), 2);

    let mut reader = CountingReader::new(b"");
    let mut output = Vec::new();
    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    let error = copy_compressed_input(
        &mut reader,
        &mut output,
        Some(u64::MAX),
        3,
        Path::new("test-partial"),
        &mut sha256,
        &mut md5,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CacheError::SizeMismatch {
            expected: u64::MAX,
            actual: 0
        }
    ));
}

#[test]
fn bounded_expected_input_does_not_commit_or_read_past_first_excess_byte() {
    let root = temporary_root("bounded-input");
    let bytes = archive_bytes();
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    let mut input = bytes.clone();
    input.extend_from_slice(b"excess");
    let mut reader = CountingReader::new(&input);
    let error = commit_artifact(ArtifactCommitRequest {
        cache_root: &root,
        artifact: &descriptor,
        reader: &mut reader,
    })
    .unwrap_err();
    assert!(matches!(error, CacheError::SizeMismatch { .. }));
    assert_eq!(reader.reads.get(), 2);
    assert!(!contains_file_named(&root.join("artifacts"), ".json"));
    assert!(!contains_file_prefix(
        &root.join("objects/sources/sha256"),
        PARTIAL_PREFIX
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_replacement_restores_corrupt_object_and_cleans_partial() {
    let root = temporary_root("replacement-failure");
    let bytes = archive_bytes();
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    let key = descriptor_key(
        &descriptor,
        &Checksums {
            md5: None,
            sha256: None,
        },
    );
    let paths = CachePaths::new(&root, &key);
    create_cache_directories(&paths).unwrap();
    let digest = Sha256Digest::new(hex_lower(&Sha256::digest(&bytes))).unwrap();
    let object = paths.object(&digest);
    fs::create_dir_all(object.parent().unwrap()).unwrap();
    let old = b"old corrupt bytes";
    fs::write(&object, old).unwrap();
    let fs_ops = RenameFailureFs::new(2);
    let error = commit_artifact_with_fs(
        ArtifactCommitRequest {
            cache_root: &root,
            artifact: &descriptor,
            reader: &mut Cursor::new(bytes),
        },
        &fs_ops,
    )
    .unwrap_err();
    assert!(matches!(error, CacheError::Io { .. }));
    assert_eq!(fs::read(&object).unwrap(), old);
    assert!(!contains_file_prefix(&root, ".corrupt."));
    assert!(!contains_file_prefix(&root, PARTIAL_PREFIX));
    assert!(!paths.metadata.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_replacement_restore_retains_quarantine_and_cleans_partial() {
    let root = temporary_root("replacement-restore-failure");
    let bytes = archive_bytes();
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    let key = descriptor_key(
        &descriptor,
        &Checksums {
            md5: None,
            sha256: None,
        },
    );
    let paths = CachePaths::new(&root, &key);
    create_cache_directories(&paths).unwrap();
    let digest = Sha256Digest::new(hex_lower(&Sha256::digest(&bytes))).unwrap();
    let object = paths.object(&digest);
    fs::create_dir_all(object.parent().unwrap()).unwrap();
    let old = b"old corrupt bytes";
    fs::write(&object, old).unwrap();
    let fs_ops = RenameFailureFs::with_failures(2, 3);
    let error = commit_artifact_with_fs(
        ArtifactCommitRequest {
            cache_root: &root,
            artifact: &descriptor,
            reader: &mut Cursor::new(bytes),
        },
        &fs_ops,
    )
    .unwrap_err();
    let quarantine = match error {
        CacheError::ReplacementRecovery { quarantine, .. } => quarantine,
        other => panic!("unexpected error: {other:?}"),
    };
    assert!(!object.exists());
    assert_eq!(fs::read(&quarantine).unwrap(), old);
    assert!(!contains_file_prefix(&root, PARTIAL_PREFIX));
    assert!(!paths.metadata.exists());
    fs::remove_dir_all(root).unwrap();
}

struct CountingReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    reads: Cell<usize>,
}

impl CountingReader<'_> {
    fn new(bytes: &[u8]) -> CountingReader<'_> {
        CountingReader {
            bytes,
            offset: 0,
            reads: Cell::new(0),
        }
    }
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reads.set(self.reads.get() + 1);
        let available = self.bytes.len().saturating_sub(self.offset);
        let count = available.min(buffer.len());
        buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

struct RenameFailureFs {
    fail_at: [usize; 2],
    renames: Cell<usize>,
}

impl RenameFailureFs {
    fn new(fail_at: usize) -> Self {
        Self::with_failures(fail_at, usize::MAX)
    }

    fn with_failures(first: usize, second: usize) -> Self {
        Self {
            fail_at: [first, second],
            renames: Cell::new(0),
        }
    }
}

impl PublishFs for RenameFailureFs {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let count = self.renames.get() + 1;
        self.renames.set(count);
        if self.fail_at.contains(&count) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected rename failure",
            ));
        }
        fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
}

struct TrackingReader<'a> {
    reads: &'a Cell<bool>,
}

impl Read for TrackingReader<'_> {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        self.reads.set(true);
        panic!("cache hit consumed reader")
    }
}
