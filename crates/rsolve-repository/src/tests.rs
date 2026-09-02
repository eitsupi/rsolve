use crate::*;
use flate2::{Compression, write::GzEncoder};
use md5::{Digest as Md5Digest, Md5};
use rsolve_core::UpstreamChecksum;
use sha2::Sha256;
use std::cell::Cell;
use std::io::{self, Cursor, Read};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tar::{Builder, Header};

fn temporary_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "rsolve-repository-{label}-{}-{}",
        std::process::id(),
        unique_nonce()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn artifact(checksums: Vec<UpstreamChecksum>, size: Option<u64>) -> SourceArtifact {
    SourceArtifact {
        locator: rsolve_core::ArtifactLocator::new("fixture://source/example").unwrap(),
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
    archive_bytes_with_entries(&[(name, contents)])
}

fn archive_bytes_with_entries(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let encoder = GzEncoder::new(&mut encoded, Compression::default());
    let mut builder = Builder::new(encoder);
    for (name, contents) in entries {
        let contents = contents.as_bytes();
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, *name, contents).unwrap();
    }
    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap();
    encoded
}

fn identity_expectation(package_name: &str, version_text: &str) -> ArtifactValidationExpectation {
    ArtifactValidationExpectation::new(
        rsolve_core::PackageName::new(package_name).unwrap(),
        rsolve_core::RPackageVersion::parse(version_text).unwrap(),
    )
}

fn git_expectation(subdirectory: Option<&str>) -> ArtifactValidationExpectation {
    identity_expectation("example", "1.0").with_git_provenance(
        rsolve_core::NormalizedGitUrl::new("https://example.test/project").unwrap(),
        rsolve_core::GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        subdirectory.map(|value| rsolve_core::RepositorySubdir::new(value).unwrap()),
    )
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

fn contains_file_named(root: &Path, suffix: &str) -> bool {
    if !root.is_dir() {
        return false;
    }
    fs::read_dir(root).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        (path.is_file()
            && path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with(suffix))
            || (path.is_dir() && contains_file_named(&path, suffix))
    })
}

fn contains_file_prefix(root: &Path, prefix: &str) -> bool {
    if !root.is_dir() {
        return false;
    }
    fs::read_dir(root).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        (path.is_file()
            && path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(prefix))
            || (path.is_dir() && contains_file_prefix(&path, prefix))
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
fn identity_validated_registry_archive_can_be_probed_without_a_reader() {
    let root = temporary_root("identity-registry");
    let bytes = archive_bytes_with(
        "Package: example\nVersion: 1.0\nDescription: fixture\n",
        "example/DESCRIPTION",
    );
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    let expectation = identity_expectation("example", "1.0");
    let committed = commit_source_artifact_with_expectation(
        &root,
        &descriptor,
        &expectation,
        Cursor::new(bytes),
    )
    .unwrap();
    let probed = probe_artifact(&root, &descriptor, &expectation)
        .unwrap()
        .expect("validated cache hit");
    assert_eq!(probed, committed);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn equivalent_description_versions_share_validated_cache_identity() {
    let root = temporary_root("identity-version-alias");
    let bytes = archive_bytes_with(
        "Package: example\nVersion: 1.7-0\nDescription: fixture\n",
        "example/DESCRIPTION",
    );
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    let canonical_expectation = identity_expectation("example", "1.7.0");
    let committed = commit_source_artifact_with_expectation(
        &root,
        &descriptor,
        &canonical_expectation,
        Cursor::new(bytes.clone()),
    )
    .unwrap();

    let alias_expectation = identity_expectation("example", "1.7-0");
    let probed = probe_artifact(&root, &descriptor, &alias_expectation)
        .unwrap()
        .expect("equivalent version should reuse the validated cache entry");
    assert_eq!(probed, committed);

    let different_expectation = identity_expectation("example", "1.7.1");
    assert!(matches!(
        commit_source_artifact_with_expectation(
            &root,
            &descriptor,
            &different_expectation,
            Cursor::new(bytes),
        ),
        Err(CacheError::DescriptionFieldMismatch {
            field: "Version",
            ..
        })
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn identity_validated_git_archive_requires_matching_provenance() {
    let root = temporary_root("identity-git");
    let no_subdir = archive_bytes_with(
        "Package: example\nVersion: 1.0\nDescription: first\n second\nRemoteUrl: https://example.test/project\nRemoteSha: 0123456789ABCDEF0123456789ABCDEF01234567\n",
        "example/DESCRIPTION",
    );
    let descriptor = artifact(vec![], Some(no_subdir.len() as u64));
    let expectation = git_expectation(None);
    commit_source_artifact_with_expectation(
        &root,
        &descriptor,
        &expectation,
        Cursor::new(no_subdir),
    )
    .unwrap();

    let wrong_url = git_expectation(None).with_git_provenance(
        rsolve_core::NormalizedGitUrl::new("https://other.test/project").unwrap(),
        rsolve_core::GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        None,
    );
    assert!(matches!(
        probe_artifact(&root, &descriptor, &wrong_url),
        Ok(None)
    ));

    let with_subdir = archive_bytes_with(
        "Package: example\nVersion: 1.0\nRemoteUrl: https://example.test/project\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\nRemoteSubdir: packages/example\n",
        "example/DESCRIPTION",
    );
    let with_subdir_descriptor = artifact(vec![], Some(with_subdir.len() as u64));
    let with_subdir_expectation = git_expectation(Some("packages/example"));
    assert!(
        commit_source_artifact_with_expectation(
            &root,
            &with_subdir_descriptor,
            &with_subdir_expectation,
            Cursor::new(with_subdir),
        )
        .is_ok()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn git_description_without_subdir_accepts_comments_and_folded_unmodeled_fields() {
    let root = temporary_root("git-commented-description");
    let contents = "# leading comment\r\nPackage: example\r\n# comment between fields\r\nVersion: 1.0\r\nDescription: first # stays in the value\r\n second\r\nRemoteUrl: https://example.test/project\r\nRemoteSha: 0123456789ABCDEF0123456789ABCDEF01234567\r\n";
    let bytes = archive_bytes_with(contents, "example/DESCRIPTION");
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    commit_source_artifact_with_expectation(
        &root,
        &descriptor,
        &git_expectation(None),
        Cursor::new(bytes),
    )
    .unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn description_comments_preserve_modeled_field_continuations() {
    let root = temporary_root("comment-continuation");
    let contents = "Package: example\nVersion: 1.0\nRemoteUrl: https://example.test/project\n # continuation must remain part of RemoteUrl\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\n";
    let bytes = archive_bytes_with(contents, "example/DESCRIPTION");
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    assert!(matches!(
        commit_source_artifact_with_expectation(
            &root,
            &descriptor,
            &git_expectation(None),
            Cursor::new(bytes),
        ),
        Err(CacheError::DescriptionFieldMismatch {
            field: "RemoteUrl",
            ..
        })
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn description_inline_hash_is_preserved_in_modeled_fields() {
    let root = temporary_root("inline-hash");
    let contents = "Package: example\nVersion: 1.0\nRemoteUrl: https://example.test/project\nRemoteSha: 0123456789abcdef0123456789abcdef01234567#inline\n";
    let bytes = archive_bytes_with(contents, "example/DESCRIPTION");
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    assert!(matches!(
        commit_source_artifact_with_expectation(
            &root,
            &descriptor,
            &git_expectation(None),
            Cursor::new(bytes),
        ),
        Err(CacheError::DescriptionFieldMismatch {
            field: "RemoteSha",
            ..
        })
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn description_comment_does_not_reset_modeled_field_state() {
    let root = temporary_root("comment-state");
    let contents = "Package: example\nVersion: 1.0\nRemoteUrl: https://example.test/project\n# comment between field and continuation\n https://other.test/project\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\n";
    let bytes = archive_bytes_with(contents, "example/DESCRIPTION");
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    assert!(matches!(
        commit_source_artifact_with_expectation(
            &root,
            &descriptor,
            &git_expectation(None),
            Cursor::new(bytes),
        ),
        Err(CacheError::DescriptionFieldMismatch {
            field: "RemoteUrl",
            ..
        })
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn identity_validation_rejects_description_defects_before_publication() {
    let cases = [
        (
            "missing",
            archive_bytes_with("Package: example\nVersion: 1.0\n", "other/DESCRIPTION"),
        ),
        (
            "duplicate",
            archive_bytes_with_entries(&[
                ("example/DESCRIPTION", "Package: example\nVersion: 1.0\n"),
                ("example/DESCRIPTION", "Package: example\nVersion: 1.0\n"),
            ]),
        ),
        (
            "malformed",
            archive_bytes_with("not a DCF record\n", "example/DESCRIPTION"),
        ),
        (
            "package-mismatch",
            archive_bytes_with("Package: other\nVersion: 1.0\n", "example/DESCRIPTION"),
        ),
        (
            "version-mismatch",
            archive_bytes_with("Package: example\nVersion: 1.0.1\n", "example/DESCRIPTION"),
        ),
        (
            "unexpected-remote",
            archive_bytes_with(
                "Package: example\nVersion: 1.0\nRemoteSubdir: src\n",
                "example/DESCRIPTION",
            ),
        ),
    ];
    for (label, bytes) in cases {
        let root = temporary_root(label);
        let descriptor = artifact(vec![], Some(bytes.len() as u64));
        let expectation = identity_expectation("example", "1.0");
        let result = commit_source_artifact_with_expectation(
            &root,
            &descriptor,
            &expectation,
            Cursor::new(bytes),
        );
        assert!(
            matches!(
                result,
                Err(CacheError::MissingDescription)
                    | Err(CacheError::DuplicateDescription)
                    | Err(CacheError::MalformedDescription { .. })
                    | Err(CacheError::DescriptionFieldMismatch { .. })
            ),
            "unexpected result for {label}: {result:?}"
        );
        assert!(!contains_file_named(&root.join("artifacts"), ".json"));
        assert!(!contains_file_prefix(
            &root.join("objects/sources/sha256"),
            PARTIAL_PREFIX
        ));
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn identity_git_field_mismatches_are_rejected() {
    let cases = [
        (
            "remote-url",
            "Package: example\nVersion: 1.0\nRemoteUrl: https://other.test/project\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\n",
            git_expectation(None),
        ),
        (
            "remote-sha",
            "Package: example\nVersion: 1.0\nRemoteUrl: https://example.test/project\nRemoteSha: abcdef0123456789abcdef0123456789abcdef01\n",
            git_expectation(None),
        ),
        (
            "missing-subdir",
            "Package: example\nVersion: 1.0\nRemoteUrl: https://example.test/project\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\n",
            git_expectation(Some("packages/example")),
        ),
        (
            "wrong-subdir",
            "Package: example\nVersion: 1.0\nRemoteUrl: https://example.test/project\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\nRemoteSubdir: other\n",
            git_expectation(Some("packages/example")),
        ),
        (
            "unexpected-subdir",
            "Package: example\nVersion: 1.0\nRemoteUrl: https://example.test/project\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\nRemoteSubdir: packages/example\n",
            git_expectation(None),
        ),
        (
            "duplicate-field",
            "Package: example\npackage: example\nVersion: 1.0\nRemoteUrl: https://example.test/project\nRemoteSha: 0123456789abcdef0123456789abcdef01234567\n",
            git_expectation(None),
        ),
    ];
    for (label, contents, expectation) in cases {
        let root = temporary_root(label);
        let bytes = archive_bytes_with(contents, "example/DESCRIPTION");
        let descriptor = artifact(vec![], Some(bytes.len() as u64));
        assert!(matches!(
            commit_source_artifact_with_expectation(
                &root,
                &descriptor,
                &expectation,
                Cursor::new(bytes),
            ),
            Err(CacheError::DescriptionFieldMismatch { .. })
                | Err(CacheError::DuplicateDescriptionField { .. })
        ));
        assert!(!contains_file_named(&root.join("artifacts"), ".json"));
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn identity_probe_reports_misses_and_corrupt_hits_without_a_reader() {
    let root = temporary_root("identity-probe");
    let bytes = archive_bytes_with("Package: example\nVersion: 1.0\n", "example/DESCRIPTION");
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    let expectation = identity_expectation("example", "1.0");
    assert_eq!(
        probe_artifact(&root, &descriptor, &expectation).unwrap(),
        None
    );
    let committed = commit_source_artifact_with_expectation(
        &root,
        &descriptor,
        &expectation,
        Cursor::new(bytes),
    )
    .unwrap();
    let mut permissions = fs::metadata(&committed.object_path).unwrap().permissions();
    #[cfg(unix)]
    permissions.set_mode(permissions.mode() | 0o200);
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    fs::set_permissions(&committed.object_path, permissions).unwrap();
    fs::write(
        &committed.object_path,
        vec![b'x'; usize::try_from(committed.size).unwrap()],
    )
    .unwrap();
    assert!(matches!(
        probe_artifact(&root, &descriptor, &expectation),
        Err(CacheError::CorruptObject { .. })
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn identity_validation_rejects_an_oversized_description() {
    let root = temporary_root("identity-description-size");
    let contents = format!(
        "Package: example\nVersion: 1.0\nDescription: {}\n",
        "x".repeat(1 << 20)
    );
    let bytes = archive_bytes_with(&contents, "example/DESCRIPTION");
    let descriptor = artifact(vec![], Some(bytes.len() as u64));
    assert!(matches!(
        commit_source_artifact_with_expectation(
            &root,
            &descriptor,
            &identity_expectation("example", "1.0"),
            Cursor::new(bytes),
        ),
        Err(CacheError::DescriptionTooLarge { .. })
    ));
    assert!(!contains_file_named(&root.join("artifacts"), ".json"));
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
