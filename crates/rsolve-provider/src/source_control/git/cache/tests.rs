use super::*;
use crate::source_control::git::{GitCommand, GitCommandOutput, GitRunnerError};
use std::cell::RefCell;
use std::process::Command;
use std::sync::{Arc, Mutex};

struct FixtureRunner {
    outputs: RefCell<Vec<GitCommandOutput>>,
    commands: Arc<Mutex<Vec<Vec<std::ffi::OsString>>>>,
    limits: Arc<Mutex<Vec<usize>>>,
}

impl GitCommandRunner for FixtureRunner {
    fn run(&self, command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError> {
        self.commands.lock().unwrap().push(command.args().to_vec());
        self.limits.lock().unwrap().push(command.output_limit());
        Ok(self.outputs.borrow_mut().remove(0))
    }
}

struct OverflowRunner {
    responses: RefCell<Vec<Result<GitCommandOutput, GitRunnerError>>>,
}

impl GitCommandRunner for OverflowRunner {
    fn run(&self, _command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError> {
        self.responses.borrow_mut().remove(0)
    }
}

fn fixture(outputs: Vec<GitCommandOutput>) -> FixtureRunner {
    FixtureRunner {
        outputs: RefCell::new(outputs),
        commands: Arc::new(Mutex::new(Vec::new())),
        limits: Arc::new(Mutex::new(Vec::new())),
    }
}

fn output(stdout: &str) -> GitCommandOutput {
    GitCommandOutput {
        status: Some(0),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    }
}

fn bytes(stdout: Vec<u8>) -> GitCommandOutput {
    GitCommandOutput {
        status: Some(0),
        stdout,
        stderr: Vec::new(),
    }
}

fn online_fixture(commit: &str, mode: &str, path: &str, blob: Vec<u8>) -> FixtureRunner {
    fixture(vec![
        output(""),
        output(""),
        output("commit\n"),
        output("fedcba9876543210fedcba9876543210fedcba98\n"),
        output(&format!("{mode} blob {commit}\t{path}\0")),
        bytes(blob),
    ])
}

fn failed_output(stderr: &str) -> GitCommandOutput {
    GitCommandOutput {
        status: Some(1),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[test]
fn blob_output_overflow_distinguishes_total_and_single_blob_limits() {
    assert_eq!(
        blob_overflow_error(super::super::MAX_BLOB_OUTPUT_BYTES as u64 - 1),
        TreeError::TotalLimit
    );
    assert_eq!(
        blob_overflow_error(super::super::MAX_BLOB_OUTPUT_BYTES as u64),
        TreeError::BlobLimit
    );
}

#[test]
fn origin_partial_is_retried_atomically_and_symlink_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let origin = root.path().join("origin.toml");
    let partial = root.path().join(".origin.toml.partial");
    let url = rsolve_core::NormalizedGitUrl::new("https://origin-retry.example/repo").unwrap();
    let expected = format!("schema = 1\nurl = \"{url}\"\nalgorithm = \"sha1\"\n");
    std::fs::write(&partial, b"interrupted write").unwrap();
    write_origin(&origin, &url, GitHashAlgorithm::Sha1, false).unwrap();
    assert_eq!(std::fs::read_to_string(&origin).unwrap(), expected);
    assert!(!partial.exists());

    std::fs::remove_file(&origin).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.path().join("outside"), &partial).unwrap();
        assert!(matches!(
            write_origin(&origin, &url, GitHashAlgorithm::Sha1, false),
            Err(GitCacheError::InvalidMetadata)
        ));
        assert!(
            std::fs::symlink_metadata(&partial)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}

#[test]
fn online_builds_source_view_then_offline_reuses_complete_view() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let runner = fixture(vec![
        output(""),
        output(""),
        output("commit\n"),
        output("fedcba9876543210fedcba9876543210fedcba98\n"),
        output(&format!("100644 blob {commit}\tDESCRIPTION\0")),
        output("Package: fixture\n"),
        output("commit\n"),
        output("fedcba9876543210fedcba9876543210fedcba98\n"),
        output("commit\n"),
        output("0123456789abcdef0123456789abcdef01234567\n"),
    ]);
    let backend = Backend::new("git", runner);
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://first.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(GitCommitId::new(commit).unwrap()),
        repository_dir: root.path().join("ignored.git"),
        offline: false,
    };
    let source = acquire(&backend, root.path(), &request, None).unwrap();
    assert!(source.view().path().join("DESCRIPTION").exists());
    let mut offline = request.clone();
    offline.offline = true;
    let cached = acquire(&backend, root.path(), &offline, None).unwrap();
    assert_eq!(source.view().tree_digest(), cached.view().tree_digest());
    let marker_path = source.view().path().join("../source.toml");
    let marker = std::fs::read_to_string(&marker_path).unwrap();
    assert!(marker.contains("binding.tree_oid"));
    std::fs::write(
        &marker_path,
        marker.replace(
            "binding.tree_oid = \"fedcba9876543210fedcba9876543210fedcba98\"",
            "binding.tree_oid = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
        ),
    )
    .unwrap();
    assert!(matches!(
        acquire(&backend, root.path(), &offline, None),
        Err(GitCacheError::Tree(TreeError::InvalidMarker { .. }))
    ));
    assert!(
        root.path()
            .join("rsolve/vcs-v1/git/repositories")
            .read_dir()
            .unwrap()
            .next()
            .is_some()
    );
}

#[test]
fn offline_missing_view_is_typed_without_tree_read() {
    let commit = GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap();
    let runner = fixture(vec![output("commit\n")]);
    let backend = Backend::new("git", runner);
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://second.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(commit),
        repository_dir: root.path().join("ignored.git"),
        offline: true,
    };
    let url_key = key("repository", request.url.as_str().as_bytes());
    let repository_root = root
        .path()
        .join("rsolve/vcs-v1/git/repositories")
        .join(url_key);
    std::fs::create_dir_all(&repository_root).unwrap();
    std::fs::write(
        repository_root.join("origin.toml"),
        format!(
            "schema = 1\nurl = \"{}\"\nalgorithm = \"sha1\"\n",
            request.url
        ),
    )
    .unwrap();
    assert!(matches!(
        acquire(&backend, root.path(), &request, None),
        Err(GitCacheError::OfflineSourceViewMiss)
    ));
}

#[test]
fn offline_cold_repository_is_an_object_miss() {
    let commit = GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap();
    let runner = fixture(vec![failed_output("missing object")]);
    let commands = Arc::clone(&runner.commands);
    let backend = Backend::new("git", runner);
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://origin.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(commit),
        repository_dir: root.path().join("ignored.git"),
        offline: true,
    };
    assert!(matches!(
        acquire(&backend, root.path(), &request, None),
        Err(GitCacheError::Git(
            super::super::GitError::OfflineObjectMiss
        ))
    ));
    assert!(
        commands
            .lock()
            .unwrap()
            .iter()
            .all(|args| { !args.iter().any(|arg| arg == "fetch" || arg == "ls-remote") })
    );
}

#[test]
fn corrupt_origin_is_metadata_error_before_offline_object_probe() {
    let commit = GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap();
    let backend = Backend::new("git", fixture(Vec::new()));
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://corrupt.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(commit),
        repository_dir: root.path().join("ignored.git"),
        offline: true,
    };
    let url_key = key("repository", request.url.as_str().as_bytes());
    let repository_root = root
        .path()
        .join("rsolve/vcs-v1/git/repositories")
        .join(url_key);
    std::fs::create_dir_all(&repository_root).unwrap();
    std::fs::write(
        repository_root.join("origin.toml"),
        b"schema = 1\nurl = \"https://other.example/repo\"\nalgorithm = \"sha1\"\n",
    )
    .unwrap();
    assert!(matches!(
        acquire(&backend, root.path(), &request, None),
        Err(GitCacheError::InvalidMetadata)
    ));
}

#[test]
fn oversized_origin_is_rejected_before_backend() {
    let commit = GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap();
    let backend = Backend::new("git", fixture(Vec::new()));
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://oversize.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(commit),
        repository_dir: root.path().join("ignored.git"),
        offline: true,
    };
    let url_key = key("repository", request.url.as_str().as_bytes());
    let repository_root = root
        .path()
        .join("rsolve/vcs-v1/git/repositories")
        .join(url_key);
    std::fs::create_dir_all(&repository_root).unwrap();
    std::fs::write(
        repository_root.join("origin.toml"),
        vec![b'x'; 16 * 1024 + 1],
    )
    .unwrap();
    assert!(matches!(
        acquire(&backend, root.path(), &request, None),
        Err(GitCacheError::InvalidMetadata)
    ));
}

#[cfg(unix)]
#[test]
fn cache_owned_repository_symlink_is_rejected_before_git() {
    let commit = GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap();
    let runner = fixture(Vec::new());
    let commands = Arc::clone(&runner.commands);
    let backend = Backend::new("git", runner);
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://repo-link.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(commit),
        repository_dir: root.path().join("ignored.git"),
        offline: false,
    };
    let url_key = key("repository", request.url.as_str().as_bytes());
    let repository_root = root
        .path()
        .join("rsolve/vcs-v1/git/repositories")
        .join(url_key);
    std::fs::create_dir_all(&repository_root).unwrap();
    std::os::unix::fs::symlink(
        root.path().join("outside.git"),
        repository_root.join("repository.git"),
    )
    .unwrap();
    assert!(matches!(
        acquire(&backend, root.path(), &request, None),
        Err(GitCacheError::InvalidMetadata)
    ));
    assert!(commands.lock().unwrap().is_empty());
}

#[test]
fn binary_blob_and_executable_mode_are_preserved() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let runner = online_fixture(commit, "100755", "binary", vec![0, 0xff, 1, 2]);
    let backend = Backend::new("git", runner);
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://bytes.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(GitCommitId::new(commit).unwrap()),
        repository_dir: root.path().join("ignored.git"),
        offline: false,
    };
    let source = acquire(&backend, root.path(), &request, None).unwrap();
    assert_eq!(
        std::fs::read(source.view().path().join("binary")).unwrap(),
        [0, 0xff, 1, 2]
    );
    #[cfg(unix)]
    assert_eq!(
        std::os::unix::fs::MetadataExt::mode(
            &std::fs::metadata(source.view().path().join("binary")).unwrap()
        ) & 0o111,
        0o111
    );
}

#[test]
fn unsupported_git_modes_fail_closed_individually() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    for (mode, kind) in [("120000", "blob"), ("160000", "commit"), ("040000", "tree")] {
        let runner = fixture(vec![
            output(""),
            output(""),
            output("commit\n"),
            output("fedcba9876543210fedcba9876543210fedcba98\n"),
            output(&format!("{mode} {kind} {commit}\tentry\0")),
        ]);
        let backend = Backend::new("git", runner);
        let root = tempfile::tempdir().unwrap();
        let request = GitAcquisitionRequest {
            url: rsolve_core::NormalizedGitUrl::new(format!("https://mode-{mode}.example/repo"))
                .unwrap(),
            revision: super::super::GitRevisionRequest::Pinned(GitCommitId::new(commit).unwrap()),
            repository_dir: root.path().join("ignored.git"),
            offline: false,
        };
        assert!(matches!(
            acquire(&backend, root.path(), &request, None),
            Err(GitCacheError::UnsupportedEntry { .. })
        ));
    }
}

#[test]
fn same_commit_from_different_urls_has_distinct_containers() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let root = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for host in ["first-url", "second-url"] {
        let backend = Backend::new(
            "git",
            online_fixture(commit, "100644", "DESCRIPTION", b"Package: x\n".to_vec()),
        );
        let request = GitAcquisitionRequest {
            url: rsolve_core::NormalizedGitUrl::new(format!("https://{host}.example/repo"))
                .unwrap(),
            revision: super::super::GitRevisionRequest::Pinned(GitCommitId::new(commit).unwrap()),
            repository_dir: root.path().join("ignored.git"),
            offline: false,
        };
        paths.push(
            acquire(&backend, root.path(), &request, None)
                .unwrap()
                .view()
                .path()
                .to_path_buf(),
        );
    }
    assert_ne!(paths[0], paths[1]);
    assert_ne!(paths[0].ancestors().nth(4), paths[1].ancestors().nth(4));
}

#[test]
fn subdirectory_is_literal_and_prefix_escape_is_rejected() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let subdirectory = rsolve_core::RepositorySubdir::new("src").unwrap();
    let runner = fixture(vec![
        output(""),
        output(""),
        output("commit\n"),
        output("fedcba9876543210fedcba9876543210fedcba98\n"),
        output(&format!("100644 blob {commit}\tsrc/file\0")),
        bytes(vec![1]),
    ]);
    let commands = Arc::clone(&runner.commands);
    let limits = Arc::clone(&runner.limits);
    let backend = Backend::new("git", runner);
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://subdir.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(GitCommitId::new(commit).unwrap()),
        repository_dir: root.path().join("ignored.git"),
        offline: false,
    };
    let source = acquire(&backend, root.path(), &request, Some(&subdirectory)).unwrap();
    assert_eq!(
        std::fs::read(source.view().path().join("file")).unwrap(),
        [1]
    );
    let recorded = commands.lock().unwrap();
    let ls_args = recorded
        .iter()
        .find(|args| args.iter().any(|arg| arg == "ls-tree"))
        .unwrap();
    let literal = ls_args
        .iter()
        .position(|arg| arg == "--literal-pathspecs")
        .unwrap();
    let git_dir = ls_args.iter().position(|arg| arg == "--git-dir").unwrap();
    let ls_tree = ls_args.iter().position(|arg| arg == "ls-tree").unwrap();
    let src = ls_args.iter().position(|arg| arg == "src").unwrap();
    assert!(literal < git_dir && git_dir < ls_tree && ls_tree < src);
    assert_eq!(ls_args.len(), 10);
    assert_eq!(ls_args[0], std::ffi::OsString::from("--no-replace-objects"));
    assert_eq!(ls_args[1], std::ffi::OsString::from("--literal-pathspecs"));
    assert_eq!(ls_args[2], std::ffi::OsString::from("--git-dir"));
    assert_eq!(ls_args[4], std::ffi::OsString::from("ls-tree"));
    assert_eq!(ls_args[5], std::ffi::OsString::from("-z"));
    assert_eq!(ls_args[6], std::ffi::OsString::from("-r"));
    assert_eq!(ls_args[8], std::ffi::OsString::from("--"));
    assert_eq!(ls_args[9], std::ffi::OsString::from("src"));
    assert!(
        limits
            .lock()
            .unwrap()
            .iter()
            .any(|limit| *limit > 64 * 1024)
    );

    let backend = Backend::new(
        "git",
        fixture(vec![
            output(""),
            output(""),
            output("commit\n"),
            output("fedcba9876543210fedcba9876543210fedcba98\n"),
            output(&format!("100644 blob {commit}\tother/file\0")),
        ]),
    );
    let root = tempfile::tempdir().unwrap();
    assert!(matches!(
        acquire(&backend, root.path(), &request, Some(&subdirectory)),
        Err(GitCacheError::Tree(TreeError::UnsafePath))
    ));
}

#[test]
fn corrupt_blob_is_a_typed_object_error() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let runner = fixture(vec![
        output(""),
        output(""),
        output("commit\n"),
        output("fedcba9876543210fedcba9876543210fedcba98\n"),
        output(&format!("100644 blob {commit}\tfile\0")),
        failed_output("bad object"),
    ]);
    let backend = Backend::new("git", runner);
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://corrupt-object.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(GitCommitId::new(commit).unwrap()),
        repository_dir: root.path().join("ignored.git"),
        offline: false,
    };
    assert!(matches!(
        acquire(&backend, root.path(), &request, None),
        Err(GitCacheError::ObjectCorrupt {
            operation: "reading Git blob"
        })
    ));
}

#[test]
fn empty_root_and_subdirectory_are_typed() {
    let commit = GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap();
    let backend = Backend::new("git", fixture(vec![output("")]));
    assert!(matches!(
        read_tree_entries(&backend, Path::new("/tmp/repository.git"), &commit, None),
        Err(GitCacheError::EmptyTree)
    ));
    let backend = Backend::new("git", fixture(vec![output("")]));
    let subdir = rsolve_core::RepositorySubdir::new("src").unwrap();
    assert!(matches!(
        read_tree_entries(
            &backend,
            Path::new("/tmp/repository.git"),
            &commit,
            Some(&subdir)
        ),
        Err(GitCacheError::SubdirectoryNotFound)
    ));
}

#[test]
fn command_output_overflow_maps_to_tree_limits() {
    let commit = GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap();
    let backend = Backend::new(
        "git",
        OverflowRunner {
            responses: RefCell::new(vec![Err(GitRunnerError::OutputTooLarge)]),
        },
    );
    assert!(matches!(
        read_tree_entries(&backend, Path::new("/tmp/repository.git"), &commit, None),
        Err(GitCacheError::Tree(TreeError::EntryLimit))
    ));
    let backend = Backend::new(
        "git",
        OverflowRunner {
            responses: RefCell::new(vec![
                Ok(output(&format!("100644 blob {commit}\tfile\0"))),
                Err(GitRunnerError::OutputTooLarge),
            ]),
        },
    );
    assert!(matches!(
        read_tree_entries(&backend, Path::new("/tmp/repository.git"), &commit, None),
        Err(GitCacheError::Tree(TreeError::BlobLimit))
    ));
}

#[test]
fn malformed_and_wrong_algorithm_git_oids_are_object_corrupt() {
    let commit = GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap();
    for record in [
        "100644 blob not-an-oid\tfile\0".to_owned(),
        format!("100644 blob {commit} extra\tfile\0"),
        "100644 blob aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tfile\0"
            .to_owned(),
    ] {
        let backend = Backend::new("git", fixture(vec![output(&record)]));
        assert!(matches!(
            read_tree_entries(&backend, Path::new("/tmp/repository.git"), &commit, None),
            Err(GitCacheError::ObjectCorrupt {
                operation: "validating Git tree entry"
            }) | Err(GitCacheError::ObjectCorrupt {
                operation: "validating Git blob OID"
            }) | Err(GitCacheError::ObjectCorrupt {
                operation: "validating Git blob hash algorithm"
            })
        ));
    }

    let wrong_algorithm_tree = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    let backend = Backend::new("git", fixture(vec![output(wrong_algorithm_tree)]));
    assert!(matches!(
        commit_tree_oid(&backend, Path::new("/tmp/repository.git"), &commit),
        Err(GitCacheError::ObjectCorrupt {
            operation: "validating commit tree hash algorithm"
        })
    ));

    let backend = Backend::new(
        "git",
        fixture(vec![output(&format!("100644 blob {commit} file\0"))]),
    );
    assert!(matches!(
        read_tree_entries(&backend, Path::new("/tmp/repository.git"), &commit, None),
        Err(GitCacheError::ObjectCorrupt {
            operation: "parsing Git tree output"
        })
    ));
}

#[test]
fn system_runner_reads_a_real_local_git_tree() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let bare = root.path().join("fixture.git");
    assert!(
        Command::new("git")
            .args(["init", "--quiet", "--bare"])
            .arg(&bare)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .arg(&work)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&work)
            .args(["config", "user.name", "rsolve fixture"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&work)
            .args(["config", "user.email", "fixture@example.invalid"])
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(work.join("DESCRIPTION"), b"Package: fixture\n").unwrap();
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&work)
            .args(["add", "DESCRIPTION"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&work)
            .args(["commit", "--quiet", "-m", "fixture"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["--git-dir"])
            .arg(&bare)
            .args(["fetch", "--quiet"])
            .arg(&work)
            .args(["HEAD:refs/heads/main"])
            .status()
            .unwrap()
            .success()
    );
    let commit_output = Command::new("git")
        .args(["-C"])
        .arg(&work)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(commit_output.status.success());
    let commit =
        GitCommitId::new(std::str::from_utf8(&commit_output.stdout).unwrap().trim()).unwrap();

    let backend = Backend::new("git", super::super::SystemGitRunner);
    let entries = read_tree_entries(&backend, &bare, &commit, None).unwrap();
    assert_eq!(
        entries,
        vec![TreeEntry::regular(
            "DESCRIPTION",
            b"Package: fixture\n".to_vec()
        )]
    );
}

#[test]
fn unsafe_git_tree_modes_fail_closed() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let runner = fixture(vec![
        output(""),
        output(""),
        output("commit\n"),
        output("fedcba9876543210fedcba9876543210fedcba98\n"),
        output(&format!("120000 blob {commit}\tlink\0")),
    ]);
    let backend = Backend::new("git", runner);
    let root = tempfile::tempdir().unwrap();
    let request = GitAcquisitionRequest {
        url: rsolve_core::NormalizedGitUrl::new("https://third.example/repo").unwrap(),
        revision: super::super::GitRevisionRequest::Pinned(GitCommitId::new(commit).unwrap()),
        repository_dir: root.path().join("ignored.git"),
        offline: false,
    };
    assert!(matches!(
        acquire(&backend, root.path(), &request, None),
        Err(GitCacheError::UnsupportedEntry { .. })
    ));
}
