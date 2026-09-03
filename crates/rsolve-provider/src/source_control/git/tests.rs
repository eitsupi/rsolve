use super::*;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Default)]
struct FixtureRunner {
    commands: RefCell<Vec<GitCommand>>,
    outputs: RefCell<Vec<GitCommandOutput>>,
}

impl GitCommandRunner for FixtureRunner {
    fn run(&self, command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError> {
        self.commands.borrow_mut().push(command.clone());
        Ok(self.outputs.borrow_mut().remove(0))
    }
}

fn output(stdout: &str) -> GitCommandOutput {
    GitCommandOutput {
        status: Some(0),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    }
}

#[test]
fn bounded_reader_keeps_capture_at_limit_while_draining_input() {
    let input = vec![b'x'; 8];
    let (captured, exceeded) = read_bounded(std::io::Cursor::new(input), 4).unwrap();
    assert_eq!(captured.len(), 4);
    assert!(exceeded);
}

#[test]
fn bounded_reader_preserves_io_errors() {
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture read failure"))
        }
    }
    assert!(read_bounded(FailingReader, 4).is_err());
}

#[test]
fn probe_requires_every_fetch_safety_option() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![
            output("git version 2.50\n"),
            output("--depth --no-tags --no-recurse-submodules --no-write-fetch-head\n"),
        ]),
    };
    assert_eq!(
        Backend::new("git", runner).probe(),
        Err(GitError::GitCapabilityUnsupported {
            capability: "fetch options".to_owned()
        })
    );
}

#[test]
fn probe_accepts_nonzero_help_status_when_all_options_are_advertised() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![
            output("git version 2.50\n"),
            GitCommandOutput {
                status: Some(129),
                stdout: Vec::new(),
                stderr: b"--depth --no-tags --no-recurse-submodules --no-write-fetch-head --no-auto-maintenance\n".to_vec(),
            },
        ]),
    };
    assert_eq!(Backend::new("git", runner).probe(), Ok(()));
}

fn failed_output(stderr: &str) -> GitCommandOutput {
    GitCommandOutput {
        status: Some(1),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[test]
fn default_branch_uses_exact_head_oid_after_symref_line() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![output(
            "ref: refs/heads/main\tHEAD\n0123456789abcdef0123456789abcdef01234567\tHEAD\n",
        )]),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    assert_eq!(
        backend
            .resolve(&url, &GitSelector::DefaultBranch)
            .unwrap()
            .to_string(),
        "0123456789abcdef0123456789abcdef01234567"
    );
}

#[test]
fn parses_exact_branch_and_rejects_malicious_revision_without_runner() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![output(
            "0123456789abcdef0123456789abcdef01234567\trefs/heads/main\n",
        )]),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    let commit = backend
        .resolve(&url, &GitSelector::Branch("main".into()))
        .unwrap();
    assert_eq!(commit.to_string().len(), 40);
    let error = backend.resolve(&url, &GitSelector::Rev("main~1".into()));
    assert_eq!(error, Err(GitError::SelectorInvalid));
}

#[test]
fn accepts_peeled_annotated_tag() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![output(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/v1\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/v1^{}\n",
        )]),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    assert_eq!(
        backend
            .resolve(&url, &GitSelector::Tag("v1".into()))
            .unwrap()
            .to_string(),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
}

#[test]
fn same_revision_name_across_branch_and_tag_is_ambiguous() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![output(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/heads/main\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/main\n",
        )]),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    assert_eq!(
        backend.resolve(&url, &GitSelector::Rev("main".into())),
        Err(GitError::SelectorAmbiguous)
    );
}

#[test]
fn repeated_reference_with_different_oid_is_mutable_drift() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![output(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/heads/main\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/heads/main\n",
        )]),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    assert_eq!(
        backend.resolve(&url, &GitSelector::Branch("main".into())),
        Err(GitError::MutableReferenceChanged)
    );
}

#[test]
fn credential_and_transport_failures_remain_typed() {
    let credential_runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![failed_output(
            "could not read Username because terminal prompts disabled",
        )]),
    };
    let transport_runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![failed_output("connection timed out")]),
    };
    let rejected_runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![failed_output("authentication failed")]),
    };
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    assert_eq!(
        Backend::new("git", credential_runner).resolve(&url, &GitSelector::DefaultBranch),
        Err(GitError::CredentialRequired)
    );
    assert_eq!(
        Backend::new("git", transport_runner).resolve(&url, &GitSelector::DefaultBranch),
        Err(GitError::Transport)
    );
    assert_eq!(
        Backend::new("git", rejected_runner).resolve(&url, &GitSelector::DefaultBranch),
        Err(GitError::CredentialRejected)
    );
}

#[test]
fn rejects_non_network_url_before_runner() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(Vec::new()),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("file://example.test/repo").unwrap();
    assert!(matches!(
        backend.resolve(&url, &GitSelector::DefaultBranch),
        Err(GitError::InvalidUrl { .. })
    ));
}

#[test]
fn rejects_ssh_before_runner() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(Vec::new()),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("ssh://example.test/repo").unwrap();
    assert_eq!(
        backend.resolve(&url, &GitSelector::DefaultBranch),
        Err(GitError::SshUnsupported)
    );
}

#[test]
fn full_oid_revision_is_used_without_remote_advertisement() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(Vec::new()),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    let oid = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(
        backend
            .resolve(&url, &GitSelector::Rev(oid.to_owned()))
            .unwrap()
            .to_string(),
        oid
    );
}

#[test]
fn exact_refs_revision_uses_only_the_advertised_ref() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![output(
            "0123456789abcdef0123456789abcdef01234567\trefs/heads/main\n",
        )]),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    assert_eq!(
        backend
            .resolve(&url, &GitSelector::Rev("refs/heads/main".into()))
            .unwrap()
            .to_string(),
        "0123456789abcdef0123456789abcdef01234567"
    );
}

#[test]
fn short_revision_queries_only_exact_branch_and_tag_refs() {
    struct RecordingRunner {
        commands: Rc<RefCell<Vec<GitCommand>>>,
    }
    impl GitCommandRunner for RecordingRunner {
        fn run(&self, command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError> {
            self.commands.borrow_mut().push(command.clone());
            Ok(output(
                "0123456789abcdef0123456789abcdef01234567\trefs/heads/main\n",
            ))
        }
    }
    let commands = Rc::new(RefCell::new(Vec::new()));
    let backend = Backend::new(
        "git",
        RecordingRunner {
            commands: Rc::clone(&commands),
        },
    );
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    backend
        .resolve(&url, &GitSelector::Rev("main".into()))
        .unwrap();
    let recorded = commands.borrow();
    let args = recorded[0].args();
    assert!(args.contains(&arg("refs/heads/main")));
    assert!(args.contains(&arg("refs/tags/main")));
    assert!(args.contains(&arg("refs/tags/main^{}")));
    assert!(!args.iter().any(|arg| arg == "main"));
}

#[test]
fn malformed_advertised_oid_is_unresolvable() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![output("not-an-oid\trefs/heads/main\n")]),
    };
    let backend = Backend::new("git", runner);
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    assert_eq!(
        backend.resolve(&url, &GitSelector::Branch("main".into())),
        Err(GitError::SelectorUnresolvable)
    );
}

#[test]
fn command_debug_redacts_environment_values() {
    let command = GitCommand::new(Path::new("git"), vec!["fetch".into()]);
    let debug = format!("{command:?}");
    assert!(!debug.contains("/dev/null"));
    assert!(debug.contains("GIT_TERMINAL_PROMPT"));
}

#[test]
fn command_boundary_has_no_ambient_git_state_and_fixed_protocol_policy() {
    let command = GitCommand::new(Path::new("git"), config_args());
    let names = command.environment_names().collect::<Vec<_>>();
    assert!(!names.contains(&"GIT_DIR"));
    assert!(!names.contains(&"GIT_WORK_TREE"));
    assert!(!names.contains(&"GIT_SSH_COMMAND"));
    assert!(command.args().contains(&arg("protocol.allow=never")));
    assert!(command.args().contains(&arg("protocol.https.allow=always")));
    assert!(!command.args().contains(&arg("protocol.ssh.allow=always")));
}

#[test]
fn ls_remote_uses_explicit_isolated_git_dir() {
    struct RecordingRunner {
        commands: Rc<RefCell<Vec<GitCommand>>>,
    }
    impl GitCommandRunner for RecordingRunner {
        fn run(&self, command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError> {
            self.commands.borrow_mut().push(command.clone());
            Ok(output("0123456789abcdef0123456789abcdef01234567\tHEAD\n"))
        }
    }
    let commands = Rc::new(RefCell::new(Vec::new()));
    let backend = Backend::new(
        "git",
        RecordingRunner {
            commands: Rc::clone(&commands),
        },
    );
    let url = NormalizedGitUrl::new("https://example.test/repo").unwrap();
    backend.resolve(&url, &GitSelector::DefaultBranch).unwrap();
    let command = &commands.borrow()[0];
    let git_dir = command
        .args()
        .windows(2)
        .find(|window| window[0] == "--git-dir")
        .expect("ls-remote must carry an isolated git-dir");
    assert_eq!(git_dir[1], arg(null_device()));
    assert!(!command.environment_names().any(|name| name == "GIT_DIR"));
}

#[test]
fn offline_pinned_object_miss_never_becomes_a_remote_operation() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![failed_output("missing object")]),
    };
    let backend = Backend::new("git", runner);
    let request = GitAcquisitionRequest {
        url: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
        revision: GitRevisionRequest::Pinned(
            GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        ),
        repository_dir: std::env::temp_dir().join("rsolve-source-control-test.git"),
        offline: true,
    };
    assert_eq!(backend.acquire(&request), Err(GitError::OfflineObjectMiss));
}

#[test]
fn fetched_non_commit_object_is_rejected() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![output(""), output(""), output("tree\n")]),
    };
    let backend = Backend::new("git", runner);
    let request = GitAcquisitionRequest {
        url: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
        revision: GitRevisionRequest::Pinned(
            GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        ),
        repository_dir: std::env::temp_dir().join("rsolve-source-control-test.git"),
        offline: false,
    };
    assert_eq!(backend.acquire(&request), Err(GitError::SelectorNotCommit));
}

#[test]
fn mutable_selector_is_rechecked_after_exact_fetch() {
    let runner = FixtureRunner {
        commands: RefCell::new(Vec::new()),
        outputs: RefCell::new(vec![
            output("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/heads/main\n"),
            output(""),
            output(""),
            output("commit\n"),
            output("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/heads/main\n"),
        ]),
    };
    let backend = Backend::new("git", runner);
    let request = GitAcquisitionRequest {
        url: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
        revision: GitRevisionRequest::Requested(GitSelector::Branch("main".into())),
        repository_dir: std::env::temp_dir().join("rsolve-source-control-test.git"),
        offline: false,
    };
    assert_eq!(
        backend.acquire(&request),
        Err(GitError::MutableReferenceChanged)
    );
}

#[test]
fn pinned_fetch_uses_a_stable_content_addressed_destination() {
    struct RecordingRunner {
        commands: Rc<RefCell<Vec<GitCommand>>>,
        outputs: RefCell<Vec<GitCommandOutput>>,
    }
    impl GitCommandRunner for RecordingRunner {
        fn run(&self, command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError> {
            self.commands.borrow_mut().push(command.clone());
            Ok(self.outputs.borrow_mut().remove(0))
        }
    }
    let commands = Rc::new(RefCell::new(Vec::new()));
    let runner = RecordingRunner {
        commands: Rc::clone(&commands),
        outputs: RefCell::new(vec![
            output(""),
            output(""),
            output("commit\n"),
            output(""),
            output(""),
            output("commit\n"),
        ]),
    };
    let backend = Backend::new("git", runner);
    let request = GitAcquisitionRequest {
        url: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
        revision: GitRevisionRequest::Pinned(
            GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        ),
        repository_dir: std::env::temp_dir().join("rsolve-source-control-test.git"),
        offline: false,
    };
    backend.acquire(&request).unwrap();
    backend.acquire(&request).unwrap();
    let recorded = commands.borrow();
    let first_target = recorded[1].args().last().unwrap();
    let second_target = recorded[4].args().last().unwrap();
    assert_eq!(first_target, second_target);
    assert!(
        first_target
            .to_string_lossy()
            .contains("refs/rsolve/acquire/sha1/")
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_repository_path_is_losslessly_preserved_in_all_commands() {
    use std::os::unix::ffi::OsStringExt;
    struct RecordingRunner {
        commands: Rc<RefCell<Vec<GitCommand>>>,
    }
    impl GitCommandRunner for RecordingRunner {
        fn run(&self, command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError> {
            self.commands.borrow_mut().push(command.clone());
            Ok(output("commit\n"))
        }
    }
    let commands = Rc::new(RefCell::new(Vec::new()));
    let backend = Backend::new(
        "git",
        RecordingRunner {
            commands: Rc::clone(&commands),
        },
    );
    let repository_dir =
        PathBuf::from(OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0x80]));
    let request = GitAcquisitionRequest {
        url: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
        revision: GitRevisionRequest::Pinned(
            GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        ),
        repository_dir: repository_dir.clone(),
        offline: false,
    };
    backend.acquire(&request).unwrap();
    for command in commands.borrow().iter() {
        assert!(command.args().windows(2).any(|window| {
            window[0] == arg("--git-dir") && window[1] == repository_dir.as_os_str()
        }));
    }
}
