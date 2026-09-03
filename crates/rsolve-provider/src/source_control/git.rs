//! A non-interactive, argument-vector based system Git backend.

use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use rsolve_core::{GitCommitId, NormalizedGitUrl};
use thiserror::Error;

static NEXT_FETCH_REF: AtomicU64 = AtomicU64::new(0);
const MAX_OUTPUT_BYTES: usize = 256 * 1024;

/// A Git selector owned by this backend rather than by the manifest layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitSelector {
    DefaultBranch,
    Branch(String),
    Tag(String),
    Rev(String),
}

/// Whether a request resolves a mutable selector or uses an already pinned
/// full object id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitRevisionRequest {
    Requested(GitSelector),
    Pinned(GitCommitId),
}

/// An acquisition request for a caller-provided bare repository directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitAcquisitionRequest {
    pub url: NormalizedGitUrl,
    pub revision: GitRevisionRequest,
    pub repository_dir: PathBuf,
    pub offline: bool,
}

/// The immutable fact produced after exact selector resolution and object
/// validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitAcquisition {
    url: NormalizedGitUrl,
    commit: GitCommitId,
    repository_dir: PathBuf,
}

impl GitAcquisition {
    pub fn url(&self) -> &NormalizedGitUrl {
        &self.url
    }

    pub fn commit(&self) -> &GitCommitId {
        &self.commit
    }

    pub fn repository_dir(&self) -> &Path {
        &self.repository_dir
    }
}

/// A fixed Git invocation.  The command is always executed directly, never
/// through a shell.  Environment values are intentionally not exposed by the
/// Debug implementation.
#[derive(Clone, Eq, PartialEq)]
struct GitCommand {
    executable: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

impl GitCommand {
    fn new(executable: &Path, args: Vec<String>) -> Self {
        Self {
            executable: executable.to_path_buf(),
            args,
            env: sanitized_environment(),
        }
    }

    #[cfg(test)]
    fn args(&self) -> &[String] {
        &self.args
    }

    fn environment_names(&self) -> impl Iterator<Item = &str> {
        self.env.iter().map(|(name, _)| name.as_str())
    }

    fn environment(&self) -> &[(String, String)] {
        &self.env
    }
}

impl fmt::Debug for GitCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitCommand")
            .field("executable", &self.executable)
            .field("argument_count", &self.args.len())
            .field(
                "environment_names",
                &self.environment_names().collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Captured output from one Git command.  The runner bounds both streams.
#[derive(Clone, Eq, PartialEq)]
struct GitCommandOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl fmt::Debug for GitCommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitCommandOutput")
            .field("status", &self.status)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .finish()
    }
}

/// Injectable command seam for deterministic protocol tests.
trait GitCommandRunner {
    fn run(&self, command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError>;
}

/// Process-level failures before Git can report a protocol result.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
enum GitRunnerError {
    #[error("Git executable is unavailable")]
    ExecutableUnavailable,
    #[error("Git process could not be started")]
    Spawn,
    #[error("Git process output exceeded the configured limit")]
    OutputTooLarge,
    #[error("Git process output could not be read")]
    Read,
}

/// The production direct-process runner.
#[derive(Clone, Debug, Default)]
struct SystemGitRunner;

impl GitCommandRunner for SystemGitRunner {
    fn run(&self, command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError> {
        let mut process = Command::new(&command.executable);
        process
            .args(&command.args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in command.environment() {
            process.env(name, value);
        }
        let mut child = process.spawn().map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => GitRunnerError::ExecutableUnavailable,
            _ => GitRunnerError::Spawn,
        })?;
        let stdout = child.stdout.take().ok_or(GitRunnerError::Spawn)?;
        let stderr = child.stderr.take().ok_or(GitRunnerError::Spawn)?;
        let stdout_reader = std::thread::spawn(|| read_bounded(stdout));
        let stderr_reader = std::thread::spawn(|| read_bounded(stderr));
        let status = child.wait().map_err(|_| GitRunnerError::Spawn)?;
        let (stdout, stdout_exceeded) = stdout_reader
            .join()
            .map_err(|_| GitRunnerError::Spawn)?
            .map_err(|_| GitRunnerError::Read)?;
        let (stderr, stderr_exceeded) = stderr_reader
            .join()
            .map_err(|_| GitRunnerError::Spawn)?
            .map_err(|_| GitRunnerError::Read)?;
        if stdout_exceeded || stderr_exceeded {
            return Err(GitRunnerError::OutputTooLarge);
        }
        Ok(GitCommandOutput {
            status: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

fn read_bounded(mut reader: impl Read) -> io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::with_capacity(MAX_OUTPUT_BYTES.min(8192));
    let mut exceeded = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Err(error) => return Err(error),
            Ok(read) => read,
        };
        let remaining = MAX_OUTPUT_BYTES.saturating_sub(captured.len());
        if remaining > 0 {
            captured.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        if read > remaining {
            exceeded = true;
        }
    }
    Ok((captured, exceeded))
}

/// Typed failures at the Git source-control boundary.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum GitError {
    #[error("Git URL is not an allowed HTTPS or SSH URL: {url}")]
    InvalidUrl { url: String },
    #[error("Git executable is unavailable")]
    GitExecutableUnavailable,
    #[error("Git executable lacks a required capability: {capability}")]
    GitCapabilityUnsupported { capability: String },
    #[error("Git repository directory must be an absolute caller-provided path")]
    InvalidRepositoryPath,
    #[error("Git selector is invalid")]
    SelectorInvalid,
    #[error("Git selector was not advertised by the remote")]
    SelectorNotFound,
    #[error("Git selector is ambiguous")]
    SelectorAmbiguous,
    #[error("Git selector cannot be resolved uniquely")]
    SelectorUnresolvable,
    #[error("Git selector resolved to a non-commit object")]
    SelectorNotCommit,
    #[error("Git mutable reference changed during acquisition")]
    MutableReferenceChanged,
    #[error("offline Git selector resolution is unavailable")]
    OfflineSelectorResolutionUnavailable,
    #[error("offline Git object is unavailable")]
    OfflineObjectMiss,
    #[error("Git requested credentials but no non-interactive broker was provided")]
    CredentialRequired,
    #[error("Git credentials were rejected")]
    CredentialRejected,
    #[error("Git transport failed")]
    Transport,
    #[error("Git command failed")]
    CommandFailed,
}

/// Internal generic executor used by the production facade and unit fixtures.
struct Backend<R = SystemGitRunner> {
    executable: PathBuf,
    runner: R,
}

/// Production system-Git facade. Fixture runners stay private to this module,
/// keeping process output and execution seams out of the public API.
pub struct GitBackend {
    inner: Backend<SystemGitRunner>,
}

impl GitBackend {
    /// Uses the system `git` executable.  Capability probing is explicit via
    /// [`GitBackend::probe`], so construction itself remains side-effect free.
    pub fn system() -> Self {
        Self {
            inner: Backend::new(discover_git_executable(), SystemGitRunner),
        }
    }

    pub fn probe(&self) -> Result<(), GitError> {
        self.inner.probe()
    }

    pub fn acquire(&self, request: &GitAcquisitionRequest) -> Result<GitAcquisition, GitError> {
        self.inner.acquire(request)
    }

    pub fn resolve(
        &self,
        url: &NormalizedGitUrl,
        selector: &GitSelector,
    ) -> Result<GitCommitId, GitError> {
        self.inner.resolve(url, selector)
    }
}

impl<R: GitCommandRunner> Backend<R> {
    fn new(executable: impl Into<PathBuf>, runner: R) -> Self {
        Self {
            executable: executable.into(),
            runner,
        }
    }

    /// Probes executable availability and the fixed fetch options used by the
    /// backend.
    pub fn probe(&self) -> Result<(), GitError> {
        self.run_checked(vec!["--version".to_owned()], "version")?;
        let output = self
            .runner
            .run(&GitCommand::new(
                &self.executable,
                vec!["fetch".to_owned(), "-h".to_owned()],
            ))
            .map_err(|error| match error {
                GitRunnerError::ExecutableUnavailable => GitError::GitExecutableUnavailable,
                GitRunnerError::OutputTooLarge | GitRunnerError::Spawn | GitRunnerError::Read => {
                    GitError::Transport
                }
            })?;
        let help = format!("{}\n{}", output.stdout, output.stderr);
        const REQUIRED_FETCH_OPTIONS: &[&str] = &[
            "--depth",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--no-auto-maintenance",
        ];
        if REQUIRED_FETCH_OPTIONS
            .iter()
            .any(|marker| !help.contains(marker))
        {
            return Err(GitError::GitCapabilityUnsupported {
                capability: "fetch options".to_owned(),
            });
        }
        Ok(())
    }

    pub fn acquire(&self, request: &GitAcquisitionRequest) -> Result<GitAcquisition, GitError> {
        validate_url(&request.url)?;
        validate_repository_path(&request.repository_dir)?;
        match &request.revision {
            GitRevisionRequest::Pinned(commit) => {
                if request.offline {
                    self.verify_local_commit(&request.repository_dir, commit)
                        .map_err(|error| match error {
                            GitError::CommandFailed | GitError::SelectorNotFound => {
                                GitError::OfflineObjectMiss
                            }
                            other => other,
                        })?;
                } else {
                    self.fetch_commit(&request.repository_dir, &request.url, commit)?;
                    self.verify_local_commit(&request.repository_dir, commit)?;
                }
                Ok(GitAcquisition {
                    url: request.url.clone(),
                    commit: commit.clone(),
                    repository_dir: request.repository_dir.clone(),
                })
            }
            GitRevisionRequest::Requested(GitSelector::Rev(revision)) if request.offline => {
                let commit = GitCommitId::new(revision)
                    .map_err(|_| GitError::OfflineSelectorResolutionUnavailable)?;
                self.verify_local_commit(&request.repository_dir, &commit)
                    .map_err(|error| match error {
                        GitError::CommandFailed | GitError::SelectorNotFound => {
                            GitError::OfflineObjectMiss
                        }
                        other => other,
                    })?;
                Ok(GitAcquisition {
                    url: request.url.clone(),
                    commit,
                    repository_dir: request.repository_dir.clone(),
                })
            }
            GitRevisionRequest::Requested(_) if request.offline => {
                Err(GitError::OfflineSelectorResolutionUnavailable)
            }
            GitRevisionRequest::Requested(selector) => {
                let commit = self.resolve(&request.url, selector)?;
                self.fetch_commit(&request.repository_dir, &request.url, &commit)?;
                self.verify_local_commit(&request.repository_dir, &commit)?;
                if !is_full_oid_selector(selector)
                    && let Err(error) = self.verify_selector_stable(&request.url, selector, &commit)
                {
                    return Err(error);
                }
                Ok(GitAcquisition {
                    url: request.url.clone(),
                    commit,
                    repository_dir: request.repository_dir.clone(),
                })
            }
        }
    }

    /// Resolves a requested selector from exact remote advertisement only.
    pub fn resolve(
        &self,
        url: &NormalizedGitUrl,
        selector: &GitSelector,
    ) -> Result<GitCommitId, GitError> {
        validate_url(url)?;
        if let GitSelector::Rev(revision) = selector
            && let Ok(commit) = GitCommitId::new(revision)
        {
            return Ok(commit);
        }
        let lines = match selector {
            GitSelector::DefaultBranch => self.run_ls_remote(url, true, vec!["HEAD".to_owned()])?,
            GitSelector::Branch(name) => {
                let name = checked_ref_component(name)?;
                self.run_ls_remote(url, false, vec![format!("refs/heads/{name}")])?
            }
            GitSelector::Tag(name) => {
                let name = checked_ref_component(name)?;
                self.run_ls_remote(
                    url,
                    false,
                    vec![
                        format!("refs/tags/{name}"),
                        format!("refs/tags/{name}^{{}}"),
                    ],
                )?
            }
            GitSelector::Rev(revision) => {
                let refspec = checked_revision(revision)?;
                let refspecs = refspec
                    .map(|value| vec![value.to_owned()])
                    .unwrap_or_else(|| {
                        vec![
                            format!("refs/heads/{revision}"),
                            format!("refs/tags/{revision}"),
                            format!("refs/tags/{revision}^{{}}"),
                        ]
                    });
                self.run_ls_remote(url, false, refspecs)?
            }
        };
        select_advertised_commit(&lines, selector)
    }

    fn run_ls_remote(
        &self,
        url: &NormalizedGitUrl,
        symref: bool,
        exact_refs: Vec<String>,
    ) -> Result<Vec<Advertisement>, GitError> {
        let mut args = config_args();
        // `ls-remote` does not need a repository, but Git otherwise walks the
        // process cwd and may discover a user workspace's local config.
        // Supplying an explicit null git-dir prevents that discovery.
        args.push("--git-dir".to_owned());
        args.push(null_device());
        args.push("ls-remote".to_owned());
        if symref {
            args.push("--symref".to_owned());
        }
        args.push(url.to_string());
        args.extend(exact_refs);
        let output = self.run_checked(args, "remote advertisement")?;
        parse_advertisement(&output.stdout)
    }

    fn fetch_commit(
        &self,
        repository_dir: &Path,
        url: &NormalizedGitUrl,
        commit: &GitCommitId,
    ) -> Result<(), GitError> {
        let mut init = vec![
            "--git-dir".to_owned(),
            repository_dir.display().to_string(),
            "init".to_owned(),
            "--bare".to_owned(),
        ];
        if commit.as_str().len() == 64 {
            init.push("--object-format=sha256".to_owned());
        }
        let _ = self.run_checked(init, "initialize owned bare repository")?;
        let target = format!(
            "{commit}:refs/rsolve/acquire/{}",
            NEXT_FETCH_REF.fetch_add(1, Ordering::Relaxed)
        );
        let mut args = config_args();
        args.extend([
            "--git-dir".to_owned(),
            repository_dir.display().to_string(),
            "-c".to_owned(),
            "gc.auto=0".to_owned(),
            "-c".to_owned(),
            "maintenance.auto=false".to_owned(),
            "fetch".to_owned(),
            "--depth=1".to_owned(),
            "--no-tags".to_owned(),
            "--no-recurse-submodules".to_owned(),
            "--no-write-fetch-head".to_owned(),
            "--no-auto-maintenance".to_owned(),
            url.to_string(),
            target,
        ]);
        self.run_checked(args, "fetch exact Git object").map(|_| ())
    }

    fn verify_selector_stable(
        &self,
        url: &NormalizedGitUrl,
        selector: &GitSelector,
        advertised_commit: &GitCommitId,
    ) -> Result<(), GitError> {
        match self.resolve(url, selector) {
            Ok(current) if current == *advertised_commit => Ok(()),
            Ok(_) => Err(GitError::MutableReferenceChanged),
            Err(GitError::SelectorNotFound) => Err(GitError::MutableReferenceChanged),
            Err(error) => Err(error),
        }
    }

    fn verify_local_commit(
        &self,
        repository_dir: &Path,
        commit: &GitCommitId,
    ) -> Result<(), GitError> {
        let object = commit.to_string();
        let type_output = self.run_checked(
            vec![
                "--git-dir".to_owned(),
                repository_dir.display().to_string(),
                "cat-file".to_owned(),
                "-t".to_owned(),
                object,
            ],
            "verify Git object type",
        )?;
        if type_output.stdout.trim() != "commit" {
            return Err(GitError::SelectorNotCommit);
        }
        Ok(())
    }

    fn run_checked(
        &self,
        args: Vec<String>,
        operation: &str,
    ) -> Result<GitCommandOutput, GitError> {
        let output = self
            .runner
            .run(&GitCommand::new(&self.executable, args))
            .map_err(|error| match error {
                GitRunnerError::ExecutableUnavailable => GitError::GitExecutableUnavailable,
                GitRunnerError::OutputTooLarge | GitRunnerError::Spawn | GitRunnerError::Read => {
                    GitError::Transport
                }
            })?;
        if output.status == Some(0) {
            return Ok(output);
        }
        Err(classify_command_failure(operation, &output.stderr))
    }
}

fn is_full_oid_selector(selector: &GitSelector) -> bool {
    matches!(selector, GitSelector::Rev(value) if GitCommitId::new(value).is_ok())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Advertisement {
    oid: String,
    reference: String,
}

fn parse_advertisement(stdout: &str) -> Result<Vec<Advertisement>, GitError> {
    let mut result = Vec::new();
    for line in stdout.lines() {
        let Some((oid, reference)) = line.split_once('\t') else {
            continue;
        };
        if oid.starts_with("ref:") || reference.is_empty() {
            continue;
        }
        if GitCommitId::new(oid).is_err() {
            return Err(GitError::SelectorUnresolvable);
        }
        result.push(Advertisement {
            oid: oid.to_owned(),
            reference: reference.to_owned(),
        });
    }
    Ok(result)
}

fn select_advertised_commit(
    advertisements: &[Advertisement],
    selector: &GitSelector,
) -> Result<GitCommitId, GitError> {
    let references: Vec<&Advertisement> = match selector {
        GitSelector::DefaultBranch => advertisements
            .iter()
            .filter(|item| item.reference == "HEAD")
            .collect(),
        GitSelector::Branch(name) => {
            let reference = format!("refs/heads/{name}");
            advertisements
                .iter()
                .filter(|item| item.reference == reference)
                .collect()
        }
        GitSelector::Tag(name) => {
            let reference = format!("refs/tags/{name}");
            let peeled = format!("{reference}^{{}}");
            let peeled_refs: Vec<&Advertisement> = advertisements
                .iter()
                .filter(|item| item.reference == peeled)
                .collect();
            if !peeled_refs.is_empty() {
                peeled_refs
            } else {
                advertisements
                    .iter()
                    .filter(|item| item.reference == reference)
                    .collect()
            }
        }
        GitSelector::Rev(revision) => {
            if GitCommitId::new(revision).is_ok() {
                return GitCommitId::new(revision).map_err(|_| GitError::SelectorInvalid);
            }
            if revision.starts_with("refs/") {
                let peeled = format!("{revision}^{{}}");
                let peeled_refs = advertisements
                    .iter()
                    .filter(|item| item.reference == peeled)
                    .collect::<Vec<_>>();
                if !peeled_refs.is_empty() {
                    peeled_refs
                } else {
                    advertisements
                        .iter()
                        .filter(|item| item.reference == *revision)
                        .collect()
                }
            } else {
                let branch = format!("refs/heads/{revision}");
                let tag = format!("refs/tags/{revision}");
                let peeled = format!("{tag}^{{}}");
                let mut matches = advertisements
                    .iter()
                    .filter(|item| item.reference == branch)
                    .collect::<Vec<_>>();
                let tags = advertisements
                    .iter()
                    .filter(|item| item.reference == peeled)
                    .collect::<Vec<_>>();
                if tags.is_empty() {
                    matches.extend(advertisements.iter().filter(|item| item.reference == tag));
                } else {
                    matches.extend(tags);
                }
                matches
            }
        }
    };
    let Some(first) = references.first() else {
        return Err(GitError::SelectorNotFound);
    };
    if references.len() > 1 {
        if references
            .iter()
            .skip(1)
            .any(|item| item.reference == first.reference && item.oid != first.oid)
        {
            return Err(GitError::MutableReferenceChanged);
        }
        return Err(GitError::SelectorAmbiguous);
    }
    GitCommitId::new(&first.oid).map_err(|_| GitError::SelectorUnresolvable)
}

fn validate_url(url: &NormalizedGitUrl) -> Result<(), GitError> {
    let scheme = url.as_str().split_once("://").map(|(scheme, _)| scheme);
    if !matches!(scheme, Some("https") | Some("ssh")) {
        return Err(GitError::InvalidUrl {
            url: url.to_string(),
        });
    }
    Ok(())
}

fn validate_repository_path(path: &Path) -> Result<(), GitError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(GitError::InvalidRepositoryPath)
    }
}

fn checked_ref_component(value: &str) -> Result<&str, GitError> {
    if value.is_empty()
        || value.starts_with('-')
        || value.starts_with('.')
        || value.ends_with('.')
        || value.starts_with('/')
        || value.ends_with('/')
        || value.ends_with(".lock")
        || value.contains("..")
        || value.contains("@{")
        || value == "@"
        || value.contains(['~', '^', ':', '?', '*', '[', '\\'])
        || value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == '\u{7f}'
        })
    {
        return Err(GitError::SelectorInvalid);
    }
    if value.split('/').any(|component| {
        component.is_empty()
            || component == "."
            || component == ".."
            || component.starts_with('.')
            || component.ends_with('.')
            || component.ends_with(".lock")
    }) {
        return Err(GitError::SelectorInvalid);
    }
    Ok(value)
}

fn checked_revision(value: &str) -> Result<Option<&str>, GitError> {
    if GitCommitId::new(value).is_ok() {
        return Ok(None);
    }
    if let Some(reference) = value.strip_prefix("refs/") {
        checked_ref_component(reference)?;
        return Ok(Some(value));
    }
    checked_ref_component(value)?;
    Ok(None)
}

fn classify_command_failure(_operation: &str, stderr: &str) -> GitError {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("terminal prompts disabled")
        || lower.contains("could not read username")
        || lower.contains("authentication required")
    {
        GitError::CredentialRequired
    } else if lower.contains("authentication failed") || lower.contains("permission denied") {
        GitError::CredentialRejected
    } else if lower.contains("could not resolve")
        || lower.contains("connection")
        || lower.contains("timed out")
        || lower.contains("host key")
        || lower.contains("certificate")
    {
        GitError::Transport
    } else {
        GitError::CommandFailed
    }
}

fn sanitized_environment() -> Vec<(String, String)> {
    let null = null_device();
    vec![
        ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
        ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
        ("GIT_CONFIG_GLOBAL".to_owned(), null.clone()),
        ("GIT_CONFIG_SYSTEM".to_owned(), null),
        ("GIT_OPTIONAL_LOCKS".to_owned(), "0".to_owned()),
        // This is a fixed, non-user-controlled command string. It keeps SSH
        // non-interactive without accepting a caller-provided shell fragment.
        (
            "GIT_SSH_COMMAND".to_owned(),
            "ssh -o BatchMode=yes".to_owned(),
        ),
    ]
}

fn config_args() -> Vec<String> {
    vec![
        "-c".to_owned(),
        "protocol.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.https.allow=always".to_owned(),
        "-c".to_owned(),
        "protocol.ssh.allow=always".to_owned(),
    ]
}

fn null_device() -> String {
    #[cfg(windows)]
    {
        "NUL".to_owned()
    }
    #[cfg(not(windows))]
    {
        "/dev/null".to_owned()
    }
}

fn discover_git_executable() -> PathBuf {
    let Some(path) = std::env::var_os("PATH") else {
        return PathBuf::from("git");
    };
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("git");
        if candidate.is_file() {
            return candidate;
        }
        #[cfg(windows)]
        for extension in [".exe", ".cmd", ".bat"] {
            let candidate = directory.join(format!("git{extension}"));
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("git")
}

#[cfg(test)]
mod tests {
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
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    #[test]
    fn bounded_reader_keeps_capture_at_limit_while_draining_input() {
        let input = vec![b'x'; MAX_OUTPUT_BYTES + 1024];
        let (captured, exceeded) = read_bounded(std::io::Cursor::new(input)).unwrap();
        assert_eq!(captured.len(), MAX_OUTPUT_BYTES);
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
        assert!(read_bounded(FailingReader).is_err());
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
                    stdout: String::new(),
                    stderr: "--depth --no-tags --no-recurse-submodules --no-write-fetch-head --no-auto-maintenance\n".to_owned(),
                },
            ]),
        };
        assert_eq!(Backend::new("git", runner).probe(), Ok(()));
    }

    fn failed_output(stderr: &str) -> GitCommandOutput {
        GitCommandOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: stderr.to_owned(),
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
        let url = NormalizedGitUrl::new("ssh://example.test/repo").unwrap();
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
        assert!(args.contains(&"refs/heads/main".to_owned()));
        assert!(args.contains(&"refs/tags/main".to_owned()));
        assert!(args.contains(&"refs/tags/main^{}".to_owned()));
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
        assert!(names.contains(&"GIT_SSH_COMMAND"));
        assert_eq!(
            command
                .environment()
                .iter()
                .find(|(name, _)| name == "GIT_SSH_COMMAND")
                .map(|(_, value)| value.as_str()),
            Some("ssh -o BatchMode=yes")
        );
        assert!(command.args().contains(&"protocol.allow=never".to_owned()));
        assert!(
            command
                .args()
                .contains(&"protocol.https.allow=always".to_owned())
        );
        assert!(
            command
                .args()
                .contains(&"protocol.ssh.allow=always".to_owned())
        );
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
        assert_eq!(git_dir[1], null_device());
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
            url: NormalizedGitUrl::new("ssh://example.test/repo").unwrap(),
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
}
