//! A non-interactive, argument-vector based system Git backend.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rsolve_core::{GitCommitId, NormalizedGitUrl};
use thiserror::Error;

pub(crate) mod cache;

pub use cache::{CachedGitSource, GitCacheError};

const MAX_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_TREE_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_BLOB_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

fn arg(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_os_string()
}

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

/// A cache acquisition request. The cache owns its repository and source
/// paths; callers provide only the Git identity and requested source subtree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSourceRequest {
    pub url: NormalizedGitUrl,
    pub revision: GitRevisionRequest,
    pub subdirectory: Option<rsolve_core::RepositorySubdir>,
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
pub(crate) struct GitCommand {
    executable: PathBuf,
    args: Vec<OsString>,
    env: Vec<(String, String)>,
    output_limit: usize,
}

impl GitCommand {
    fn new(executable: &Path, args: Vec<OsString>) -> Self {
        Self {
            executable: executable.to_path_buf(),
            args,
            env: sanitized_environment(),
            output_limit: MAX_OUTPUT_BYTES,
        }
    }

    fn with_output_limit(executable: &Path, args: Vec<OsString>, output_limit: usize) -> Self {
        let mut command = Self::new(executable, args);
        command.output_limit = output_limit;
        command
    }

    #[cfg(test)]
    fn args(&self) -> &[OsString] {
        &self.args
    }

    #[cfg(test)]
    fn output_limit(&self) -> usize {
        self.output_limit
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
pub(crate) struct GitCommandOutput {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
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
pub(crate) trait GitCommandRunner {
    fn run(&self, command: &GitCommand) -> Result<GitCommandOutput, GitRunnerError>;
}

/// Process-level failures before Git can report a protocol result.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub(crate) enum GitRunnerError {
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
pub(crate) struct SystemGitRunner;

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
        let output_limit = command.output_limit;
        let stdout_reader = std::thread::spawn(move || read_bounded(stdout, output_limit));
        let stderr_reader = std::thread::spawn(move || read_bounded(stderr, output_limit));
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
            stdout,
            stderr,
        })
    }
}

fn read_bounded(mut reader: impl Read, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::with_capacity(limit.min(8192));
    let mut exceeded = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Err(error) => return Err(error),
            Ok(read) => read,
        };
        let remaining = limit.saturating_sub(captured.len());
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
    #[error("Git URL is not an allowed HTTPS URL: {url}")]
    InvalidUrl { url: String },
    #[error("SSH Git transport is not supported by this backend")]
    SshUnsupported,
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
    #[error("Git command output exceeded the operation limit: {operation}")]
    OutputTooLarge { operation: String },
}

/// Internal generic executor used by the production facade and unit fixtures.
pub(crate) struct Backend<R = SystemGitRunner> {
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

    /// Acquires a pinned/requested source through the per-URL cache and
    /// publishes a backend-neutral immutable tree view. The cache owns all
    /// repository and source paths; no caller-provided filesystem path is
    /// accepted by this API.
    pub fn acquire_cached(
        &self,
        cache_root: impl AsRef<Path>,
        request: &GitSourceRequest,
    ) -> Result<CachedGitSource, GitCacheError> {
        let low_level = GitAcquisitionRequest {
            url: request.url.clone(),
            revision: request.revision.clone(),
            repository_dir: PathBuf::new(),
            offline: request.offline,
        };
        cache::acquire(
            &self.inner,
            cache_root.as_ref(),
            &low_level,
            request.subdirectory.as_ref(),
        )
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
        self.run_checked(vec![arg("--version")], "version", MAX_OUTPUT_BYTES)?;
        let output = self
            .runner
            .run(&GitCommand::new(
                &self.executable,
                vec![arg("fetch"), arg("-h")],
            ))
            .map_err(|error| match error {
                GitRunnerError::ExecutableUnavailable => GitError::GitExecutableUnavailable,
                GitRunnerError::OutputTooLarge => GitError::Transport,
                GitRunnerError::Spawn | GitRunnerError::Read => GitError::Transport,
            })?;
        let mut help = output.stdout.clone();
        help.push(b'\n');
        help.extend_from_slice(&output.stderr);
        const REQUIRED_FETCH_OPTIONS: &[&str] = &[
            "--depth",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--no-auto-maintenance",
        ];
        if REQUIRED_FETCH_OPTIONS.iter().any(|marker| {
            !help
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        }) {
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
            GitSelector::DefaultBranch => self.run_ls_remote(url, true, vec![arg("HEAD")])?,
            GitSelector::Branch(name) => {
                let name = checked_ref_component(name)?;
                self.run_ls_remote(url, false, vec![arg(format!("refs/heads/{name}"))])?
            }
            GitSelector::Tag(name) => {
                let name = checked_ref_component(name)?;
                self.run_ls_remote(
                    url,
                    false,
                    vec![
                        arg(format!("refs/tags/{name}")),
                        arg(format!("refs/tags/{name}^{{}}")),
                    ],
                )?
            }
            GitSelector::Rev(revision) => {
                let refspec = checked_revision(revision)?;
                let refspecs = refspec.map(|value| vec![arg(value)]).unwrap_or_else(|| {
                    vec![
                        arg(format!("refs/heads/{revision}")),
                        arg(format!("refs/tags/{revision}")),
                        arg(format!("refs/tags/{revision}^{{}}")),
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
        exact_refs: Vec<OsString>,
    ) -> Result<Vec<Advertisement>, GitError> {
        let mut args = config_args();
        args.push(arg("--git-dir"));
        args.push(arg(null_device()));
        args.push(arg("ls-remote"));
        if symref {
            args.push(arg("--symref"));
        }
        args.push(arg(url.to_string()));
        args.extend(exact_refs);
        let output = self.run_checked(args, "remote advertisement", MAX_OUTPUT_BYTES)?;
        parse_advertisement(&output.stdout)
    }

    fn fetch_commit(
        &self,
        repository_dir: &Path,
        url: &NormalizedGitUrl,
        commit: &GitCommitId,
    ) -> Result<(), GitError> {
        let mut init = vec![
            arg("--git-dir"),
            repository_dir.as_os_str().to_os_string(),
            arg("init"),
            arg("--bare"),
        ];
        if commit.as_str().len() == 64 {
            init.push(arg("--object-format=sha256"));
        }
        let _ = self.run_checked(init, "initialize owned bare repository", MAX_OUTPUT_BYTES)?;
        let namespace = match commit.algorithm() {
            rsolve_core::GitHashAlgorithm::Sha1 => "sha1",
            rsolve_core::GitHashAlgorithm::Sha256 => "sha256",
        };
        let target = arg(format!("{commit}:refs/rsolve/acquire/{namespace}/{commit}"));
        let mut args = config_args();
        args.extend([
            arg("--git-dir"),
            repository_dir.as_os_str().to_os_string(),
            arg("-c"),
            arg("gc.auto=0"),
            arg("-c"),
            arg("maintenance.auto=false"),
            arg("fetch"),
            arg("--depth=1"),
            arg("--no-tags"),
            arg("--no-recurse-submodules"),
            arg("--no-write-fetch-head"),
            arg("--no-auto-maintenance"),
            arg(url.to_string()),
            target,
        ]);
        self.run_checked(args, "fetch exact Git object", MAX_OUTPUT_BYTES)
            .map(|_| ())
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
                arg("--no-replace-objects"),
                arg("--git-dir"),
                repository_dir.as_os_str().to_os_string(),
                arg("cat-file"),
                arg("-t"),
                arg(object),
            ],
            "verify Git object type",
            MAX_OUTPUT_BYTES,
        )?;
        if type_output.stdout.as_slice().trim_ascii() != b"commit" {
            return Err(GitError::SelectorNotCommit);
        }
        Ok(())
    }

    fn run_checked(
        &self,
        args: Vec<OsString>,
        operation: &str,
        output_limit: usize,
    ) -> Result<GitCommandOutput, GitError> {
        let output = self
            .runner
            .run(&GitCommand::with_output_limit(
                &self.executable,
                args,
                output_limit,
            ))
            .map_err(|error| match error {
                GitRunnerError::ExecutableUnavailable => GitError::GitExecutableUnavailable,
                GitRunnerError::OutputTooLarge => GitError::OutputTooLarge {
                    operation: operation.to_owned(),
                },
                GitRunnerError::Spawn | GitRunnerError::Read => GitError::Transport,
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

fn parse_advertisement(stdout: &[u8]) -> Result<Vec<Advertisement>, GitError> {
    let mut result = Vec::new();
    for raw_line in stdout.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(separator) = line.iter().position(|byte| *byte == b'\t') else {
            continue;
        };
        let (oid, reference) = line.split_at(separator);
        let reference = &reference[1..];
        let oid = std::str::from_utf8(oid).map_err(|_| GitError::SelectorUnresolvable)?;
        let reference =
            std::str::from_utf8(reference).map_err(|_| GitError::SelectorUnresolvable)?;
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
    if scheme == Some("ssh") {
        return Err(GitError::SshUnsupported);
    }
    if scheme != Some("https") {
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

fn classify_command_failure(_operation: &str, stderr: &[u8]) -> GitError {
    let lower = String::from_utf8_lossy(stderr).to_ascii_lowercase();
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
    ]
}

fn config_args() -> Vec<OsString> {
    vec![
        arg("-c"),
        arg("protocol.allow=never"),
        arg("-c"),
        arg("protocol.https.allow=always"),
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
mod tests;
