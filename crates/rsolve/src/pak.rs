//! Narrow boundary for driving an external pak process.
//!
//! rsolve passes an already-selected closure to one pak request. Package builds,
//! dependency scheduling, system requirements, and platform installation
//! semantics remain in pak.
//!
//! The line-file process transport is an independent narrow reimplementation
//! of a pattern used by r-lib/ir (MIT, Copyright (c) 2026 Posit Software, PBC,
//! source commit df455a4513034180306d219f5e8cc052163782ff); it does not copy
//! that project's code or installer semantics.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use rsolve_core::{PackageName, RPackageVersion};
use sha2::{Digest, Sha256};

/// Paths and environment required by one isolated child R process.
#[derive(Clone, Debug)]
pub struct PakProcessConfig {
    pub rscript: PathBuf,
    pub pak_library: PathBuf,
    pub pak_private_library: PathBuf,
    pub repository: PathBuf,
    pub project_library: PathBuf,
    pub home: PathBuf,
    pub r_user: PathBuf,
    pub user_cache: PathBuf,
    pub package_cache: PathBuf,
    pub xdg_cache: PathBuf,
    pub tmp: PathBuf,
    pub package_file: PathBuf,
    pub result_file: PathBuf,
    pub path: Option<OsString>,
}

/// A local artifact whose bytes are expected to be used by pak.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PakArtifact {
    pub package: String,
    pub version: String,
    pub path: PathBuf,
    pub sha256: String,
}

/// One selected closure request. Names cross the boundary one per line.
#[derive(Clone, Debug)]
pub struct PakInstallRequest {
    pub packages: Vec<String>,
    pub artifacts: Vec<PakArtifact>,
}

#[derive(Clone, Debug)]
pub struct PakInstalledPackage {
    pub name: String,
    pub version: String,
    pub imports: Option<String>,
    pub linking_to: Option<String>,
    pub description: Option<String>,
    pub path: String,
    pub remote_repository: String,
    pub remote_ref: String,
    pub remote_sha: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug)]
pub struct PakInstallResult {
    pub calls: Vec<String>,
    pub pak_calls: usize,
    pub installed: Vec<PakInstalledPackage>,
    pub repository_url: String,
    pub pak_status: String,
}

#[derive(Debug)]
pub enum PakProcessError {
    RepositoryUrl,
    InvalidPackageName(String),
    DuplicatePackageName(String),
    DuplicateArtifact(String),
    MissingArtifact(String),
    UnexpectedArtifact(String),
    InvalidArtifactDigest(String),
    InvalidArtifactVersion(String),
    Io(std::io::Error),
    Spawn(std::io::Error),
    Failed { status: String, stderr: String },
    Protocol(String),
}

impl fmt::Display for PakProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepositoryUrl => formatter.write_str("repository path cannot become a file URL"),
            Self::InvalidPackageName(name) => {
                write!(formatter, "invalid package name for protocol: {name:?}")
            }
            Self::DuplicatePackageName(name) => write!(formatter, "duplicate package: {name}"),
            Self::DuplicateArtifact(name) => write!(formatter, "duplicate artifact: {name}"),
            Self::MissingArtifact(name) => {
                write!(formatter, "missing artifact for package: {name}")
            }
            Self::UnexpectedArtifact(name) => write!(formatter, "artifact is not selected: {name}"),
            Self::InvalidArtifactDigest(name) => {
                write!(formatter, "invalid artifact digest: {name}")
            }
            Self::InvalidArtifactVersion(name) => {
                write!(formatter, "invalid artifact version: {name}")
            }
            Self::Io(error) => write!(formatter, "pak protocol file failed: {error}"),
            Self::Spawn(error) => write!(formatter, "could not start Rscript: {error}"),
            Self::Failed { status, stderr } => {
                write!(formatter, "pak R process failed ({status}): {stderr}")
            }
            Self::Protocol(error) => write!(formatter, "pak result DCF is invalid: {error}"),
        }
    }
}

impl std::error::Error for PakProcessError {}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_request(request: &PakInstallRequest) -> Result<(), PakProcessError> {
    if request.packages.is_empty() {
        return Err(PakProcessError::InvalidPackageName(
            "<empty request>".into(),
        ));
    }
    let mut packages = BTreeMap::new();
    for package in &request.packages {
        let canonical = PackageName::new(package)
            .map_err(|_| PakProcessError::InvalidPackageName(package.clone()))?;
        if packages.insert(canonical, ()).is_some() {
            return Err(PakProcessError::DuplicatePackageName(package.clone()));
        }
    }
    let mut artifacts = BTreeMap::new();
    for artifact in &request.artifacts {
        let canonical = PackageName::new(&artifact.package)
            .map_err(|_| PakProcessError::InvalidPackageName(artifact.package.clone()))?;
        RPackageVersion::parse(&artifact.version)
            .map_err(|_| PakProcessError::InvalidArtifactVersion(artifact.package.clone()))?;
        if !valid_sha256(&artifact.sha256) {
            return Err(PakProcessError::InvalidArtifactDigest(
                artifact.package.clone(),
            ));
        }
        if artifacts.insert(canonical.clone(), ()).is_some() {
            return Err(PakProcessError::DuplicateArtifact(artifact.package.clone()));
        }
        if !packages.contains_key(&canonical) {
            return Err(PakProcessError::UnexpectedArtifact(
                artifact.package.clone(),
            ));
        }
    }
    for package in packages.keys() {
        if !artifacts.contains_key(package) {
            return Err(PakProcessError::MissingArtifact(package.to_string()));
        }
    }
    Ok(())
}

struct ArtifactStaging {
    directory: PathBuf,
    archive_file: PathBuf,
}

impl Drop for ArtifactStaging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Copy each artifact into an rsolve-owned directory while hashing the bytes that
/// will subsequently be handed to pak. The staging directory is deliberately
/// created without replacement so a stale or concurrent directory cannot be
/// reused accidentally.
fn stage_artifacts(
    config: &PakProcessConfig,
    request: &PakInstallRequest,
) -> Result<ArtifactStaging, PakProcessError> {
    fs::create_dir_all(&config.tmp).map_err(PakProcessError::Io)?;
    static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);
    let directory = loop {
        let id = NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = config
            .tmp
            .join(format!(".rsolve-pak-staging-{}-{id}", std::process::id()));
        match fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(PakProcessError::Io(error)),
        }
    };
    let archive_file = directory.join("archive-paths");
    let staging = ArtifactStaging {
        directory,
        archive_file,
    };
    let mut archive_paths = Vec::with_capacity(request.artifacts.len());

    for artifact in &request.artifacts {
        let package_directory = staging.directory.join(&artifact.package);
        fs::create_dir(&package_directory).map_err(PakProcessError::Io)?;
        let archive =
            package_directory.join(format!("{}_{}.tar.gz", artifact.package, artifact.version));
        let mut source = fs::File::open(&artifact.path).map_err(PakProcessError::Io)?;
        let mut target = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&archive)
            .map_err(PakProcessError::Io)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = source.read(&mut buffer).map_err(PakProcessError::Io)?;
            if count == 0 {
                break;
            }
            target
                .write_all(&buffer[..count])
                .map_err(PakProcessError::Io)?;
            digest.update(&buffer[..count]);
        }
        target.flush().map_err(PakProcessError::Io)?;
        let actual = format!("{:x}", digest.finalize());
        if actual != artifact.sha256.to_ascii_lowercase() {
            return Err(PakProcessError::InvalidArtifactDigest(
                artifact.package.clone(),
            ));
        }
        let archive_path = archive
            .to_str()
            .ok_or_else(|| PakProcessError::Protocol("staged archive path is not UTF-8".into()))?;
        archive_paths.push(percent_encode(archive_path.as_bytes(), NON_ALPHANUMERIC).to_string());
    }
    let mut archive_manifest = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging.archive_file)
        .map_err(PakProcessError::Io)?;
    archive_manifest
        .write_all((archive_paths.join("\n") + "\n").as_bytes())
        .map_err(PakProcessError::Io)?;
    Ok(staging)
}

const PAK_PROGRAM: &str = r#"
project <- normalizePath(Sys.getenv("RSOLVE_PAK_PROJECT_LIBRARY"), mustWork = FALSE)
pak_library <- normalizePath(Sys.getenv("RSOLVE_PAK_LIBRARY"), mustWork = FALSE)
private_library <- normalizePath(Sys.getenv("RSOLVE_PAK_PRIVATE_LIBRARY"), mustWork = FALSE)
repository_url <- Sys.getenv("RSOLVE_PAK_REPOSITORY_URL")
package_file <- Sys.getenv("RSOLVE_PAK_PACKAGE_FILE")
archive_file <- Sys.getenv("RSOLVE_PAK_ARCHIVE_FILE")
result_file <- Sys.getenv("RSOLVE_PAK_RESULT_FILE")
dir.create(project, recursive = TRUE, showWarnings = FALSE)
.libPaths(c(project, pak_library, private_library, .Library))
options(repos = c(rsolve = repository_url))
library(pak, lib.loc = pak_library)
packages <- readLines(package_file, warn = FALSE, encoding = "UTF-8")
archives <- utils::URLdecode(readLines(archive_file, warn = FALSE, encoding = "UTF-8"))
calls <- packages
invisible(capture.output(pak::pkg_install(archives, lib = project, ask = FALSE, dependencies = NA)))
installed <- lapply(calls, function(package) {
  description <- packageDescription(package, lib.loc = project)
  value <- function(name) {
    field <- description[[name]]
    if (is.null(field) || is.na(field)) "" else as.character(field)
  }
  list(
    name = value("Package"),
    version = value("Version"),
    imports = value("Imports"),
    linking_to = value("LinkingTo"),
    description = value("Description"),
    path = normalizePath(file.path(project, package), mustWork = TRUE)
  )
})
status_table <- tryCatch(pak::pkg_status(calls, lib = project), error = function(error) NULL)
status <- if (is.null(status_table)) "error" else "ok"
metadata <- data.frame(Package = "__rsolve_protocol__", Version = "1", Imports = "", LinkingTo = "", Description = "", Path = "", RemoteRepos = "", RemotePkgRef = "", RemoteSha = "", Status = "", Repository = repository_url, PakStatus = status, PakCalls = "1", stringsAsFactors = FALSE)
records <- data.frame(Package = character(), Version = character(), Imports = character(), LinkingTo = character(), Description = character(), Path = character(), RemoteRepos = character(), RemotePkgRef = character(), RemoteSha = character(), Status = character(), Repository = character(), PakStatus = character(), PakCalls = character(), stringsAsFactors = FALSE)
for (item in installed) {
  row <- if (!is.null(status_table)) status_table[status_table$package == item$name, , drop = FALSE] else data.frame()
  value <- function(name) if (nrow(row) == 0L || is.null(row[[name]]) || is.na(row[[name]][1])) "" else as.character(row[[name]][1])
  remote_repository <- value("remoterepos")
  if (remote_repository == "") remote_repository <- repository_url
  remote_ref <- value("remotepkgref")
  if (remote_ref == "" || startsWith(remote_ref, "local::")) remote_ref <- item$name
  records <- rbind(records, data.frame(Package = item$name, Version = item$version, Imports = item$imports, LinkingTo = item$linking_to, Description = item$description, Path = item$path, RemoteRepos = remote_repository, RemotePkgRef = remote_ref, RemoteSha = value("remotesha"), Status = value("status"), Repository = "", PakStatus = "", PakCalls = "", stringsAsFactors = FALSE))
}
write.dcf(rbind(metadata, records), result_file)
"#;

/// Run the fixed pak protocol in a freshly configured child process.
fn parse_dcf(input: &str) -> Result<Vec<BTreeMap<String, String>>, PakProcessError> {
    let mut records = Vec::new();
    let mut current: BTreeMap<String, String> = BTreeMap::new();
    let mut field: Option<String> = None;
    for line in input.lines() {
        if line.is_empty() {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
            }
            field = None;
        } else if line.starts_with(' ') || line.starts_with('\t') {
            let Some(name) = field.as_ref() else {
                return Err(PakProcessError::Protocol(
                    "DCF continuation without a field".into(),
                ));
            };
            current.entry(name.clone()).and_modify(|value| {
                if !value.is_empty() {
                    value.push('\n');
                }
                value.push_str(line.trim_start());
            });
        } else {
            let Some((name, value)) = line.split_once(':') else {
                return Err(PakProcessError::Protocol(format!(
                    "invalid DCF line: {line}"
                )));
            };
            field = Some(name.to_owned());
            current.insert(
                name.to_owned(),
                value.strip_prefix(' ').unwrap_or(value).to_owned(),
            );
        }
    }
    if !current.is_empty() {
        records.push(current);
    }
    Ok(records)
}

pub fn run_pak(
    config: &PakProcessConfig,
    request: &PakInstallRequest,
) -> Result<PakInstallResult, PakProcessError> {
    validate_request(request)?;
    let staging = stage_artifacts(config, request)?;
    let repository_url = url::Url::from_directory_path(&config.repository)
        .map_err(|_| PakProcessError::RepositoryUrl)?
        .to_string();
    let package_input = request.packages.join("\n") + "\n";
    fs::write(&config.package_file, package_input).map_err(PakProcessError::Io)?;
    let _ = fs::remove_file(&config.result_file);

    let mut command = Command::new(&config.rscript);
    command
        .args(["--vanilla", "--slave", "-e", PAK_PROGRAM])
        .env_clear()
        .env("HOME", &config.home)
        .env("R_USER", &config.r_user)
        .env("R_USER_CACHE_DIR", &config.user_cache)
        .env("R_PKG_CACHE_DIR", &config.package_cache)
        .env("XDG_CACHE_HOME", &config.xdg_cache)
        .env("TMPDIR", &config.tmp)
        .env("TMP", &config.tmp)
        .env("TEMP", &config.tmp)
        .env("R_LIBS_USER", &config.project_library)
        .env("R_LIBS_SITE", "")
        .env("R_PROFILE_USER", "")
        .env("R_ENVIRON_USER", "")
        .env("PKG_SYSREQS", "false")
        .env("R_PKG_SYSREQS2", "false")
        .env("RSOLVE_PAK_PROJECT_LIBRARY", &config.project_library)
        .env("RSOLVE_PAK_LIBRARY", &config.pak_library)
        .env("RSOLVE_PAK_PRIVATE_LIBRARY", &config.pak_private_library)
        .env("RSOLVE_PAK_REPOSITORY_URL", &repository_url)
        .env("RSOLVE_PAK_PACKAGE_FILE", &config.package_file)
        .env("RSOLVE_PAK_ARCHIVE_FILE", &staging.archive_file)
        .env("RSOLVE_PAK_RESULT_FILE", &config.result_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = &config.path {
        command.env("PATH", path);
    }
    for variable in ["LANG", "LC_ALL", "LC_CTYPE"] {
        if let Some(value) = std::env::var_os(variable) {
            command.env(variable, value);
        }
    }
    let separator = if cfg!(windows) { ";" } else { ":" };
    let r_libs = format!(
        "{}{}{}",
        config.pak_library.display(),
        separator,
        config.pak_private_library.display()
    );
    command.env("R_LIBS", r_libs);
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    let child = command.spawn().map_err(PakProcessError::Spawn)?;
    let output = child.wait_with_output().map_err(PakProcessError::Spawn)?;
    if !output.status.success() {
        return Err(PakProcessError::Failed {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let output_file = fs::read_to_string(&config.result_file).map_err(PakProcessError::Io)?;
    let records = parse_dcf(&output_file)?;
    let Some(protocol) = records
        .iter()
        .find(|record| record.get("Package").map(String::as_str) == Some("__rsolve_protocol__"))
    else {
        return Err(PakProcessError::Protocol(
            "missing protocol DCF record".into(),
        ));
    };
    let installed = records
        .iter()
        .filter(|record| record.get("Package").map(String::as_str) != Some("__rsolve_protocol__"))
        .map(|record| {
            let required = |name: &str| {
                record
                    .get(name)
                    .filter(|value| !value.is_empty())
                    .cloned()
                    .ok_or_else(|| {
                        PakProcessError::Protocol(format!("installed record lacks {name}"))
                    })
            };
            Ok(PakInstalledPackage {
                name: required("Package")?,
                version: required("Version")?,
                imports: record
                    .get("Imports")
                    .filter(|value| !value.is_empty())
                    .cloned(),
                linking_to: record
                    .get("LinkingTo")
                    .filter(|value| !value.is_empty())
                    .cloned(),
                description: record
                    .get("Description")
                    .filter(|value| !value.is_empty())
                    .cloned(),
                path: required("Path")?,
                remote_repository: required("RemoteRepos")?,
                remote_ref: required("RemotePkgRef")?,
                remote_sha: record
                    .get("RemoteSha")
                    .filter(|value| !value.is_empty())
                    .cloned(),
                status: required("Status")?,
            })
        })
        .collect::<Result<Vec<_>, PakProcessError>>()?;
    let expected_names: std::collections::BTreeSet<_> =
        request.packages.iter().map(String::as_str).collect();
    let actual_names: std::collections::BTreeSet<_> = installed
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    if installed.len() != expected_names.len() || actual_names != expected_names {
        return Err(PakProcessError::Protocol(
            "installed package names do not match request".into(),
        ));
    }
    Ok(PakInstallResult {
        calls: request.packages.clone(),
        pak_calls: protocol
            .get("PakCalls")
            .ok_or_else(|| PakProcessError::Protocol("missing PakCalls".into()))?
            .parse()
            .map_err(|_| PakProcessError::Protocol("invalid PakCalls".into()))?,
        installed,
        repository_url: protocol.get("Repository").cloned().unwrap_or_default(),
        pak_status: protocol.get("PakStatus").cloned().unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{PakArtifact, PakInstallRequest, PakProcessError, parse_dcf, validate_request};

    fn artifact(package: &str) -> PakArtifact {
        PakArtifact {
            package: package.into(),
            version: "0.1.0".into(),
            path: PathBuf::from(format!("/tmp/{package}.tar.gz")),
            sha256: "a".repeat(64),
        }
    }

    #[test]
    fn request_requires_unique_selected_names_and_artifact_coverage() {
        let duplicate = PakInstallRequest {
            packages: vec!["leaf".into(), "leaf".into()],
            artifacts: vec![artifact("leaf")],
        };
        assert!(matches!(
            validate_request(&duplicate),
            Err(PakProcessError::DuplicatePackageName(_))
        ));

        let missing = PakInstallRequest {
            packages: vec!["leaf".into(), "root".into()],
            artifacts: vec![artifact("leaf")],
        };
        assert!(matches!(
            validate_request(&missing),
            Err(PakProcessError::MissingArtifact(_))
        ));
    }

    #[test]
    fn request_rejects_unselected_artifacts_and_bad_digests() {
        let unexpected = PakInstallRequest {
            packages: vec!["leaf".into()],
            artifacts: vec![artifact("middle")],
        };
        assert!(matches!(
            validate_request(&unexpected),
            Err(PakProcessError::UnexpectedArtifact(_))
        ));

        let mut bad = artifact("leaf");
        bad.sha256 = "not-a-digest".into();
        let request = PakInstallRequest {
            packages: vec!["leaf".into()],
            artifacts: vec![bad],
        };
        assert!(matches!(
            validate_request(&request),
            Err(PakProcessError::InvalidArtifactDigest(_))
        ));
    }

    #[test]
    fn request_rejects_non_canonical_package_coordinates() {
        for value in ["user/repo", "foo@1.0.0", "./local-package"] {
            let request = PakInstallRequest {
                packages: vec![value.into()],
                artifacts: vec![artifact(value)],
            };
            assert!(matches!(
                validate_request(&request),
                Err(PakProcessError::InvalidPackageName(name)) if name == value
            ));
        }

        for value in ["user/repo", "foo@1.0.0", "./local-package"] {
            let request = PakInstallRequest {
                packages: vec!["valid".into()],
                artifacts: vec![artifact(value)],
            };
            assert!(matches!(
                validate_request(&request),
                Err(PakProcessError::InvalidPackageName(name)) if name == value
            ));
        }
    }

    #[test]
    fn request_rejects_invalid_artifact_versions() {
        let mut invalid = artifact("leaf");
        invalid.version = "not-a-version".into();
        let request = PakInstallRequest {
            packages: vec!["leaf".into()],
            artifacts: vec![invalid],
        };
        assert!(matches!(
            validate_request(&request),
            Err(PakProcessError::InvalidArtifactVersion(name)) if name == "leaf"
        ));
    }

    #[test]
    fn dcf_parser_accepts_crlf_records_and_continuations() {
        let records = parse_dcf("Package: demo\r\nDescription: first\r\n second\r\n\r\n")
            .expect("CRLF DCF should parse");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].get("Package").map(String::as_str), Some("demo"));
        assert_eq!(
            records[0].get("Description").map(String::as_str),
            Some("first\nsecond")
        );
    }
}
