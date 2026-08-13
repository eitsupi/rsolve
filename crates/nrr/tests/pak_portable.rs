use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use nrr::{PakArtifact, PakInstallRequest, PakProcessConfig, run_pak};
use sha2::{Digest, Sha256};

fn required_absolute(name: &str) -> PathBuf {
    let value = env::var_os(name).unwrap_or_else(|| panic!("{name} is required"));
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "{name} must be absolute");
    assert!(path.exists(), "{name} does not exist: {}", path.display());
    path
}

fn fresh_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "nrr-pak-portable-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create fresh test root");
    root
}

fn fixture_repository(root: &Path) -> PathBuf {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../nrr-repository/tests/fixtures/closure");
    let repository = root.join("repository");
    let contrib = repository.join("src/contrib");
    fs::create_dir_all(&contrib).expect("create fixture repository");
    fs::copy(source.join("PACKAGES"), contrib.join("PACKAGES")).expect("copy PACKAGES");
    for package in ["leaf", "middle", "root"] {
        let archive = format!("{package}_0.1.0.tar.gz");
        fs::copy(
            source.join("artifacts").join(&archive),
            contrib.join(&archive),
        )
        .expect("copy fixture archive");
    }
    assert!(!contrib.join("PACKAGES.rds").exists());
    assert!(!contrib.join("PACKAGES.gz").exists());
    repository
}

fn artifacts(repository: &Path) -> Vec<PakArtifact> {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../nrr-repository/tests/fixtures/closure/SHA256SUMS");
    let manifest: BTreeMap<_, _> = fs::read_to_string(source)
        .expect("read fixture manifest")
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            (
                fields.next().expect("fixture digest"),
                fields.next().expect("fixture name"),
            )
        })
        .map(|(digest, name)| (name.to_owned(), digest.to_owned()))
        .collect();
    ["leaf", "middle", "root"]
        .into_iter()
        .map(|package| {
            let name = format!("{package}_0.1.0.tar.gz");
            PakArtifact {
                package: package.to_owned(),
                path: repository.join("src/contrib").join(&name),
                sha256: {
                    let bytes = fs::read(repository.join("src/contrib").join(&name))
                        .expect("read fixture archive");
                    let digest = format!("{:x}", Sha256::digest(bytes));
                    assert_eq!(digest, manifest[&name]);
                    digest
                },
            }
        })
        .collect()
}

fn config(root: &Path, repository: &Path, project: &Path) -> PakProcessConfig {
    PakProcessConfig {
        rscript: required_absolute("NRR_RSCRIPT"),
        pak_library: required_absolute("NRR_PAK_LIBRARY"),
        pak_private_library: required_absolute("NRR_PAK_PRIVATE_LIBRARY"),
        repository: repository.to_owned(),
        project_library: project.to_owned(),
        home: root.join("home"),
        r_user: root.join("r-user"),
        user_cache: root.join("cache/r-user"),
        package_cache: root.join("cache/r-pkg"),
        xdg_cache: root.join("cache/xdg"),
        tmp: root.join("tmp"),
        package_file: root.join("package-names.txt"),
        result_file: root.join("pak-result.dcf"),
        path: env::var_os("PATH"),
    }
}

fn wrong_order_install(config: &PakProcessConfig) -> std::process::Output {
    let repository_url = url::Url::from_directory_path(&config.repository)
        .expect("fixture repository URL")
        .to_string();
    let mut command = Command::new(&config.rscript);
    command
        .args([
            "--vanilla",
            "--slave",
            "-e",
            r#"
repo <- Sys.getenv("NRR_NEGATIVE_REPOSITORY")
lib <- Sys.getenv("NRR_NEGATIVE_LIBRARY")
pak_library <- Sys.getenv("NRR_NEGATIVE_PAK_LIBRARY")
private_library <- Sys.getenv("NRR_NEGATIVE_PRIVATE_LIBRARY")
dir.create(lib, recursive = TRUE, showWarnings = FALSE)
.libPaths(c(lib, pak_library, private_library, .Library))
options(repos = c(nrr = repo))
library(pak, lib.loc = pak_library)
pak::pkg_install("root", lib = lib, ask = FALSE, dependencies = FALSE)
"#,
        ])
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
        .env("NRR_NEGATIVE_REPOSITORY", repository_url)
        .env("NRR_NEGATIVE_LIBRARY", &config.project_library)
        .env("NRR_NEGATIVE_PAK_LIBRARY", &config.pak_library)
        .env("NRR_NEGATIVE_PRIVATE_LIBRARY", &config.pak_private_library);
    let separator = if cfg!(windows) { ";" } else { ":" };
    command.env(
        "R_LIBS",
        format!(
            "{}{}{}",
            config.pak_library.display(),
            separator,
            config.pak_private_library.display()
        ),
    );
    if let Some(path) = &config.path {
        command.env("PATH", path);
    }
    command.output().expect("run wrong-order R control")
}

fn prepare_root(root: &Path) {
    for directory in [
        "home",
        "r-user",
        "cache/r-user",
        "cache/r-pkg",
        "cache/xdg",
        "tmp",
        "library",
    ] {
        fs::create_dir_all(root.join(directory)).expect("create controlled directory");
    }
}

fn assert_installed(result: &nrr::PakInstallResult, project: &Path, expected: &[&str]) {
    assert_eq!(result.calls, expected);
    assert_eq!(result.pak_calls, 1);
    assert_eq!(result.installed.len(), expected.len());
    let actual_names: std::collections::BTreeSet<_> = result
        .installed
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    let expected_names: std::collections::BTreeSet<_> = expected.iter().copied().collect();
    assert_eq!(actual_names, expected_names);
    for installed in &result.installed {
        assert_eq!(installed.version, "0.1.0");
        assert!(
            installed
                .path
                .starts_with(project.to_str().expect("UTF-8 project path"))
        );
    }
    let repository_url = url::Url::from_directory_path(
        project
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("repository"),
    )
    .expect("fixture repository URL")
    .to_string();
    assert_eq!(
        result.repository_url.trim_end_matches('/'),
        repository_url.trim_end_matches('/')
    );
    assert_eq!(result.pak_status, "ok");
    for installed in &result.installed {
        assert_eq!(
            installed.remote_repository.trim_end_matches('/'),
            repository_url.trim_end_matches('/')
        );
        assert_eq!(installed.remote_ref, installed.name);
        assert_eq!(installed.status, "OK");
    }
}

#[test]
fn portable_pak_contract_uses_single_call_and_dependency_aware_success() {
    assert_eq!(env::var("NRR_TEST_MODE").as_deref(), Ok("pak-portable"));
    let root = fresh_root("contract");
    let repository = fixture_repository(&root);
    let artifact_list = artifacts(&repository);

    let wrong_root = root.join("wrong");
    prepare_root(&wrong_root);
    let wrong_project = wrong_root.join("library");
    let wrong = wrong_order_install(&config(&wrong_root, &repository, &wrong_project));
    assert!(!wrong.status.success());
    for package in ["leaf", "middle", "root"] {
        assert!(
            !wrong_project.join(package).exists(),
            "wrong-order install left {package}"
        );
    }

    let correct_root = root.join("correct");
    prepare_root(&correct_root);
    let correct_project = correct_root.join("library");
    let result = run_pak(
        &config(&correct_root, &repository, &correct_project),
        &PakInstallRequest {
            packages: vec!["root", "middle", "leaf"]
                .into_iter()
                .map(String::from)
                .collect(),
            artifacts: artifact_list.clone(),
        },
    )
    .expect("dependency-first pak install");
    assert_installed(&result, &correct_project, &["root", "middle", "leaf"]);
    let installed: BTreeMap<_, _> = result
        .installed
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect();
    assert_eq!(installed.len(), 3);
    assert!(
        installed["middle"]
            .imports
            .as_deref()
            .unwrap_or("")
            .contains("leaf")
    );
    assert!(
        installed["root"]
            .linking_to
            .as_deref()
            .unwrap_or("")
            .contains("middle")
    );
    assert!(
        installed["middle"]
            .description
            .as_deref()
            .unwrap_or("")
            .contains("café")
    );

    fs::remove_dir_all(root).expect("remove test root");
}
