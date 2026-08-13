//! Acceptance test for the plain source repository consumed by R.
//!
//! This is an opt-in nextest target because it requires R and a native
//! compiler. It deliberately uses only the checked-in fixture archives.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use nrr_core::{
    ArtifactLocator, DependencyKind, DependencyRequirement, DependencySourceConstraint,
    PackageName, Provenance, RPackageVersion, RelationOp, ReleaseIdentity, ReleaseMetadata,
    SourceArtifact, SourceScheme, VersionClause, VersionConstraint,
};
use nrr_repository::{
    MaterializationArtifact, MaterializationRequest, commit_source_artifact, materialize,
};
use sha2::{Digest, Sha256};
use url::Url;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/closure")
}

fn sha256(path: &Path) -> String {
    let digest = Sha256::digest(fs::read(path).expect("read fixture archive"));
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fixture_manifest(root: &Path) -> BTreeMap<String, String> {
    fs::read_to_string(root.join("SHA256SUMS"))
        .expect("read fixture manifest")
        .lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .map(|(digest, name)| (name.trim().to_owned(), digest.to_owned()))
        .collect()
}

fn dependency(kind: DependencyKind, package: &str) -> DependencyRequirement {
    dependency_with_constraint(kind, package, VersionConstraint::any())
}

fn dependency_with_constraint(
    kind: DependencyKind,
    package: &str,
    constraint: VersionConstraint,
) -> DependencyRequirement {
    DependencyRequirement::new(
        kind,
        PackageName::new(package).expect("valid fixture package name"),
        DependencySourceConstraint::Any,
        constraint,
    )
}

fn artifact(
    cache: &Path,
    source: &Path,
    package: &str,
    metadata: ReleaseMetadata,
    dependencies: Vec<DependencyRequirement>,
) -> MaterializationArtifact {
    let bytes = fs::read(source).expect("read fixture source");
    let source_artifact = SourceArtifact {
        locator: ArtifactLocator::new(format!("fixture://closure/{package}")).unwrap(),
        upstream_checksums: Vec::new(),
        size: Some(bytes.len() as u64),
    };
    let cached = commit_source_artifact(cache, &source_artifact, bytes.as_slice())
        .expect("commit fixture to shared cache");
    let identity = ReleaseIdentity::new(
        PackageName::new(package).unwrap(),
        Provenance::ImmutableSource {
            scheme: SourceScheme::new("fixture").unwrap(),
            digest: cached.sha256.clone(),
        },
    );
    MaterializationArtifact::new(identity, RPackageVersion::parse("0.1.0").unwrap(), cached)
        .with_metadata(metadata, dependencies)
}

fn run_r(repository_url: &str, library: &Path, script: &str) {
    let script_path = library.parent().unwrap().join("interop.R");
    fs::write(&script_path, script).expect("write R acceptance script");
    let rscript = env::var_os("NRR_RSCRIPT").unwrap_or_else(|| "Rscript".into());
    let output = Command::new(rscript)
        .arg("--vanilla")
        .arg(&script_path)
        .env("NRR_REPOSITORY", repository_url)
        .env("NRR_LIBRARY", library)
        .output()
        .expect("run R acceptance script");
    assert!(
        output.status.success(),
        "R acceptance failed (status={}):\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!(
        "NRR_R_INTEROP status=ok stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn repository_round_trips_through_real_r() {
    let fixture = fixture_root();
    let manifest = fixture_manifest(&fixture);
    let temp = env::temp_dir().join(format!("nrr-repository-r-interop-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).expect("create acceptance temp root");
    let root = temp.join("repository-r-interop");
    let cache = temp.join("shared cache");
    let library = root.join("library project");
    fs::create_dir_all(&library).expect("create R library");
    for package in ["leaf", "middle", "root"] {
        let archive = fixture
            .join("artifacts")
            .join(format!("{package}_0.1.0.tar.gz"));
        assert_eq!(
            manifest.get(archive.file_name().unwrap().to_str().unwrap()),
            Some(&sha256(&archive))
        );
    }
    let leaf_meta =
        ReleaseMetadata::from_pairs([(String::from("License"), String::from("MIT"))]).unwrap();
    let middle_meta = ReleaseMetadata::from_pairs([
        (String::from("License"), String::from("MIT")),
        (
            String::from("Description"),
            String::from("UTF-8 middle package – café.\n folded metadata line."),
        ),
    ])
    .unwrap();
    let root_meta =
        ReleaseMetadata::from_pairs([(String::from("License"), String::from("MIT"))]).unwrap();
    let selected = vec![
        artifact(
            &cache,
            &fixture.join("artifacts/leaf_0.1.0.tar.gz"),
            "leaf",
            leaf_meta,
            vec![],
        ),
        artifact(
            &cache,
            &fixture.join("artifacts/middle_0.1.0.tar.gz"),
            "middle",
            middle_meta,
            vec![dependency_with_constraint(
                DependencyKind::Imports,
                "leaf",
                VersionConstraint::new(vec![
                    VersionClause::new(RelationOp::Ge, RPackageVersion::parse("0.1.0").unwrap()),
                    VersionClause::new(RelationOp::Lt, RPackageVersion::parse("0.2.0").unwrap()),
                ]),
            )],
        ),
        artifact(
            &cache,
            &fixture.join("artifacts/root_0.1.0.tar.gz"),
            "root",
            root_meta,
            vec![dependency(DependencyKind::LinkingTo, "middle")],
        ),
    ];
    let state = materialize(MaterializationRequest::new(&root, &selected))
        .expect("materialize selected closure");
    assert_eq!(state.schema_version, 2);
    let contrib = root.join(".nrr/repository/src/contrib");
    assert!(contrib.join("PACKAGES").is_file());
    assert_eq!(
        fs::read(contrib.join("PACKAGES")).expect("read generated PACKAGES"),
        fs::read(fixture.join("PACKAGES")).expect("read checked PACKAGES fixture")
    );
    assert!(!contrib.join("PACKAGES.rds").exists());
    assert!(!contrib.join("PACKAGES.gz").exists());
    let r_script = r#"
repo <- Sys.getenv("NRR_REPOSITORY")
lib <- Sys.getenv("NRR_LIBRARY")
dir.create(lib, recursive=TRUE, showWarnings=FALSE)
.libPaths(c(lib, .Library, .Library.site))
ap <- available.packages(repos=repo, type="source", fields=c("Depends", "Imports", "LinkingTo", "Description"))
stopifnot(all(c("leaf", "middle", "root") %in% rownames(ap)))
stopifnot(all(ap[c("leaf", "middle", "root"), "Version"] == "0.1.0"))
stopifnot(grepl("leaf (>= 0.1.0, < 0.2.0)", ap["middle", "Imports"], fixed=TRUE))
stopifnot(grepl("middle", ap["root", "LinkingTo"], fixed=TRUE))
stopifnot(grepl("café", ap["middle", "Description"], fixed=TRUE))
stopifnot(grepl("folded metadata line", ap["middle", "Description"], fixed=TRUE))
# A fresh library must fail when the native LinkingTo dependency is absent.
wrong <- file.path(dirname(lib), "wrong-order-library")
dir.create(wrong, recursive=TRUE, showWarnings=FALSE)
bad <- tryCatch({
  .libPaths(c(wrong, .Library, .Library.site))
  options(warn=2)
  install.packages("root", lib=wrong, repos=repo, type="source", dependencies=FALSE, quiet=TRUE)
  FALSE
}, error=function(e) TRUE)
stopifnot(bad)
stopifnot(!dir.exists(file.path(lib, "middle")))
.libPaths(c(lib, .Library, .Library.site))
install.packages("leaf", lib=lib, repos=repo, type="source", dependencies=FALSE, quiet=TRUE)
install.packages("middle", lib=lib, repos=repo, type="source", dependencies=FALSE, quiet=TRUE)
install.packages("root", lib=lib, repos=repo, type="source", dependencies=FALSE, quiet=TRUE)
stopifnot(as.character(packageVersion("leaf", lib.loc=lib)) == "0.1.0")
stopifnot(as.character(packageVersion("middle", lib.loc=lib)) == "0.1.0")
stopifnot(as.character(packageVersion("root", lib.loc=lib)) == "0.1.0")
stopifnot(requireNamespace("middle", quietly=TRUE, lib.loc=lib))
stopifnot(requireNamespace("root", quietly=TRUE, lib.loc=lib))
stopifnot(middle::middle_value() == "middle-leaf-ok")
middle_dcf <- read.dcf(file.path(lib, "middle", "DESCRIPTION"))
root_dcf <- read.dcf(file.path(lib, "root", "DESCRIPTION"))
stopifnot(middle_dcf[1, "Version"] == "0.1.0")
stopifnot(grepl("leaf", middle_dcf[1, "Imports"], fixed=TRUE))
stopifnot(grepl("café", middle_dcf[1, "Description"], fixed=TRUE))
stopifnot(root_dcf[1, "Version"] == "0.1.0")
stopifnot(grepl("middle", root_dcf[1, "LinkingTo"], fixed=TRUE))
cat("NRR_R_INTEROP available_packages=ok install_order=ok wrong_order=failed\n")
"#;
    let repository_url = Url::from_directory_path(root.join(".nrr/repository"))
        .unwrap()
        .to_string();
    assert!(repository_url.starts_with("file://"));
    run_r(&repository_url, &library, r_script);
    let _ = fs::remove_dir_all(temp);
}
