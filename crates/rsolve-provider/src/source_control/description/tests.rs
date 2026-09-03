use super::*;
use crate::source_control::tree::{self, TreeEntry};
use rsolve_core::{
    DependencyKind, DependencySourceConstraint, GitCommitId, NormalizedGitUrl, PackageName,
    PackageRequirement, Provenance, RPackageVersion, RelationOp, ReleaseIdentity,
    VersionConstraint,
};

fn identity(package: &str) -> ReleaseIdentity {
    ReleaseIdentity::new(
        PackageName::new(package).unwrap(),
        Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/project.git").unwrap(),
            commit: GitCommitId::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
            subdirectory: None,
        },
    )
}

fn view(root: &Path, description: &[u8]) -> ImmutableSourceView {
    tree::publish(
        root.join("view"),
        [TreeEntry::regular("DESCRIPTION", description.to_vec())],
    )
    .unwrap()
}

fn expected(package: &str, constraint: VersionConstraint) -> PackageRequirement {
    PackageRequirement::new(
        PackageName::new(package).unwrap(),
        DependencySourceConstraint::Any,
        constraint,
    )
    .unwrap()
}

fn project(
    view: &ImmutableSourceView,
    identity: &ReleaseIdentity,
    expected: &PackageRequirement,
) -> Result<PackageRelease, DescriptionProjectionError> {
    project_description(view, DescriptionProjectionRequest::new(identity, expected))
}

#[test]
fn projects_one_record_with_canonical_identity_and_dependencies() {
    let root = tempfile::tempdir().unwrap();
    let source = view(
        root.path(),
        b"Package: demo\nVersion: 1.7-0\nLicense: MIT\nDepends: R (>= 4.0)\nImports: cli (>= 1.0), jsonlite\nLinkingTo: cpp11\nSuggests: testthat\nEnhances: knitr\n",
    );
    let identity = identity("demo");
    let expected = expected("demo", VersionConstraint::any());

    let release = project(&source, &identity, &expected).unwrap();
    assert_eq!(release.identity(), &identity);
    assert_eq!(release.version(), &RPackageVersion::parse("1.7.0").unwrap());
    assert_eq!(
        release.metadata().fields().get("License"),
        Some(&"MIT".to_owned())
    );
    assert!(!release.metadata().fields().contains_key("Package"));
    assert!(!release.metadata().fields().contains_key("Version"));
    assert_eq!(release.distributions(), &[]);
    assert_eq!(release.declared_dependencies().len(), 6);
    assert_eq!(
        release.declared_dependencies()[0].kind,
        DependencyKind::Depends
    );
    assert_eq!(
        release.declared_dependencies()[0].package.name().as_str(),
        "R"
    );
    assert_eq!(
        release.declared_dependencies()[1]
            .package
            .constraint()
            .clauses[0]
            .op,
        RelationOp::Ge
    );
}

#[test]
fn rejects_missing_description() {
    let root = tempfile::tempdir().unwrap();
    let view = tree::publish(root.path().join("view"), std::iter::empty()).unwrap();
    let identity = identity("demo");
    let expected = expected("demo", VersionConstraint::any());
    assert!(matches!(
        project(&view, &identity, &expected),
        Err(DescriptionProjectionError::Missing { .. })
    ));
}

#[test]
fn rejects_oversized_description() {
    let root = tempfile::tempdir().unwrap();
    let mut description = vec![b'x'; MAX_DESCRIPTION_BYTES as usize + 1];
    description[0] = b'P';
    let source = view(root.path(), &description);
    let identity = identity("demo");
    let expected = expected("demo", VersionConstraint::any());
    assert!(matches!(
        project(&source, &identity, &expected),
        Err(DescriptionProjectionError::TooLarge { .. })
    ));
}

#[cfg(unix)]
#[test]
fn rejects_description_symlink() {
    let root = tempfile::tempdir().unwrap();
    let source = view(root.path(), b"Package: demo\nVersion: 1.0\n");
    let description = source.path().join("DESCRIPTION");
    std::fs::remove_file(&description).unwrap();
    std::os::unix::fs::symlink(root.path().join("target"), description).unwrap();
    let identity = identity("demo");
    let expected = expected("demo", VersionConstraint::any());
    assert!(matches!(
        project(&source, &identity, &expected),
        Err(DescriptionProjectionError::Symlink { .. })
    ));
}

#[cfg(unix)]
#[test]
fn keeps_reading_the_validated_directory_after_path_replacement() {
    let root = tempfile::tempdir().unwrap();
    let source = view(root.path(), b"Package: demo\nVersion: 1.0\n");
    let view_path = root.path().join("view");
    std::fs::rename(&view_path, root.path().join("original")).unwrap();
    let _replacement = view(root.path(), b"Package: replacement\nVersion: 9.0\n");

    let identity = identity("demo");
    let expected = expected("demo", VersionConstraint::any());
    let release = project(&source, &identity, &expected).unwrap();
    assert_eq!(release.identity(), &identity);
    assert_eq!(release.version(), &RPackageVersion::parse("1.0").unwrap());
}

#[cfg(unix)]
#[test]
fn rejects_description_fifo_without_blocking() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let root = tempfile::tempdir().unwrap();
    let source = view(root.path(), b"Package: demo\nVersion: 1.0\n");
    let description = source.path().join("DESCRIPTION");
    std::fs::remove_file(&description).unwrap();
    let path = CString::new(description.as_os_str().as_bytes()).unwrap();
    let result = unsafe { libc::mkfifo(path.as_ptr(), 0o644) };
    assert_eq!(
        result,
        0,
        "mkfifo failed: {}",
        std::io::Error::last_os_error()
    );

    let identity = identity("demo");
    let expected = expected("demo", VersionConstraint::any());
    assert!(matches!(
        project(&source, &identity, &expected),
        Err(DescriptionProjectionError::NotRegular { .. })
    ));
}

#[test]
fn rejects_multiple_records_and_duplicate_fields() {
    let root = tempfile::tempdir().unwrap();
    let identity = identity("demo");
    let expected = expected("demo", VersionConstraint::any());
    let source = view(
        root.path(),
        b"Package: demo\nVersion: 1.0\n\nPackage: demo\nVersion: 1.0\n",
    );
    assert!(matches!(
        project(&source, &identity, &expected),
        Err(DescriptionProjectionError::MultipleRecords { count: 2 })
    ));

    let duplicate_root = tempfile::tempdir().unwrap();
    let duplicate = view(
        duplicate_root.path(),
        b"Package: demo\nVersion: 1.0\npackage: demo\n",
    );
    assert!(matches!(
        project(&duplicate, &identity, &expected),
        Err(DescriptionProjectionError::DuplicateField { .. })
    ));
}

#[test]
fn rejects_package_and_version_mismatch() {
    let root = tempfile::tempdir().unwrap();
    let identity = identity("demo");
    let expected = expected(
        "demo",
        VersionConstraint::from_clause(RelationOp::Ge, RPackageVersion::parse("2.0").unwrap()),
    );
    let package_mismatch = view(root.path(), b"Package: other\nVersion: 1.0\n");
    assert!(matches!(
        project(&package_mismatch, &identity, &expected),
        Err(DescriptionProjectionError::PackageMismatch { .. })
    ));

    let version_root = tempfile::tempdir().unwrap();
    let version_mismatch = view(version_root.path(), b"Package: demo\nVersion: 1.0\n");
    assert!(matches!(
        project(&version_mismatch, &identity, &expected),
        Err(DescriptionProjectionError::VersionConstraintMismatch { .. })
    ));
}
