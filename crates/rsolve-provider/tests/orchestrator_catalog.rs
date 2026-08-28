//! Independent acceptance checks by the orchestrator, not the implementer.
use rsolve_core::*;
use rsolve_provider::cran::CranCatalog;

const PACKAGES: &[u8] = include_bytes!("fixtures/cran-2026-08-08/synthetic-PACKAGES");

fn catalog() -> CranCatalog {
    CranCatalog::from_packages(PACKAGES).expect("fixture must parse")
}

fn only(c: &CranCatalog, name: &str) -> PackageRelease {
    let n = PackageName::new(name).unwrap();
    let v = c.candidates(&n);
    assert_eq!(v.len(), 1, "{name} should have one candidate");
    v[0].clone()
}

#[test]
fn r_survives_as_a_real_requirement() {
    let c = catalog();
    let core = only(&c, "rsolvefixture.core");
    let r = core
        .declared_dependencies()
        .iter()
        .find(|d| d.package.name().as_str() == "R")
        .expect("Depends: R (>= 4.6.0) must reach the model, not be filtered out");
    assert_eq!(r.kind, DependencyKind::Depends);
    assert!(
        r.package
            .constraint()
            .satisfies(&RPackageVersion::parse("4.6.0").unwrap())
    );
    assert!(
        r.package
            .constraint()
            .satisfies(&RPackageVersion::parse("4.6").unwrap()),
        "4.6 == 4.6.0"
    );
    assert!(
        !r.package
            .constraint()
            .satisfies(&RPackageVersion::parse("4.5.1").unwrap())
    );
}

#[test]
fn folded_dependency_list_is_split_into_entries() {
    let c = catalog();
    let core = only(&c, "rsolvefixture.core");
    let mut imports: Vec<_> = core
        .declared_dependencies()
        .iter()
        .filter(|d| d.kind == DependencyKind::Imports)
        .map(|d| d.package.name().as_str().to_owned())
        .collect();
    imports.sort();
    assert_eq!(
        imports,
        vec!["rsolvefixture.import", "rsolvefixture.import.helper"],
        "a value folded across lines must yield two entries, not one concatenation"
    );
}

#[test]
fn all_five_dependency_kinds_are_represented() {
    let c = catalog();
    let core = only(&c, "rsolvefixture.core");
    for kind in [
        DependencyKind::Depends,
        DependencyKind::Imports,
        DependencyKind::LinkingTo,
        DependencyKind::Suggests,
        DependencyKind::Enhances,
    ] {
        assert!(
            core.declared_dependencies().iter().any(|d| d.kind == kind),
            "{kind:?} missing from the parsed record"
        );
    }
}

#[test]
fn unconstrained_dependency_accepts_any_version() {
    let c = catalog();
    let core = only(&c, "rsolvefixture.core");
    let base = core
        .declared_dependencies()
        .iter()
        .find(|d| d.package.name().as_str() == "rsolvefixture.base")
        .expect("bare dependency name must be kept");
    for v in ["0.0.1", "99.0"] {
        assert!(
            base.package
                .constraint()
                .satisfies(&RPackageVersion::parse(v).unwrap())
        );
    }
}

#[test]
fn a_malformed_record_is_reported_not_silently_dropped() {
    let mut broken = PACKAGES.to_vec();
    broken.extend_from_slice(b"\nPackage: rsolvefixture.broken\nVersion: not-a-version\n");
    let error = CranCatalog::from_packages(&broken).unwrap_err();
    assert_eq!(error.diagnostics().len(), 1);
    let d = &error.diagnostics()[0];
    assert_eq!(
        d.package(),
        Some("rsolvefixture.broken"),
        "diagnostic names the record"
    );
}
