//! Validate fixture names and dependency fields through the provider parsers.

use rsolve_core::PackageName;
use rsolve_provider::cran::{CranCatalog, DcfDocument};

const PACKAGES: &[u8] = include_bytes!("fixtures/cran-2026-08-08/synthetic-PACKAGES");
const DESCRIPTION: &[u8] = include_bytes!("fixtures/cran-2026-08-08/synthetic-DESCRIPTION");

fn package_names(document: &DcfDocument) -> impl Iterator<Item = &str> {
    document
        .records()
        .iter()
        .filter_map(|record| record.field("Package"))
        .map(|field| field.value().trim())
}

#[test]
fn every_fixture_package_name_is_valid_and_catalog_is_complete() {
    let packages = DcfDocument::parse(PACKAGES).expect("PACKAGES fixture must parse");
    let description = DcfDocument::parse(DESCRIPTION).expect("DESCRIPTION fixture must parse");

    assert_eq!(packages.records().len(), 4);
    assert_eq!(description.records().len(), 1);

    let catalog = CranCatalog::from_packages(PACKAGES).expect("PACKAGES fixture must catalog");
    assert!(
        catalog.diagnostics().is_empty(),
        "unexpected diagnostics: {:?}",
        catalog.diagnostics()
    );
    assert_eq!(catalog.package_count(), 4);
    assert_eq!(catalog.candidate_count(), 4);

    let names: Vec<_> = package_names(&packages)
        .chain(package_names(&description))
        .collect();
    assert_eq!(names.len(), 5);
    for name in names {
        PackageName::new(name)
            .unwrap_or_else(|error| panic!("fixture package name {name:?} must be valid: {error}"));
    }
}

#[test]
fn package_name_rule_rejects_hyphens_and_trailing_periods() {
    assert!(PackageName::new("rsolvefixture-core").is_err());
    assert!(PackageName::new("rsolvefixture.").is_err());
}

#[test]
fn catalog_rejects_malformed_dependency_entry_through_provider_parser() {
    let malformed = b"Package: rsolvefixture.invalid\nVersion: 1.0.0\nDepends: rsolvefixture.valid (>= 1.0) trailing\n";
    let catalog = CranCatalog::from_packages(malformed).expect("DCF syntax must parse");

    assert_eq!(catalog.diagnostics().len(), 1);
    assert_eq!(catalog.package_count(), 0);
    assert_eq!(catalog.candidate_count(), 0);
    assert!(catalog.diagnostics()[0].to_string().contains("Depends"));
}
