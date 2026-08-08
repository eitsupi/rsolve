//! The provider fixtures must be convertible by the domain layer in later steps.
#[test]
fn synthetic_fixture_package_names_are_valid_r_names() {
    for n in [
        "nrrfixture.core",
        "nrrfixture.folded",
        "nrrfixture.rare",
        "nrrfixture.plain",
        "nrrfixture.description",
        "nrrfixture.suggest.00",
    ] {
        assert!(
            nrr_core::PackageName::new(n).is_ok(),
            "{n} must be a valid R package name so step4 can convert the fixture"
        );
    }
    assert!(
        nrr_core::PackageName::new("nrrfixture-core").is_err(),
        "hyphens are not valid in R package names"
    );
}
