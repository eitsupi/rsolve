//! Validate the names present in the provider fixtures, rather than a copied
//! list that could drift away from the fixture contents.

const PACKAGES: &[u8] =
    include_bytes!("../../nrr-provider/tests/fixtures/cran-2026-08-08/synthetic-PACKAGES");
const DESCRIPTION: &[u8] =
    include_bytes!("../../nrr-provider/tests/fixtures/cran-2026-08-08/synthetic-DESCRIPTION");

fn fields(input: &[u8]) -> Vec<(String, String)> {
    let text = std::str::from_utf8(input).expect("fixture must be UTF-8");
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            let (_, value) = fields.last_mut().expect("continuation must follow a field");
            value.push('\n');
            value.push_str(line.trim_start());
        } else {
            let (name, value) = line
                .split_once(':')
                .expect("fixture field must contain a colon");
            fields.push((
                name.to_owned(),
                value.trim_start_matches([' ', '\t']).to_owned(),
            ));
        }
    }
    fields
}

#[test]
fn every_fixture_package_and_dependency_name_is_a_valid_r_name() {
    let mut package_count = 0;
    let mut dependency_count = 0;
    for fixture in [PACKAGES, DESCRIPTION] {
        for (field, value) in fields(fixture) {
            if field.eq_ignore_ascii_case("Package") {
                package_count += 1;
                assert!(
                    nrr_core::PackageName::new(value.trim()).is_ok(),
                    "fixture package {value:?} must be a valid R package name"
                );
            } else if matches!(
                field.to_ascii_lowercase().as_str(),
                "depends" | "imports" | "linkingto" | "suggests" | "enhances"
            ) {
                for dependency in value.split(',') {
                    let name = dependency
                        .split_whitespace()
                        .next()
                        .expect("fixture dependency entry must have a name");
                    dependency_count += 1;
                    assert!(
                        nrr_core::PackageName::new(name).is_ok(),
                        "fixture dependency {name:?} must be a valid R package name"
                    );
                }
            }
        }
    }
    assert_eq!(package_count, 5);
    assert!(dependency_count > 0);
}

#[test]
fn package_name_rule_rejects_hyphens_and_trailing_periods() {
    assert!(nrr_core::PackageName::new("nrrfixture-core").is_err());
    assert!(nrr_core::PackageName::new("nrrfixture.").is_err());
}
