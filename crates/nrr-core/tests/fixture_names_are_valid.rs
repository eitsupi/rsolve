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

fn validate_dependency_entry(entry: &str) -> Result<(), String> {
    let entry = entry.trim();
    let (name, constraint) = match entry.split_once('(') {
        Some((name, constraint)) => {
            let constraint = constraint
                .strip_suffix(')')
                .ok_or_else(|| "version constraint must end with ')'".to_owned())?;
            if constraint.contains(['(', ')']) {
                return Err("version constraint contains an unexpected parenthesis".to_owned());
            }
            (name.trim(), Some(constraint))
        }
        None => (entry, None),
    };

    nrr_core::PackageName::new(name)
        .map_err(|error| format!("invalid package name {name:?}: {error}"))?;

    let Some(constraint) = constraint else {
        return Ok(());
    };

    let mut parts = constraint.split_whitespace();
    let operator = parts
        .next()
        .ok_or_else(|| "version constraint is missing an operator".to_owned())?;
    let version = parts
        .next()
        .ok_or_else(|| "version constraint is missing a version".to_owned())?;
    if parts.next().is_some() {
        return Err("version constraint has unexpected trailing tokens".to_owned());
    }
    if !matches!(operator, "<" | "<=" | "=" | "==" | "!=" | ">=" | ">") {
        return Err(format!("invalid version constraint operator {operator:?}"));
    }
    nrr_core::RPackageVersion::parse(version)
        .map_err(|error| format!("invalid version {version:?}: {error}"))?;
    Ok(())
}

fn validate_dependency_field(value: &str) -> Result<usize, String> {
    value
        .split(',')
        .enumerate()
        .map(|(index, entry)| {
            validate_dependency_entry(entry)
                .map_err(|error| format!("dependency entry {index}: {error}"))
                .map(|()| 1)
        })
        .sum()
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
                dependency_count += validate_dependency_field(&value).unwrap_or_else(|error| {
                    panic!("fixture dependency field {field:?} is malformed: {error}")
                });
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

#[test]
fn dependency_validation_rejects_trailing_tokens_in_any_entry() {
    assert!(validate_dependency_field("nrrfixture.import, nrrfixture.helper (>= 1.0)").is_ok());
    for malformed in [
        "nrrfixture.import, nrrfixture.helper unexpected",
        "nrrfixture.import (>= 1.0) trailing",
        "nrrfixture.import (>= 1.0 extra)",
    ] {
        assert!(
            validate_dependency_field(malformed).is_err(),
            "accepted malformed dependency field {malformed:?}"
        );
    }
}
