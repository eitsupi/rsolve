//! Deterministic plain DCF PACKAGES generation.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use nrr_core::{DependencyKind, DependencyRequirement, DependencySourceConstraint, RelationOp};
use thiserror::Error;

use crate::MaterializationArtifact;

const DEPENDENCY_FIELDS: [(DependencyKind, &str); 5] = [
    (DependencyKind::Depends, "Depends"),
    (DependencyKind::Imports, "Imports"),
    (DependencyKind::LinkingTo, "LinkingTo"),
    (DependencyKind::Suggests, "Suggests"),
    (DependencyKind::Enhances, "Enhances"),
];

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum PackagesError {
    #[error("invalid DCF field name: {field}")]
    InvalidFieldName { field: String },
    #[error("reserved or duplicate DCF field: {field}")]
    DuplicateField { field: String },
    #[error("invalid DCF value for {field}: {reason}")]
    InvalidFieldValue { field: String, reason: String },
    #[error("duplicate dependency {name} in {field}")]
    DuplicateDependency { field: String, name: String },
    #[error("dependency field {field} contains an unsupported constraint")]
    UnsupportedConstraint { field: String },
}

pub(crate) fn write_packages(
    artifacts: &[MaterializationArtifact],
) -> Result<Vec<u8>, PackagesError> {
    let mut rows = artifacts.to_vec();
    rows.sort_by(|left, right| {
        left.package()
            .as_str()
            .cmp(right.package().as_str())
            .then_with(|| left.version.cmp(&right.version))
    });
    let mut paragraphs = Vec::with_capacity(rows.len());
    for artifact in rows {
        paragraphs.push(write_record(&artifact)?);
    }
    let mut output = paragraphs.join("\n\n");
    output.push('\n');
    Ok(output.into_bytes())
}

fn write_record(artifact: &MaterializationArtifact) -> Result<String, PackagesError> {
    let mut fields = vec![
        ("Package".to_owned(), artifact.package().to_string()),
        ("Version".to_owned(), artifact.version.to_string()),
    ];
    let mut grouped: BTreeMap<DependencyKind, Vec<&DependencyRequirement>> = BTreeMap::new();
    for dependency in &artifact.dependencies {
        grouped.entry(dependency.kind).or_default().push(dependency);
    }
    for (kind, field) in DEPENDENCY_FIELDS {
        let Some(dependencies) = grouped.get(&kind) else {
            continue;
        };
        let mut seen = HashSet::new();
        let mut rendered = Vec::new();
        for dependency in dependencies {
            if !seen.insert(dependency.name.as_str().to_owned()) {
                return Err(PackagesError::DuplicateDependency {
                    field: field.to_owned(),
                    name: dependency.name.to_string(),
                });
            }
            rendered.push(render_dependency(dependency, field)?);
        }
        rendered.sort();
        fields.push((field.to_owned(), rendered.join(", ")));
    }
    let mut reserved: HashSet<String> = fields
        .iter()
        .map(|(name, _)| canonical_field_name(name).to_ascii_lowercase())
        .collect();
    for (name, value) in artifact.metadata.fields() {
        validate_field_name(name)?;
        let canonical = canonical_field_name(name);
        if !reserved.insert(canonical.to_ascii_lowercase()) {
            return Err(PackagesError::DuplicateField {
                field: name.to_owned(),
            });
        }
        fields.push((canonical, value.to_owned()));
    }
    fields.sort_by(|left, right| {
        field_rank(&left.0)
            .cmp(&field_rank(&right.0))
            .then_with(|| left.0.cmp(&right.0))
    });
    let mut output = String::new();
    for (name, value) in fields {
        validate_value(&name, &value)?;
        let mut lines = value.split('\n');
        write!(&mut output, "{name}: {}", lines.next().unwrap_or_default()).unwrap();
        for line in lines {
            write!(&mut output, "\n {line}").unwrap();
        }
        output.push('\n');
    }
    output.pop();
    Ok(output)
}

fn render_dependency(
    dependency: &DependencyRequirement,
    field: &str,
) -> Result<String, PackagesError> {
    if !matches!(dependency.source, DependencySourceConstraint::Any) {
        return Err(PackagesError::UnsupportedConstraint {
            field: field.to_owned(),
        });
    }
    let mut rendered = dependency.name.to_string();
    if !dependency.constraint.clauses.is_empty() {
        rendered.push_str(" (");
        for (index, clause) in dependency.constraint.clauses.iter().enumerate() {
            if index > 0 {
                rendered.push_str(", ");
            }
            rendered.push_str(match clause.op {
                RelationOp::Lt => "<",
                RelationOp::Le => "<=",
                RelationOp::Eq => "==",
                RelationOp::Ne => "!=",
                RelationOp::Ge => ">=",
                RelationOp::Gt => ">",
            });
            rendered.push(' ');
            rendered.push_str(clause.version.as_str());
        }
        rendered.push(')');
    }
    Ok(rendered)
}

fn field_rank(name: &str) -> usize {
    match name.to_ascii_lowercase().as_str() {
        "package" => 0,
        "version" => 1,
        "priority" => 2,
        "depends" => 3,
        "imports" => 4,
        "linkingto" => 5,
        "suggests" => 6,
        "enhances" => 7,
        "license" => 8,
        "license_is_foss" => 9,
        "license_restricts_use" => 10,
        "os_type" => 11,
        "archs" => 12,
        "md5sum" => 13,
        "sha256" | "sha256sum" => 14,
        "needscompilation" => 15,
        "built" => 16,
        "path" => 17,
        "file" => 18,
        "published" => 19,
        _ => 20,
    }
}

fn canonical_field_name(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "package" => "Package",
        "version" => "Version",
        "priority" => "Priority",
        "depends" => "Depends",
        "imports" => "Imports",
        "linkingto" => "LinkingTo",
        "suggests" => "Suggests",
        "enhances" => "Enhances",
        "license" => "License",
        "license_is_foss" => "License_is_FOSS",
        "license_restricts_use" => "License_restricts_use",
        "os_type" => "OS_type",
        "archs" => "Archs",
        "md5sum" => "MD5sum",
        "sha256" | "sha256sum" => "SHA256",
        "needscompilation" => "NeedsCompilation",
        "built" => "Built",
        "path" => "Path",
        "file" => "File",
        "published" => "Published",
        _ => name,
    }
    .to_owned()
}

fn validate_field_name(name: &str) -> Result<(), PackagesError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        || !name.as_bytes()[0].is_ascii_alphabetic()
    {
        return Err(PackagesError::InvalidFieldName {
            field: name.to_owned(),
        });
    }
    Ok(())
}

fn validate_value(field: &str, value: &str) -> Result<(), PackagesError> {
    if value.contains('\r') {
        return Err(PackagesError::InvalidFieldValue {
            field: field.to_owned(),
            reason: "carriage return is not allowed".to_owned(),
        });
    }
    if value
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(PackagesError::InvalidFieldValue {
            field: field.to_owned(),
            reason: "control character is not allowed".to_owned(),
        });
    }
    Ok(())
}
