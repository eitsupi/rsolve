use super::*;
pub(super) struct ParsedDependency {
    pub(super) name: PackageName,
    pub(super) constraint: VersionConstraint,
}

pub(super) fn parse_dependency_entry(
    input: &str,
) -> Result<ParsedDependency, DependencyParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(DependencyParseError::EmptyEntry);
    }

    let (name_text, constraint) = match input.find('(') {
        Some(open) => {
            if !input.ends_with(')') {
                return Err(DependencyParseError::InvalidConstraintSyntax);
            }
            let expression = &input[open + 1..input.len() - 1];
            if expression.contains('(') || expression.contains(')') {
                return Err(DependencyParseError::InvalidConstraintSyntax);
            }
            let name_text = input[..open].trim();
            let expression = expression.trim();
            (name_text, Some(parse_constraint(expression)?))
        }
        None => {
            if input.contains(')') {
                return Err(DependencyParseError::InvalidConstraintSyntax);
            }
            (input, None)
        }
    };

    let name = PackageName::new(name_text).map_err(DependencyParseError::InvalidPackageName)?;
    Ok(ParsedDependency {
        name,
        constraint: constraint.unwrap_or_else(VersionConstraint::unconstrained),
    })
}

fn parse_constraint(input: &str) -> Result<VersionConstraint, DependencyParseError> {
    let operators = [
        (">=", RelationOp::Ge),
        ("<=", RelationOp::Le),
        ("==", RelationOp::Eq),
        ("!=", RelationOp::Ne),
        (">", RelationOp::Gt),
        ("<", RelationOp::Lt),
    ];
    let (operator, op) = operators
        .iter()
        .find(|(operator, _)| input.starts_with(operator))
        .ok_or(DependencyParseError::InvalidConstraintSyntax)?;
    let version_text = input[operator.len()..].trim();
    if version_text.is_empty() {
        return Err(DependencyParseError::MissingConstraintVersion);
    }
    let version =
        RPackageVersion::parse(version_text).map_err(DependencyParseError::InvalidVersion)?;
    Ok(VersionConstraint::from_clause(*op, version))
}
