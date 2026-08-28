// This is a fingerprint of validated logical/solver metadata, not an
// arbitrary DESCRIPTION passthrough, repository observation, or distribution
// and artifact bytes.
const METADATA_DIGEST_DOMAIN: &[u8] = b"rsolve.logical-release-metadata\0v1";

use sha2::{Digest, Sha256};

use crate::constraints::{
    DeclaredDependency, DependencyKind, DependencySourceConstraint, RelationOp,
};
use crate::identity::{Provenance, ReleaseIdentity};
use crate::names::Sha256Digest;
use crate::r_versions::RPackageVersion;

pub(super) fn canonical_metadata_digest(
    identity: &ReleaseIdentity,
    observed_version: &RPackageVersion,
    dependencies: &[DeclaredDependency],
) -> Sha256Digest {
    let mut encoded = Vec::new();
    append_bytes(&mut encoded, METADATA_DIGEST_DOMAIN);
    append_identity(&mut encoded, identity);
    append_version(&mut encoded, observed_version);

    let mut dependency_records = dependencies
        .iter()
        .map(encode_dependency)
        .collect::<Vec<_>>();
    dependency_records.sort();
    dependency_records.dedup();
    append_u64(&mut encoded, dependency_records.len() as u64);
    for dependency in dependency_records {
        append_bytes(&mut encoded, &dependency);
    }

    let digest = Sha256::digest(encoded);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    Sha256Digest::new(hex).expect("SHA-256 output is always a valid digest")
}

fn encode_dependency(dependency: &DeclaredDependency) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(match dependency.kind {
        DependencyKind::Depends => 0,
        DependencyKind::Imports => 1,
        DependencyKind::LinkingTo => 2,
        DependencyKind::Suggests => 3,
        DependencyKind::Enhances => 4,
    });
    append_string(&mut encoded, dependency.package.name().as_str());
    append_source_constraint(&mut encoded, dependency.package.source());
    let mut clauses = dependency
        .package
        .constraint()
        .clauses
        .iter()
        .map(|clause| {
            let mut encoded = Vec::new();
            encoded.push(match clause.op {
                RelationOp::Lt => 0,
                RelationOp::Le => 1,
                RelationOp::Eq => 2,
                RelationOp::Ne => 3,
                RelationOp::Ge => 4,
                RelationOp::Gt => 5,
            });
            append_version(&mut encoded, &clause.version);
            encoded
        })
        .collect::<Vec<_>>();
    clauses.sort();
    clauses.dedup();
    append_u64(&mut encoded, clauses.len() as u64);
    for clause in clauses {
        append_bytes(&mut encoded, &clause);
    }
    encoded
}

fn append_source_constraint(encoded: &mut Vec<u8>, source: &DependencySourceConstraint) {
    match source {
        DependencySourceConstraint::Any => encoded.push(0),
        DependencySourceConstraint::Registry { namespace } => {
            encoded.push(1);
            append_string(encoded, namespace.as_str());
        }
        DependencySourceConstraint::Repository { repository } => {
            encoded.push(5);
            append_string(encoded, repository.as_str());
        }
        DependencySourceConstraint::Bioconductor { namespace, release } => {
            encoded.push(2);
            append_string(encoded, namespace.as_str());
            append_string(encoded, release.as_str());
        }
        DependencySourceConstraint::Git { repository } => {
            encoded.push(3);
            append_string(encoded, repository.as_str());
        }
        DependencySourceConstraint::Exact(identity) => {
            encoded.push(4);
            append_identity(encoded, identity);
        }
    }
}

fn append_identity(encoded: &mut Vec<u8>, identity: &ReleaseIdentity) {
    append_string(encoded, identity.name().as_str());
    match identity.provenance() {
        Provenance::RBasePackage { r_version } => {
            encoded.push(0);
            append_version(encoded, r_version);
        }
        Provenance::RegistryRelease { namespace, version } => {
            encoded.push(1);
            append_string(encoded, namespace.as_str());
            append_version(encoded, version);
        }
        Provenance::GitCommit {
            repository,
            commit,
            subdirectory,
        } => {
            encoded.push(2);
            append_string(encoded, repository.as_str());
            append_string(encoded, commit.as_str());
            append_optional_string(encoded, subdirectory.as_ref().map(|value| value.as_str()));
        }
        Provenance::BioconductorRelease {
            namespace,
            release,
            version,
        } => {
            encoded.push(3);
            append_string(encoded, namespace.as_str());
            append_string(encoded, release.as_str());
            append_version(encoded, version);
        }
        Provenance::ImmutableSource { scheme, digest } => {
            encoded.push(4);
            append_string(encoded, scheme.as_str());
            append_string(encoded, digest.as_str());
        }
    }
}

fn append_optional_string(encoded: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            encoded.push(1);
            append_string(encoded, value);
        }
        None => encoded.push(0),
    }
}

fn append_string(encoded: &mut Vec<u8>, value: &str) {
    append_bytes(encoded, value.as_bytes());
}

/// Encode R versions by their semantic numeric components, never by their
/// retained display spelling.  This keeps equivalent separators, leading
/// zeroes, and trailing zero components at the same digest coordinate.
fn append_version(encoded: &mut Vec<u8>, value: &RPackageVersion) {
    let component_count = value.canonical_component_count();
    append_u64(encoded, component_count as u64);
    for component in value.components().take(component_count) {
        append_u64(encoded, u64::from(component));
    }
}

fn append_bytes(encoded: &mut Vec<u8>, value: &[u8]) {
    append_u64(encoded, value.len() as u64);
    encoded.extend_from_slice(value);
}

fn append_u64(encoded: &mut Vec<u8>, value: u64) {
    encoded.extend_from_slice(&value.to_le_bytes());
}
