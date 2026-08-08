//! Independent acceptance checks written by the orchestrator, not by the
//! implementer. These assert the settled semantics through the public API only.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use nrr_core::*;

fn v(s: &str) -> RPackageVersion {
    RPackageVersion::parse(s).unwrap_or_else(|e| panic!("parse {s:?}: {e}"))
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

#[test]
fn trailing_components_are_zero_and_hash_identically() {
    assert_eq!(v("4.4"), v("4.4.0"), "4.4 == 4.4.0");
    assert_eq!(
        hash_of(&v("4.4")),
        hash_of(&v("4.4.0")),
        "equal versions must hash identically or HashMap keys break"
    );
    assert_eq!(v("1.0"), v("1.0.0.0.0"));
}

#[test]
fn separators_are_equivalent_and_leading_zeros_insignificant() {
    assert_eq!(v("1.7-0"), v("1.7.0"));
    assert_eq!(v("01.2"), v("1.2"));
    assert_eq!(v("1.0-0"), v("1.0.0"));
    assert_eq!(hash_of(&v("1.7-0")), hash_of(&v("1.7.0")));
}

#[test]
fn comparison_is_numeric_not_lexicographic() {
    assert!(v("1.10") > v("1.9"));
    assert!(v("1.6-5") < v("1.7-0"));
    assert!(v("2026.1.1") == v("2026.01.01"));
}

#[test]
fn compare_version_semantics_are_deliberately_not_used() {
    // R's compareVersion("4.4","4.4.0") is -1. nrr rejects that on purpose.
    assert!(
        !(v("4.4") < v("4.4.0")),
        "compareVersion semantics leaked into nrr"
    );
}

#[test]
fn nine_or_more_components_are_accepted_not_truncated() {
    let long = "1.2.3.4.5.6.7.8.9.10.11";
    let parsed = v(long);
    assert_eq!(parsed.canonical_component_count(), 11);
    assert!(v("1.2.3.4.5.6.7.8.9.10.11") > v("1.2.3.4.5.6.7.8.9.10.10"));
    assert_ne!(v(long), v("1.2.3.4.5.6.7.8"));
}

#[test]
fn largest_observed_cran_component_fits() {
    // Largest single component measured across current CRAN was 20260000.
    let parsed = v("20260000.1");
    assert!(parsed > v("20259999.1"));
}

#[test]
fn original_spelling_round_trips() {
    assert_eq!(v("1.6-5").as_str(), "1.6-5");
    assert_eq!(v("01.2").as_str(), "01.2");
    assert_eq!(v("1.6-5").to_string(), "1.6-5");
}

#[test]
fn parse_errors_do_not_panic() {
    for bad in ["", "1..2", ".1", "1.", "abc", "1.x", "-1", "4294967296"] {
        assert!(
            RPackageVersion::parse(bad).is_err(),
            "expected {bad:?} to be rejected"
        );
    }
}

#[test]
fn r_ge_4_4_is_satisfied_by_4_4_0() {
    let c = VersionConstraint::from_clause(RelationOp::Ge, v("4.4"));
    assert!(c.satisfies(&v("4.4.0")), "R (>= 4.4) must accept 4.4.0");
    assert!(c.satisfies(&v("4.5.1")));
    assert!(!c.satisfies(&v("4.3.3")));

    let c2 = VersionConstraint::from_clause(RelationOp::Ge, v("4.4.0"));
    assert!(c2.satisfies(&v("4.4")), "R (>= 4.4.0) must accept 4.4");
}

#[test]
fn matrix_boundary_constraints_behave_as_documented() {
    // Matrix 1.6-5: Depends R (>= 3.5.0); Matrix 1.7-0: Depends R (>= 4.4.0)
    let old = VersionConstraint::from_clause(RelationOp::Ge, v("3.5.0"));
    let new = VersionConstraint::from_clause(RelationOp::Ge, v("4.4.0"));

    let r43 = v("4.3.3");
    let r44 = v("4.4.0");

    assert!(old.satisfies(&r43));
    assert!(!new.satisfies(&r43), "R 4.3 must reject Matrix 1.7-0");
    assert!(old.satisfies(&r44));
    assert!(new.satisfies(&r44), "R 4.4 must accept Matrix 1.7-0");
}

#[test]
fn metadata_refuses_to_hold_dependency_fields() {
    for reserved in [
        "Depends",
        "Imports",
        "LinkingTo",
        "Suggests",
        "Enhances",
        "Package",
        "Version",
    ] {
        assert!(
            ReleaseMetadata::from_pairs([(reserved, "x")]).is_err(),
            "{reserved} must not be storable as generic metadata"
        );
    }
    assert!(ReleaseMetadata::from_pairs([("Title", "x")]).is_ok());
}

// --- aggregation invariants -------------------------------------------------

fn pkg(s: &str) -> PackageName {
    PackageName::new(s).unwrap()
}

fn git_identity(name: &str, commit: &str) -> ReleaseIdentity {
    ReleaseIdentity::new(
        pkg(name),
        Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.invalid/foo.git").unwrap(),
            commit: GitCommitId::new(commit).unwrap(),
            subdirectory: None,
        },
    )
}

fn registry_identity(name: &str, ns: &str, version: &str) -> ReleaseIdentity {
    ReleaseIdentity::new(
        pkg(name),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new(ns).unwrap(),
            version: v(version),
        },
    )
}

fn observation(identity: ReleaseIdentity, version: &str) -> ReleaseObservation {
    ReleaseObservation {
        observed_package: identity.name().clone(),
        observed_version: v(version),
        identity,
        metadata: ReleaseMetadata::default(),
        dependencies: Vec::new(),
        distributions: Vec::new(),
    }
}

#[test]
fn same_git_commit_with_two_versions_is_a_conflict_not_a_silent_dedup() {
    let id = git_identity("foo", "0123456789abcdef0123456789abcdef01234567");
    let mut agg = ReleaseAggregation::new();

    agg.observe(observation(id.clone(), "1.0.0")).unwrap();
    let second = agg.observe(observation(id.clone(), "2.0.0"));

    assert!(
        second.is_err(),
        "the second observation must conflict, not be dropped as a duplicate"
    );
    assert_eq!(agg.len(), 1);
    assert_eq!(agg.get(&id).unwrap().version(), &v("1.0.0"));
}

#[test]
fn same_name_and_version_in_two_namespaces_stay_separate_releases() {
    let cran = registry_identity("foo", "cran", "1.0.0");
    let internal = registry_identity("foo", "internal", "1.0.0");
    assert_ne!(cran, internal, "namespace must discriminate identity");

    let mut agg = ReleaseAggregation::new();
    agg.observe(observation(cran.clone(), "1.0.0")).unwrap();
    agg.observe(observation(internal.clone(), "1.0.0")).unwrap();

    assert_eq!(
        agg.len(),
        2,
        "name+version alone must never merge two registries' releases"
    );
    assert!(agg.get(&cran).is_some() && agg.get(&internal).is_some());
}

#[test]
fn observed_package_must_match_identity_name() {
    let id = registry_identity("foo", "cran", "1.0.0");
    let mut bad = observation(id, "1.0.0");
    bad.observed_package = pkg("bar");
    assert!(
        PackageRelease::try_from(bad).is_err(),
        "constructor must reject a package name that disagrees with identity"
    );
}

#[test]
fn observed_version_must_match_registry_provenance_coordinate() {
    let id = registry_identity("foo", "cran", "1.0.0");
    assert!(
        PackageRelease::try_from(observation(id, "9.9.9")).is_err(),
        "constructor must reject a version that disagrees with the provenance coordinate"
    );
}
