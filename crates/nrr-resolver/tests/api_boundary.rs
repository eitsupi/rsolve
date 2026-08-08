//! API-boundary property for composition types.
//!
//! Set property:
//! - Domain: every public item reachable from the `nrr_resolver` crate root,
//!   including fields, parameters, return types, re-exports, and trait bounds;
//! - predicate: an item is a violation if any of those exposed types is a
//!   manifest, feature, or environment type owned by `nrr`;
//! - comparison: the resolver API and composition-type set must be disjoint.
//!
//! The enforcement instrument is the crate graph, not a name-filtered list of
//! resolver functions.  `nrr` owns all three composition types and already
//! depends on `nrr-resolver`; allowing the reverse edge would be a cycle.  A
//! reference in any signature position therefore cannot compile.  This test
//! records the root-side half of that property.  `scripts/check-deps.sh`
//! checks the resolved graph (including transitive edges) for the same
//! boundary.

use std::fs;
use std::path::Path;

#[test]
fn resolver_manifest_feature_environment_surface_is_disjoint() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let cargo_toml = fs::read_to_string(manifest).expect("resolver manifest must be readable");

    // What actually enforces this is cargo: `nrr` already depends on
    // `nrr-resolver`, so the reverse edge is a cycle and no spelling of it can
    // be built.  Verified by adding the edge in both inline and table form --
    // cargo rejects each with "cyclic package dependency" before any test runs.
    //
    // This assertion is a faster, redundant signal that names the property, so
    // a reader meeting a cycle error knows why it exists.  It matches both
    // spellings so it does not quietly cover less than it appears to.
    assert!(
        !cargo_toml.lines().any(|line| {
            let line = line.trim();
            line.starts_with("nrr =")
                || line.starts_with("nrr=")
                || line == "[dependencies.nrr]"
                || line == "[dev-dependencies.nrr]"
                || line == "[build-dependencies.nrr]"
        }),
        "resolver must not depend on the composition crate"
    );
}
