#[path = "pak_portable.rs"]
mod pak_harness;

#[test]
fn portable_pak_contract_uses_single_call_and_dependency_aware_success() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rsolve-repository/tests/fixtures/closure");
    pak_harness::run_contract("pak-portable", &fixture);
}
