#[path = "pak_portable.rs"]
mod pak_harness;

#[test]
fn portable_pak_contract_uses_single_call_and_dependency_aware_success() {
    pak_harness::run_contract("pak-portable");
}
