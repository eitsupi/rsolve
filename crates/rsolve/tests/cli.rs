use std::process::Command;

use tempfile::tempdir;

#[test]
fn help_is_successful_and_rendered_without_stderr() {
    let output = Command::new(env!("CARGO_BIN_EXE_rsolve"))
        .arg("--help")
        .output()
        .expect("run rsolve help");
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Resolve explicit packages"));
    assert!(output.stderr.is_empty());

    let lock_help = Command::new(env!("CARGO_BIN_EXE_rsolve"))
        .args(["lock", "--help"])
        .output()
        .expect("run rsolve lock help");
    assert!(lock_help.status.success());
    assert!(String::from_utf8_lossy(&lock_help.stdout).contains("Repeat this flag"));
    assert!(lock_help.stderr.is_empty());
}

#[test]
fn invalid_usage_is_exit_two_and_rendered_on_stderr() {
    let output = Command::new(env!("CARGO_BIN_EXE_rsolve"))
        .args(["lock"])
        .output()
        .expect("run invalid rsolve command");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
}

#[test]
#[ignore = "requires explicit RSOLVE_TEST_MODE=cran-live and network access"]
fn opt_in_live_cran_lock_resolves_matrix() {
    assert_eq!(
        std::env::var("RSOLVE_TEST_MODE").as_deref(),
        Ok("cran-live"),
        "set RSOLVE_TEST_MODE=cran-live to authorize the live CRAN test"
    );
    let directory = tempdir().expect("create live test directory");
    let output_path = directory.path().join("rsolve.lock");
    let output = Command::new(env!("CARGO_BIN_EXE_rsolve"))
        .args([
            "lock",
            "--r-version",
            "4.4.0",
            "--package",
            "Matrix",
            "--output",
        ])
        .arg(&output_path)
        .output()
        .expect("run live CRAN lock command");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let text = std::fs::read_to_string(output_path).expect("read generated lock");
    let lock = rsolve::from_toml(&text).expect("decode generated lock");
    assert!(
        lock.resolutions[0]
            .packages
            .iter()
            .any(|package| package.identity.name().as_str() == "Matrix")
    );
}
