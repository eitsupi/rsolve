#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

cargo fmt --all -- --check
cargo metadata --locked --offline
scripts/check-deps.sh
scripts/check-test-profiles.sh
sh scripts/check-test-profiles-negative.sh
Rscript --vanilla crates/nrr-provider/tests/fixtures/cran-2026-08-08/generate_packages_fixture.R --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --doc --workspace --locked --offline
cargo nextest run --workspace --all-targets --profile default --locked --offline --no-fail-fast --no-tests=pass
