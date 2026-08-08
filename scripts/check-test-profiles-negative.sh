#!/bin/sh
# Every checked-in case must be rejected by the profile evaluator.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$root/scripts/test-fixtures/profile-guard
evaluator=$root/scripts/check-test-profiles-evaluate.sh
metadata=$fixture_dir/metadata.json

for case in intended-missing intended-and-another same-name-other intended-listed-default; do
    case_dir=$fixture_dir/$case
    if [ "$case" = intended-listed-default ]; then
        default_list=$case_dir/default.json
        profile_list=$fixture_dir/valid/profile.json
    else
        default_list=$fixture_dir/valid/default.json
        profile_list=$case_dir/profile.json
    fi

    if sh "$evaluator" "$metadata" "$default_list" "$profile_list" nrr-provider r_interop >/dev/null 2>&1; then
        echo "profile guard negative control unexpectedly passed: $case" >&2
        exit 1
    fi
    echo "profile guard negative control rejected: $case"
done
