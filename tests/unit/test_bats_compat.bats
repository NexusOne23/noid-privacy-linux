#!/usr/bin/env bats

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

@test "Bats before 1.3 receives an isolated per-test directory" {
  local run_root="${BATS_TEST_TMPDIR:-${BATS_RUN_TMPDIR:-${TMPDIR:-/tmp}}}"
  local test_number="${BATS_TEST_NUMBER:-$$}"
  unset BATS_TEST_TMPDIR
  BATS_RUN_TMPDIR="$run_root"

  _noid_ensure_test_tmpdir

  [[ "$BATS_TEST_TMPDIR" == "${run_root%/}/noid-test-${test_number}" ]]
  [[ -d "$BATS_TEST_TMPDIR" ]]
  [[ "$BATS_TEST_TMPDIR" != / ]]
}

@test "modern Bats native temporary directory remains unchanged" {
  BATS_TEST_TMPDIR=/synthetic/native-bats-test-directory
  _noid_ensure_test_tmpdir
  [[ "$BATS_TEST_TMPDIR" == /synthetic/native-bats-test-directory ]]
}
