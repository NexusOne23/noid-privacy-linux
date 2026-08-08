#!/usr/bin/env bash
#
# Bats 1.3 introduced BATS_TEST_TMPDIR. Ubuntu 22.04 ships Bats 1.2.1,
# which provides only a run-level temporary directory. Keep fixture tests
# isolated per test on both versions instead of accidentally resolving an
# unset BATS_TEST_TMPDIR to the filesystem root.

_noid_ensure_test_tmpdir() {
  [[ -n "${BATS_TEST_TMPDIR:-}" ]] && return 0

  local base="${BATS_RUN_TMPDIR:-${BATS_TMPDIR:-${TMPDIR:-/tmp}}}"
  BATS_TEST_TMPDIR="${base%/}/noid-test-${BATS_TEST_NUMBER:-$$}"
  mkdir -p -- "$BATS_TEST_TMPDIR"
}
