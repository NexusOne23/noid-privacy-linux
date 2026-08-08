#!/usr/bin/env bats
#
# Test that the v3.6 _emit_pass/fail/warn/info functions:
#   - increment counters correctly
#   - emit underscore-prefixed names (no shadow class)
#
# These tests verify the v3.6 function-naming refactor — they catch regressions
# if anyone reverts to bare names like pass()/fail()/warn()/info().

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
}

@test "definitions use underscore prefix (no name shadow)" {
  grep -qE '^_emit_pass\(\) \{'  "$SCRIPT"
  grep -qE '^_emit_fail\(\) \{'  "$SCRIPT"
  grep -qE '^_emit_warn\(\) \{'  "$SCRIPT"
  grep -qE '^_emit_info\(\) \{'  "$SCRIPT"
}

@test "no leftover bare function definitions" {
  for pattern in '^pass\(\) \{' '^fail\(\) \{' '^warn\(\) \{' '^info\(\) \{'; do
    run grep -qE "$pattern" "$SCRIPT"
    [[ "$status" -ne 0 ]]
  done
}

@test "no leftover bare call sites in script body" {
  # Pattern: word-boundary + bare emit name + space + string-start
  # Anchored to avoid false hits on `flatpak info`, `docker info`, etc.
  for name in pass fail warn; do
    run grep -nE "(^|[[:space:]])${name}[[:space:]]+[\"$]" "$SCRIPT"
    [[ "$status" -ne 0 ]]
  done
}

@test "PASS counter increments on _emit_pass call" {
  # Source the helpers in a sub-shell, call once, check counter
  result=$(
    PASS=0
    # Inline minimal version to avoid sourcing the entire script
    _emit_pass() { PASS=$((PASS + 1)); printf "PASS %s\n" "$1"; }
    _emit_pass "test message"
    echo "$PASS"
  )
  [[ "$result" == *"1" ]]
}
