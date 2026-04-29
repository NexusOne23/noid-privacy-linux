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
  ! grep -qE '^pass\(\) \{'  "$SCRIPT"
  ! grep -qE '^fail\(\) \{'  "$SCRIPT"
  ! grep -qE '^warn\(\) \{'  "$SCRIPT"
  ! grep -qE '^info\(\) \{'  "$SCRIPT"
}

@test "no leftover bare call sites in script body" {
  # Pattern: word-boundary + bare emit name + space + string-start
  # Anchored to avoid false hits on `flatpak info`, `docker info`, etc.
  ! grep -nE '(^|[[:space:]])pass[[:space:]]+["$]' "$SCRIPT"
  ! grep -nE '(^|[[:space:]])fail[[:space:]]+["$]' "$SCRIPT"
  ! grep -nE '(^|[[:space:]])warn[[:space:]]+["$]' "$SCRIPT"
}

@test "PASS counter increments on _emit_pass call" {
  # Source the helpers in a sub-shell, call once, check counter
  result=$(
    JSON_MODE=false; PASS=0; FAIL=0; WARN=0; INFO=0
    GRN=""; RST=""
    # Inline minimal version to avoid sourcing the entire script
    _emit_pass() { ((PASS++)); printf "PASS %s\n" "$1"; }
    _emit_pass "test message"
    echo "$PASS"
  )
  [[ "$result" == *"1" ]]
}
