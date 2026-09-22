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
  # Exercise the actual emitter and section recorder, not a copied function.
  result=$(
    PASS=0
    # shellcheck disable=SC2034  # consumed by sourced production functions
    JSON_MODE=false GRN="" RST="" CURRENT_SECTION_ID=fixture
    # shellcheck disable=SC2034
    declare -A SECTION_WEIGHTS=([fixture]=1) SECTION_PASS_COUNTS=()
    # shellcheck disable=SC1090
    source <(awk '
      /^(_emit_pass|_score_record|_finding_safe)\(\) \{/ { in_function=1 }
      in_function { print }
      in_function && /^}/ { in_function=0 }
    ' "$SCRIPT")
    _emit_pass "test message"
    printf '%s %s\n' "$PASS" "${SECTION_PASS_COUNTS[fixture]}"
  )
  [[ "$result" == $'  ✅ PASS  test message\n1 1' ]]
}
