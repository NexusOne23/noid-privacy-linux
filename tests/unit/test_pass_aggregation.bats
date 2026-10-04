#!/usr/bin/env bats
#
# Test the v3.6 PASS-aggregation helpers (_emit_pass_agg_start/agg/agg_end).
# Verify:
#   - Aggregator correctly increments PASS counter per item
#   - --verbose mode emits one PASS per item
#   - Default mode emits ONE summary PASS for the whole loop
#   - JSON mode forces full detail (consumers need it)

# State below is consumed by the extracted production functions.
# shellcheck disable=SC2034

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # Load the real aggregator, emitter, scoring recorder and escaping helpers
  # without executing the host audit or replacing their implementations.
  # shellcheck disable=SC1090
  source <(awk '
    /^(_emit_pass_agg_start|_emit_pass_agg|_emit_pass_agg_end|_emit_pass|_score_record|_finding_safe|_json_escape)\(\) \{/ { in_function=1 }
    in_function { print }
    in_function && /^}/ { in_function=0 }
  ' "$SCRIPT")
  PASS=0
  GRN=""; RST=""
  CURRENT_SECTION="Fixture"
  CURRENT_SECTION_ID=fixture
  declare -gA SECTION_WEIGHTS=([fixture]=1)
  declare -gA SECTION_PASS_COUNTS=()
  declare -ga JSON_FINDINGS=()
  _AGG_LABEL=""
  declare -ga _AGG_ITEMS=()
}

@test "aggregator increments PASS counter per item (default mode)" {
  VERBOSE=false; JSON_MODE=false
  PASS=0
  _emit_pass_agg_start "Test"
  _emit_pass_agg "item1"
  _emit_pass_agg "item2"
  _emit_pass_agg "item3"
  _emit_pass_agg_end 3 "items"
  [[ "$PASS" -eq 3 ]]
  [[ "${SECTION_PASS_COUNTS[fixture]}" -eq 3 ]]
  [[ "${#_AGG_ITEMS[@]}" -eq 0 && -z "$_AGG_LABEL" ]]
}

@test "aggregator emits single summary in default mode" {
  VERBOSE=false; JSON_MODE=false
  PASS=0
  output=$(
    _emit_pass_agg_start "Test"
    _emit_pass_agg "item1"
    _emit_pass_agg "item2"
    _emit_pass_agg_end 2 "items"
  )
  [[ "$output" == '  ✅ PASS  Test: 2/2 items' ]]
}

@test "aggregator emits per-item PASSes in verbose mode" {
  VERBOSE=true; JSON_MODE=false
  PASS=0
  output=$(
    _emit_pass_agg_start "Test"
    _emit_pass_agg "item1"
    _emit_pass_agg "item2"
    _emit_pass_agg_end 2 "items"
  )
  [[ "$output" == $'  ✅ PASS  Test: item1\n  ✅ PASS  Test: item2' ]]
}

@test "aggregator emits per-item PASSes in JSON mode (consumers need detail)" {
  VERBOSE=false; JSON_MODE=true
  PASS=0
  _emit_pass_agg_start "Test"
  _emit_pass_agg "item1"
  _emit_pass_agg "item2"
  _emit_pass_agg_end 2 "items"
  [[ "$PASS" -eq 2 && "${SECTION_PASS_COUNTS[fixture]}" -eq 2 ]]
  [[ "${#JSON_FINDINGS[@]}" -eq 2 ]]
  [[ "${JSON_FINDINGS[0]}" == '{"severity":"PASS","section":"Fixture","section_id":"fixture","message":"Test: item1"}' ]]
  [[ "${JSON_FINDINGS[1]}" == '{"severity":"PASS","section":"Fixture","section_id":"fixture","message":"Test: item2"}' ]]
}

@test "aggregator with zero items emits no summary" {
  VERBOSE=false; JSON_MODE=false
  PASS=0
  output=$(
    _emit_pass_agg_start "Test"
    _emit_pass_agg_end 5 "items"
  )
  [[ -z "$output" ]]
  [[ "$PASS" -eq 0 ]]
}
