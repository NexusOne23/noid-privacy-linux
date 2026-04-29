#!/usr/bin/env bats
#
# Test the v3.6 PASS-aggregation helpers (_emit_pass_agg_start/agg/agg_end).
# Verify:
#   - Aggregator correctly increments PASS counter per item
#   - --verbose mode emits one PASS per item
#   - Default mode emits ONE summary PASS for the whole loop
#   - JSON mode forces full detail (consumers need it)

setup() {
  # Inline minimal version of the aggregator helpers to test in isolation
  PASS=0; FAIL=0; WARN=0; INFO=0
  _AGG_LABEL=""
  declare -ga _AGG_ITEMS=()
  GRN=""; RST=""

  _emit_pass() { ((PASS++)); echo "PASS: $1"; }

  _emit_pass_agg_start() {
    _AGG_LABEL="$1"
    _AGG_ITEMS=()
  }
  _emit_pass_agg() {
    if $VERBOSE || $JSON_MODE; then
      _emit_pass "$_AGG_LABEL: $1"
    else
      # Avoid `((PASS++))` — returns 1 when PASS was 0 under set -e.
      PASS=$((PASS + 1))
      _AGG_ITEMS+=("$1")
    fi
  }
  _emit_pass_agg_end() {
    local _total="$1" _suffix="${2:-set}"
    if ! $VERBOSE && ! $JSON_MODE; then
      local _count="${#_AGG_ITEMS[@]}"
      if [[ "$_count" -gt 0 ]]; then
        printf "PASS: %s: %d/%d %s\n" \
          "$_AGG_LABEL" "$_count" "$_total" "$_suffix"
      fi
    fi
    _AGG_ITEMS=()
    _AGG_LABEL=""
  }
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
  # One PASS line in output, not two
  count=$(echo "$output" | grep -c "^PASS:")
  [[ "$count" -eq 1 ]]
  [[ "$output" == *"Test: 2/2 items"* ]]
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
  count=$(echo "$output" | grep -c "^PASS:")
  [[ "$count" -eq 2 ]]
}

@test "aggregator emits per-item PASSes in JSON mode (consumers need detail)" {
  VERBOSE=false; JSON_MODE=true
  PASS=0
  output=$(
    _emit_pass_agg_start "Test"
    _emit_pass_agg "item1"
    _emit_pass_agg "item2"
    _emit_pass_agg_end 2 "items"
  )
  count=$(echo "$output" | grep -c "^PASS:")
  [[ "$count" -eq 2 ]]
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
