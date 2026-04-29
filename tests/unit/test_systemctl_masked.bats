#!/usr/bin/env bats
#
# Test the systemctl is-masked fix — `is-masked` is NOT a valid systemctl
# verb. The correct check uses `is-enabled` and parses for the literal
# string "masked".
#
# Bug class: API-versioning across distros (NoID Bug Pattern #4).

setup() {
  FIXTURE_DIR="${BATS_TEST_DIRNAME}/../fixtures"
  [[ -d "$FIXTURE_DIR" ]] || skip "fixtures directory not found"
}

@test "systemctl is-masked verb does not exist" {
  # Sanity: this test documents the bug — systemctl never had this verb.
  # `is-masked` always errors with "Unknown command".
  if command -v systemctl &>/dev/null; then
    run systemctl is-masked dummy.service 2>&1
    # Any output mentioning "Unknown" or non-zero exit confirms the bug exists
    [[ "$status" -ne 0 ]] || [[ "$output" == *"Unknown"* ]] || [[ "$output" == *"unknown"* ]]
  else
    skip "systemctl not available in test environment"
  fi
}

@test "is-enabled output 'masked' indicates masked service" {
  result=$(< "$FIXTURE_DIR/systemctl-is-enabled-masked.txt")
  [[ "$result" == "masked" ]]
}

@test "is-enabled output 'disabled' is NOT masked" {
  result=$(< "$FIXTURE_DIR/systemctl-is-enabled-disabled.txt")
  [[ "$result" != "masked" ]]
}
