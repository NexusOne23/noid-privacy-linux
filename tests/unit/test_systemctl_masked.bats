#!/usr/bin/env bats
#
# Test the systemctl is-masked fix — `is-masked` is NOT a valid systemctl
# verb. The correct check uses `is-enabled` and parses for the literal
# string "masked".
#
# Bug class: API-versioning across distros (NoID Privacy Bug Pattern #4).

setup() {
  FIXTURE_DIR="${BATS_TEST_DIRNAME}/../fixtures"
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -d "$FIXTURE_DIR" && -f "$SCRIPT" ]] || skip "fixtures or main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_failed_systemd_unit_names\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_failed_noid_image_unit_names\(\) \{/,/^}/ {print}' "$SCRIPT")
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

@test "failed-unit parser returns names for plain and marker-prefixed rows" {
  rows=$'systemd-networkd-wait-online.service loaded failed failed description\n* ascii.service loaded failed failed description\n× unicode.service loaded failed failed description'
  run _failed_systemd_unit_names <<< "$rows"
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'systemd-networkd-wait-online.service\nascii.service\nunicode.service' ]]
  grep -q 'systemctl --failed --no-legend --plain' "$SCRIPT"
}

@test "NoID image-unit parser is exact and excludes unrelated failures" {
  rows=$'noid-mount-hardening.service loaded failed failed hardening\nNetworkManager-wait-online.service loaded failed failed network\nnotnoid-helper.service loaded failed failed unrelated'
  run _failed_noid_image_unit_names <<< "$rows"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "noid-mount-hardening.service" ]]
}

@test "failed NoID image units warn while unrelated failed units remain inventory" {
  block=$(sed -n '/# Failed Services/,/# Timer Units/p' "$SCRIPT")
  # Literal production-source patterns.
  # shellcheck disable=SC2016
  [[ "$block" == *'_emit_warn "$_FAILED_NOID_COUNT failed NoID image'* ]]
  # shellcheck disable=SC2016
  [[ "$block" == *'_emit_info "$_FAILED_OTHER_COUNT failed systemd'* ]]
}
