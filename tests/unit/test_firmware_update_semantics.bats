#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_fwupd_update_grade\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "available firmware update is adverse" {
  updates='{"Devices":[{"Name":"Example","Releases":[{"Version":"2"}]}]}'
  devices='{"Devices":[{"Name":"Example","Flags":["updatable"]}]}'
  [[ "$(_fwupd_update_grade "$updates" "$devices" 0 0)" == "updates_available" ]]
}

@test "empty update list passes only with update-capable hardware" {
  updates='{"Devices":[]}'
  devices='{"Devices":[{"Name":"Example","Flags":["internal","updatable"]}]}'
  [[ "$(_fwupd_update_grade "$updates" "$devices" 0 0)" == "up_to_date" ]]
}

@test "no update-capable hardware remains unassessed" {
  updates='{"Devices":[]}'
  devices='{"Devices":[{"Name":"Example","Flags":["internal"]}]}'
  [[ "$(_fwupd_update_grade "$updates" "$devices" 0 0)" == "no_updatable" ]]
}

@test "fwupdmgr return code two cannot create a pass" {
  [[ "$(_fwupd_update_grade 'No updatable devices' '' 2 0)" == "unassessed" ]]
}

@test "either timed out inventory makes the result incomplete" {
  [[ "$(_fwupd_update_grade '' '' 124 0)" == "timeout" ]]
  [[ "$(_fwupd_update_grade '' '' 0 124)" == "timeout" ]]
}
