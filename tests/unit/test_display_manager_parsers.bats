#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  FIXTURE_DIR="${BATS_TEST_DIRNAME}/../fixtures"
  [[ -f "$SCRIPT" && -d "$FIXTURE_DIR" ]] || skip "test inputs missing"
  # shellcheck source=/dev/null
  source <(sed -n \
    '/^# BEGIN NOID DISPLAY MANAGER PARSER$/,/^# END NOID DISPLAY MANAGER PARSER$/p' \
    "$SCRIPT")
}

@test "SDDM local empty User clears vendor auto-login" {
  run _dm_section_last_value sddm User \
    "$FIXTURE_DIR/sddm-autologin-vendor.conf" \
    "$FIXTURE_DIR/sddm-autologin-disabled.conf"
  [[ "$status" -eq 0 ]]
  [[ -z "$output" ]]
}

@test "SDDM parser returns final enabled auto-login user" {
  run _dm_section_last_value sddm User \
    "$FIXTURE_DIR/sddm-autologin-vendor.conf" \
    "$FIXTURE_DIR/sddm-autologin-enabled.conf"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "alice" ]]
}

@test "LightDM local setting overrides vendor guest default" {
  run _dm_section_last_value lightdm allow-guest \
    "$FIXTURE_DIR/lightdm-seat-vendor.conf" \
    "$FIXTURE_DIR/lightdm-seat-local.conf"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "false" ]]
}

@test "LightDM main file has highest precedence" {
  run _dm_section_last_value lightdm autologin-user \
    "$FIXTURE_DIR/lightdm-seat-vendor.conf" \
    "$FIXTURE_DIR/lightdm-seat-local.conf" \
    "$FIXTURE_DIR/lightdm-seat-main.conf"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "bob" ]]
}

@test "greetd parser ignores the authenticated greeter account" {
  run _dm_section_last_value greetd user "$FIXTURE_DIR/greetd-no-autologin.toml"
  [[ "$status" -eq 0 ]]
  [[ -z "$output" ]]
}

@test "greetd parser finds initial-session auto-login" {
  run _dm_section_last_value greetd user "$FIXTURE_DIR/greetd-with-autologin.toml"
  [[ "$status" -eq 0 ]]
  [[ "$output" == "alice" ]]
}

@test "display-manager block covers GDM, SDDM, LightDM, and greetd" {
  grep -q 'AutomaticLoginEnable' "$SCRIPT"
  grep -q '_dm_section_last_value sddm User' "$SCRIPT"
  grep -q '_dm_section_last_value lightdm autologin-user' "$SCRIPT"
  grep -q '_dm_section_last_value greetd user' "$SCRIPT"
}
