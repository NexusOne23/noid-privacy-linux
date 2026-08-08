#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  FIXTURE_DIR="${BATS_TEST_DIRNAME}/../fixtures"
  [[ -f "$SCRIPT" ]] || skip "main script missing"
  # shellcheck source=/dev/null
  source <(sed -n \
    '/^# BEGIN NOID FIREFOX PREF PARSER$/,/^# END NOID FIREFOX PREF PARSER$/p' \
    "$SCRIPT")
}

@test "user.js overrides prefs.js" {
  _FIREFOX_POLICY_DIRS=/nonexistent
  run _ff_pref "$FIXTURE_DIR/firefox-profile/prefs.js" toolkit.telemetry.enabled
  [[ "$status" -eq 0 ]]
  [[ "$output" == "false" ]]
}

@test "commented user.js example does not override numeric prefs.js state" {
  _FIREFOX_POLICY_DIRS=/nonexistent
  run _ff_pref "$FIXTURE_DIR/firefox-profile/prefs.js" network.trr.mode
  [[ "$status" -eq 0 ]]
  [[ "$output" == "2" ]]
}

@test "multiline enterprise DisableTelemetry policy overrides profile" {
  _FIREFOX_POLICY_DIRS="$FIXTURE_DIR/firefox-policy"
  run _ff_pref "$FIXTURE_DIR/firefox-profile/prefs.js" toolkit.telemetry.enabled
  [[ "$status" -eq 0 ]]
  [[ "$output" == "false" ]]
}

@test "missing preference is unassessed" {
  _FIREFOX_POLICY_DIRS=/nonexistent
  run _ff_pref "$FIXTURE_DIR/firefox-profile/prefs.js" missing.preference
  [[ "$status" -ne 0 ]]
  [[ -z "$output" ]]
}

@test "DoH results are informational because system or VPN DNS may be intentional" {
  grep -q 'Browser DNS: DoH-first' "$SCRIPT"
  grep -q 'Browser DNS: native system resolver (DoH explicitly off, mode 5' "$SCRIPT"
  grep -q 'Browser DNS: Firefox default/rollout mode (mode 0)' "$SCRIPT"
  grep -q 'Browser DNS mode not explicitly set; effective vendor/enterprise default was not inferred' "$SCRIPT"
  run grep -q '_emit_pass "DNS-over-HTTPS' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}
