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

@test "saved profile value remains available with enterprise policy present" {
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


@test "block comments and quoted comment delimiters preserve preference data" {
  printf '%s\n' '/* user_pref("target", true); */' 'user_pref("unrelated", "https://example.invalid/*literal*/");' 'user_pref("target", false);' > "$BATS_TEST_TMPDIR/prefs.js"
  run _ff_pref "$BATS_TEST_TMPDIR/prefs.js" target
  [[ "$status" -eq 0 && "$output" == false ]]
}

@test "conditional or malformed user JavaScript cannot masquerade as applied preference" {
  printf '%s\n' 'user_pref("target", true);' > "$BATS_TEST_TMPDIR/prefs.js"
  printf '%s\n' 'if (false) {' 'user_pref("target", false);' '}' > "$BATS_TEST_TMPDIR/user.js"
  run _ff_pref "$BATS_TEST_TMPDIR/prefs.js" target
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "policy files are not assumed applied to every Firefox-family profile" {
  _FIREFOX_POLICY_DIRS="$FIXTURE_DIR/firefox-policy"
  printf '%s\n' 'user_pref("toolkit.telemetry.enabled", true);' > "$BATS_TEST_TMPDIR/prefs.js"
  run _ff_pref "$BATS_TEST_TMPDIR/prefs.js" toolkit.telemetry.enabled
  [[ "$status" -eq 0 && "$output" == true ]]
}

@test "profile statements are parsed as data and never evaluated" {
  printf '%s\n' 'user_pref("target", false); invalid syntax' > "$BATS_TEST_TMPDIR/prefs.js"
  run _ff_pref "$BATS_TEST_TMPDIR/prefs.js" target
  [[ "$status" -ne 0 && -z "$output" ]]
}
