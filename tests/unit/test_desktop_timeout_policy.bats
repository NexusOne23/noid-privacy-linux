#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_desktop_idle_grade\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_desktop_lock_delay_grade\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_milliseconds_to_seconds_ceil\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_desktop_setting_unavailable_text\(\) \{/,/^}/ {print}' "$SCRIPT")
}

@test "COSMIC millisecond values cannot collapse a positive timeout to disabled" {
  [[ "$(_milliseconds_to_seconds_ceil 0)" == "0" ]]
  [[ "$(_milliseconds_to_seconds_ceil 1)" == "1" ]]
  [[ "$(_milliseconds_to_seconds_ceil 999)" == "1" ]]
  [[ "$(_milliseconds_to_seconds_ceil 1000)" == "1" ]]
  [[ "$(_milliseconds_to_seconds_ceil 1001)" == "2" ]]
  run _milliseconds_to_seconds_ceil invalid
  [[ "$status" -ne 0 ]]
}

@test "idle timeout grades the five and fifteen minute boundaries" {
  [[ "$(_desktop_idle_grade 0)" == "fail" ]]
  [[ "$(_desktop_idle_grade 300)" == "pass" ]]
  [[ "$(_desktop_idle_grade 301)" == "warn" ]]
  [[ "$(_desktop_idle_grade 900)" == "warn" ]]
  [[ "$(_desktop_idle_grade 901)" == "fail" ]]
  [[ "$(_desktop_idle_grade invalid)" == "unassessed" ]]
}

@test "lock activation delay grades immediate one-minute and longer states" {
  [[ "$(_desktop_lock_delay_grade 0)" == "pass" ]]
  [[ "$(_desktop_lock_delay_grade 1)" == "warn" ]]
  [[ "$(_desktop_lock_delay_grade 60)" == "warn" ]]
  [[ "$(_desktop_lock_delay_grade 61)" == "fail" ]]
  [[ "$(_desktop_lock_delay_grade invalid)" == "unassessed" ]]
}

@test "missing desktop settings are distinct from missing active sessions" {
  [[ "$(_desktop_setting_unavailable_text "Idle-delay" kde 1)" == \
    "Idle-delay setting not explicit/readable for 1 active kde user profile" ]]
  [[ "$(_desktop_setting_unavailable_text "Idle-delay" kde 2)" == \
    "Idle-delay setting not explicit/readable for 2 active kde user profiles" ]]
  [[ "$(_desktop_setting_unavailable_text "Idle-delay" kde 0)" == \
    "No active kde sessions found for idle-delay check" ]]
}

@test "Section 26 cannot duplicate screen-lock severity from Section 39" {
  overview=$(sed -n '/^check_desktop() {/,/^check_ntp() {/p' "$SCRIPT")
  run grep -E '_emit_(pass|warn|fail) "Screen lock' <<< "$overview"
  [[ "$status" -ne 0 ]]
  [[ "$overview" == *'graded in Section 39'* ]]
  # Literal production-source variable.
  # shellcheck disable=SC2016
  [[ "$overview" != *'Screen lock: no active $_DE_FAMILY session found'* ]]
  [[ "$overview" == *'_desktop_setting_unavailable_text'* ]]
}
