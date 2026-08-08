#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
}

@test "namespace inventory wording is distribution neutral" {
  grep -q 'moderate per-user namespace ceiling' "$SCRIPT"
  grep -q 'large per-user namespace ceiling' "$SCRIPT"
  run grep -E 'Fedora/RHEL default range|typical for Ubuntu/container' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "RAM inventory labels the available column accurately" {
  # shellcheck disable=SC2016  # literal production-source output
  grep -Fq 'RAM: $MEM_USED used / $MEM_TOTAL total; $MEM_AVAIL available' "$SCRIPT"
  # shellcheck disable=SC2016  # literal obsolete wording
  run grep -F '$MEM_AVAIL free' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "utmp inventory does not claim complete current-login coverage" {
  grep -q 'Traditional utmp sessions:' "$SCRIPT"
  grep -q 'logind-only graphical sessions may be absent' "$SCRIPT"
  run grep -q 'Currently logged in:' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "unmuted microphone state is not called active recording" {
  grep -q 'Default microphone source unmuted' "$SCRIPT"
  grep -q 'does not prove recording' "$SCRIPT"
  run grep -q 'Microphone active for' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}
