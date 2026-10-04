#!/usr/bin/env bats

# Exercise native-response consumers, including precedence and producer errors.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _nm_connectivity_state _nm_connectivity_audit _dnf5_countme_rows _dnf_countme_rows _dnf_countme_audit; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  NATIVE_RC=0 NATIVE_ERR=''
  NATIVE_OUT=$'======== "fixture" repository configuration: ========\nenabled = 1\ncountme = 0\nmetalink = https://example.invalid/metalink\nmirrorlist'
  CALLS="$BATS_TEST_TMPDIR/query-calls"
}

command() {
  [[ "$1" == -v && "$2" == dnf5 ]] && return 0
  builtin command "$@"
}
timeout() {
  printf '%s\n' "$*" >> "$CALLS"
  printf '%s\n' "$NATIVE_OUT"
  printf '%s' "$NATIVE_ERR" >&2
  return "$NATIVE_RC"
}
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }

@test "native repository-level countme false retains a bounded PASS" {
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *'PASS:DNF countme disabled for all 1 enabled repositories'* ]]
  [[ "$output" != *'example.invalid'* && "$output" != *INCOMPLETE* ]]
}

@test "repository countme true with mirror discovery warns" {
  NATIVE_OUT=${NATIVE_OUT/countme = 0/countme = 1}
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *'WARN:DNF countme enabled for 1 enabled repositories'* && "$output" != *PASS:* ]]
}

@test "a disabled repository does not imply active countme traffic" {
  NATIVE_OUT=${NATIVE_OUT/enabled = 1/enabled = 0}
  NATIVE_OUT=${NATIVE_OUT/countme = 0/countme = 1}
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *'no enabled repositories'* && "$output" != *WARN:* && "$output" != *PASS:* ]]
}

@test "enabled countme without HTTP discovery remains context" {
  NATIVE_OUT=$'======== "fixture" repository configuration: ========\nenabled = 1\ncountme = 1\nbaseurl = https://example.invalid/packages\nmetalink\nmirrorlist'
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *'without HTTP(S) mirror discovery'* && "$output" != *WARN:* && "$output" != *PASS:* ]]
}

@test "mirrorlist and case-insensitive HTTP schemes are eligible" {
  NATIVE_OUT=$'======== "fixture" repository configuration: ========\nenabled = 1\ncountme = 1\nmirrorlist = HTTPS://example.invalid/list'
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *WARN:* ]]
}

@test "each repository requires its own booleans" {
  NATIVE_OUT+=$'\n======== "second" repository configuration: ========\nenabled = 1\ncountme = 1\nmetalink = https://example.invalid/list'
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *'enabled for 1 enabled repositories'* && "$output" != *PASS:* ]]
  NATIVE_OUT=${NATIVE_OUT%countme = 1*}
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* && "$output" != *WARN:* ]]
}

@test "failed and diagnostic-bearing configuration streams discard partial results" {
  for NATIVE_RC in 1 124 127; do
    run _dnf_countme_audit
    [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
  NATIVE_RC=0 NATIVE_ERR='repository could not be parsed'
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
}

@test "missing duplicate and invalid native booleans cannot PASS" {
  local value
  for value in $'enabled = 1' $'enabled = 1\ncountme = 0\ncountme = 1' \
      $'enabled = 1\ncountme = unknown' $'enabled = unknown\ncountme = 0'; do
    NATIVE_OUT=$'======== "fixture" repository configuration: ========\n'"$value"
    run _dnf_countme_audit
    [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
}

@test "successful empty repository configuration earns no privacy credit" {
  NATIVE_OUT=''
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *'no enabled repositories'* && "$output" != *PASS:* && "$output" != *INCOMPLETE* ]]
}

@test "repository credentials and locations never appear in parser output" {
  NATIVE_OUT+=$'\npassword = synthetic-secret\nproxy_password = synthetic-proxy-secret\nsslcacert = /private/fixture.pem'
  run _dnf5_countme_rows <<< "$NATIVE_OUT"
  [[ "$status" -eq 0 && "$output" == '1 0 1' ]]
}

@test "unexpected output outside native records remains unassessed" {
  NATIVE_OUT=$'warning: truncated configuration\n'"$NATIVE_OUT"
  run _dnf_countme_audit
  [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
}

@test "DNF native command stays cache-only without plugins" {
  run _dnf_countme_audit
  [[ "$status" -eq 0 ]]
  grep -Fxq '15 dnf5 --cacheonly --no-plugins --dump-repo-config=*' "$CALLS"
}

@test "NetworkManager disabled runtime state retains PASS" {
  NATIVE_OUT=$'b true\nb false'
  run _nm_connectivity_audit
  [[ "$status" -eq 0 && "$output" == 'PASS:NetworkManager connectivity check disabled (effective runtime setting)' ]]
}

@test "NetworkManager enabled runtime state cannot be overridden by stale file intent" {
  NATIVE_OUT=$'b true\nb true'
  run _nm_connectivity_audit
  [[ "$status" -eq 0 && "$output" == *'checking enabled (runtime setting; actual requests not observed)'* && "$output" != *PASS:* ]]
}

@test "NetworkManager availability is separate from the enabled switch" {
  NATIVE_OUT=$'b false\nb true'
  run _nm_connectivity_audit
  [[ "$status" -eq 0 && "$output" == *'enabled but service not configured'* && "$output" != *PASS:* ]]
  NATIVE_OUT=$'b false\nb false'
  run _nm_connectivity_audit
  [[ "$status" -eq 0 && "$output" == *PASS:* ]]
}

@test "NetworkManager missing partial extra and invalid properties are unassessed" {
  for NATIVE_OUT in '' 'b true' $'b true\nb false\nb false' $'b true\ns false' $'b unknown\nb false'; do
    run _nm_connectivity_audit
    [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
}

@test "failed NetworkManager query discards even apparently complete boolean output" {
  NATIVE_OUT=$'b true\nb false' NATIVE_RC=1
  run _nm_connectivity_audit
  [[ "$status" -eq 0 && "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
}

@test "NetworkManager query reads properties without service activation or a probe" {
  NATIVE_OUT=$'b true\nb false'
  run _nm_connectivity_audit
  [[ "$status" -eq 0 ]]
  grep -Fq -- '--auto-start=no --allow-interactive-authorization=no --timeout=5 get-property' "$CALLS"
  grep -Fq 'ConnectivityCheckAvailable ConnectivityCheckEnabled' "$CALLS"
}
