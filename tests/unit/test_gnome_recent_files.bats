#!/usr/bin/env bats

# Bats and the loaded production check invoke these fixture functions.
# shellcheck disable=SC2317
# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # shellcheck disable=SC1090
  source <(awk '/^_check_gnome_recent_files\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_plural\(\) \{/,/^}/ {print}' "$SCRIPT")
  TRACKING=true
  AGE=7
  FAILED_KEY=""
  SETTINGS_CALLS="$BATS_TEST_TMPDIR/settings-calls"
  : > "$SETTINGS_CALLS"
}

_gsettings_user() {
  printf '%s\n' "$4" >> "$SETTINGS_CALLS"
  case "$4" in
    remember-recent-files) printf '%s\n' "$TRACKING" ;;
    recent-files-max-age) printf '%s\n' "$AGE" ;;
    *) return 2 ;;
  esac
  [[ "$4" != "$FAILED_KEY" ]]
}

_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }

@test "GNOME unlimited recent-file retention is WARN and preserves the negative sentinel" {
  for AGE in -1 'int32 -1'; do
    run _check_gnome_recent_files fixture 1234
    [[ "$status" -eq 0 ]]
    [[ "$output" == 'WARN:Recent files retained indefinitely (max-age=-1) [fixture]' ]]
  done
}

@test "GNOME finite recent-file durations preserve grading boundaries and int32 maximum" {
  local expected
  for AGE in 0 1 7 8 30 31 2147483647; do
    case "$AGE" in
      0|1|7) expected=PASS ;;
      8|30) expected=INFO ;;
      *) expected=WARN ;;
    esac
    run _check_gnome_recent_files fixture 1234
    [[ "$status" -eq 0 ]]
    [[ "$output" == "$expected:Recent files"* ]]
    [[ "$output" != *unassessed* ]]
  done
  AGE='int32 7'
  run _check_gnome_recent_files fixture 1234
  [[ "$status" -eq 0 ]]
  [[ "$output" == 'PASS:Recent files kept for 7 days [fixture]' ]]
}

@test "GNOME missing malformed and out-of-contract ages stay unassessed without arithmetic evaluation" {
  for AGE in '' -2 -2147483648 2147483648 9223372036854775808 9999999999999999999999999999999999 \
             08 00 +1 'uint32 7' 'error 1' '1+1' 'array[1]' $'7\n0'; do
    run _check_gnome_recent_files fixture 1234
    [[ "$status" -eq 0 ]]
    [[ "$output" == 'INFO:Recent files max-age unavailable or unsupported; retention unassessed [fixture]' ]]
  done
}

@test "GNOME failed age queries cannot produce PASS from partial values" {
  FAILED_KEY=recent-files-max-age
  for AGE in '' 0 7 -1; do
    run _check_gnome_recent_files fixture 1234
    [[ "$status" -eq 0 ]]
    [[ "$output" == 'INFO:Recent files retention query failed; retention unassessed [fixture]' ]]
  done
}

@test "GNOME disabled history does not require an age query" {
  TRACKING=false
  FAILED_KEY=recent-files-max-age
  run _check_gnome_recent_files fixture 1234
  [[ "$status" -eq 0 ]]
  [[ "$output" == 'PASS:Recent files tracking disabled [fixture]' ]]
  [[ "$(cat "$SETTINGS_CALLS")" == remember-recent-files ]]
}

@test "GNOME tracking query failure rejects partial true and false values" {
  FAILED_KEY=remember-recent-files
  for TRACKING in true false ''; do
    run _check_gnome_recent_files fixture 1234
    [[ "$status" -eq 0 ]]
    [[ "$output" == 'INFO:Recent files tracking query failed; retention unassessed [fixture]' ]]
  done
  run grep -q recent-files-max-age "$SETTINGS_CALLS"
  [[ "$status" -eq 1 ]]
}

@test "GNOME unavailable tracking values cannot establish history absence" {
  for TRACKING in '' unknown 'boolean false'; do
    run _check_gnome_recent_files fixture 1234
    [[ "$status" -eq 0 ]]
    [[ "$output" == 'INFO:Recent files tracking value unavailable or unsupported; retention unassessed [fixture]' ]]
  done
  run grep -q recent-files-max-age "$SETTINGS_CALLS"
  [[ "$status" -eq 1 ]]
}
