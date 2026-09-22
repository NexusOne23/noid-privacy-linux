#!/usr/bin/env bats

# Exercise production GNOME readers/consumers with controlled native responses.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _user_unit_runtime_state _gnome_indexer_state _de_check_file_indexer _gnome_privacy_boolean; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  # Preserve the real section's handling of the dispatcher's status.
  # shellcheck disable=SC1090
  source <(printf '_indexer_consumer() {\n'; sed -n '/^  local _idx_name _idx_rc/,/^  _flatpak_permission_audit/p' "$SCRIPT" | sed '$d'; printf '}\n')
  declare -gA UNIT_RAWS=() UNIT_RCS=() PROC_RCS=()
  UNIT_DEFAULT=$'LoadState=masked\nActiveState=inactive'
  UNIT_RC=0 PROC_RC=1 ACCOUNT_RC=0 VALUE_RC=0
  ROWS='fixture:x:1000:1000::/fixture:/bin/bash'
  VALUE=false
  _DE_FAMILY=gnome
  CALLS="$BATS_TEST_TMPDIR/unit-calls"
}

timeout() {
  [[ "$1" == 5 && "$2" == sudo && "$3" == -n && "$4" == -u && "$6" == -- && "$7" == env ]] || return 98
  [[ "$8" == DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/*/bus && "$9" == XDG_RUNTIME_DIR=/run/user/* ]] || return 98
  [[ "${10}" == systemctl && "${11}" == --user && "${12}" == show && "${13}" == --all && "${14}" == --no-pager ]] || return 98
  [[ "${15}" == -p && "${16}" == LoadState && "${17}" == -p && "${18}" == ActiveState ]] || return 98
  local unit="${19}"
  printf '%s %s\n' "$5" "$unit" >> "$CALLS"
  printf '%s\n' "${UNIT_RAWS[$unit]-$UNIT_DEFAULT}"
  return "${UNIT_RCS[$unit]-$UNIT_RC}"
}
_process_running_exact() { return "${PROC_RCS[$1]-$PROC_RC}"; }
_passwd_lines() { printf '%s\n' "$ROWS"; return "$ACCOUNT_RC"; }
_is_human_uid() { [[ "$1" -ge 1000 ]]; }
_gsettings_user() { printf '%s\n' "$VALUE"; return "$VALUE_RC"; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }

@test "checked loaded masked and absent inactive user units remain inactive" {
  local load
  for load in loaded masked not-found; do
    UNIT_DEFAULT="LoadState=$load"$'\nActiveState=inactive'
    run _user_unit_runtime_state fixture 1000 fixture.service
    [[ "$status" -eq 0 && "$output" == inactive ]]
  done
}

@test "an active unit remains active even if its file has been masked" {
  UNIT_DEFAULT=$'LoadState=masked\nActiveState=active'
  run _user_unit_runtime_state fixture 1000 fixture.service
  [[ "$status" -eq 0 && "$output" == active ]]
}

@test "failed empty and partial user-manager queries cannot establish absence" {
  for UNIT_RC in 1 124 127; do
    run _user_unit_runtime_state fixture 1000 fixture.service
    [[ "$status" -ne 0 && -z "$output" ]]
  done
  UNIT_RC=0 UNIT_DEFAULT=''
  run _user_unit_runtime_state fixture 1000 fixture.service
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "missing duplicate and unknown properties are unassessed" {
  for UNIT_DEFAULT in 'ActiveState=inactive' 'LoadState=masked' \
      $'LoadState=masked\nActiveState=inactive\nActiveState=inactive' \
      $'LoadState=masked\nActiveState=inactive\nUnexpected=value' \
      $'LoadState=\nActiveState=active'; do
    run _user_unit_runtime_state fixture 1000 fixture.service
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "transitioning failed and unknown unit states do not gain an inactivity verdict" {
  local state
  for state in activating deactivating failed unknown; do
    UNIT_DEFAULT="LoadState=loaded"$'\n'"ActiveState=$state"
    run _user_unit_runtime_state fixture 1000 fixture.service
    [[ "$status" -ne 0 && -z "$output" ]]
  done
  UNIT_DEFAULT=$'LoadState=error\nActiveState=inactive'
  run _user_unit_runtime_state fixture 1000 fixture.service
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "invalid UIDs never reach sudo or arithmetic" {
  local uid
  for uid in '' 01000 -1 'array[1]' 99999999999999999999; do
    run _user_unit_runtime_state fixture "$uid" fixture.service
    [[ "$status" -ne 0 && -z "$output" ]]
  done
  [[ ! -e "$CALLS" ]]
}

@test "complete GNOME absence checks all known units and retains PASS" {
  run _indexer_consumer
  [[ "$status" -eq 0 && "$output" == 'PASS:GNOME Tracker/LocalSearch file indexer not running' ]]
  [[ "$(wc -l < "$CALLS")" -eq 3 ]]
}

@test "a user-bus error cannot become indexer inactivity PASS" {
  UNIT_RC=1
  run _indexer_consumer
  [[ "$status" -eq 0 && "$output" == *'native indexer is unassessed'* ]]
  [[ "$output" == *'INCOMPLETE'* && "$output" != *'PASS:'* ]]
}

@test "a later active unit remains positive despite an earlier query error" {
  UNIT_RCS[tracker-miner-fs-3.service]=1
  UNIT_RAWS[localsearch-3.service]=$'LoadState=loaded\nActiveState=active'
  run _gnome_indexer_state
  [[ "$status" -eq 0 && -z "$output" ]]
}

@test "native process presence also detects standalone GNOME indexers" {
  PROC_RCS[localsearch-extractor-3]=0
  ACCOUNT_RC=1
  run _gnome_indexer_state
  [[ "$status" -eq 0 && ! -e "$CALLS" ]]
}

@test "failed process evidence is not hidden by inactive user units" {
  PROC_RCS[tracker-miner-fs]=2
  run _gnome_indexer_state
  [[ "$status" -eq 2 ]]
}

@test "a later process observation still establishes presence after another error" {
  PROC_RCS[localsearch-3]=2 PROC_RCS[tracker-miner-fs]=0
  run _gnome_indexer_state
  [[ "$status" -eq 0 && ! -e "$CALLS" ]]
}

@test "failed partial and empty account snapshots do not establish absence" {
  ACCOUNT_RC=1
  run _gnome_indexer_state
  [[ "$status" -eq 2 && ! -e "$CALLS" ]]
  ACCOUNT_RC=0 ROWS=''
  run _gnome_indexer_state
  [[ "$status" -eq 2 ]]
}

@test "malformed account rows cannot silently shrink the checked scope" {
  ROWS=$'fixture:x:1000:1000::/fixture:/bin/bash\nmalformed'
  run _gnome_indexer_state
  [[ "$status" -eq 2 ]]
}

@test "no eligible human account remains explicitly unassessed" {
  for ROWS in 'root:x:0:0::/root:/bin/bash' 'service:x:1001:1001::/fixture:/usr/sbin/nologin'; do
    run _gnome_indexer_state
    [[ "$status" -eq 2 && ! -e "$CALLS" ]]
  done
}

@test "each eligible local account is checked" {
  ROWS+=$'\nsecond:x:1001:1001::/custom:/bin/bash'
  run _gnome_indexer_state
  [[ "$status" -eq 1 && "$(wc -l < "$CALLS")" -eq 6 ]]
}

@test "GNOME boolean false retains the normal disabled PASS" {
  run _gnome_privacy_boolean fixture 1000 org.gnome.system.location enabled 'GNOME Location Services'
  [[ "$status" -eq 0 && "$output" == 'PASS:GNOME Location Services disabled [fixture]' ]]
}

@test "GNOME boolean true retains the enabled warning" {
  VALUE=true
  run _gnome_privacy_boolean fixture 1000 org.gnome.system.location enabled 'GNOME Location Services'
  [[ "$status" -eq 0 && "$output" == 'WARN:GNOME Location Services enabled [fixture]' ]]
}

@test "failed boolean queries discard both partial false and true output" {
  VALUE_RC=1
  for VALUE in true false ''; do
    run _gnome_privacy_boolean fixture 1000 org.gnome.system.location enabled 'GNOME Location Services'
    [[ "$status" -eq 0 && "$output" == *'query failed; setting unassessed'* ]]
    [[ "$output" == *INCOMPLETE* && "$output" != *'PASS:'* && "$output" != *'WARN:'* ]]
  done
}

@test "unsupported empty and multi-value booleans remain unassessed" {
  for VALUE in '' 'boolean false' unknown $'true\nfalse'; do
    run _gnome_privacy_boolean fixture 1000 org.gnome.system.location enabled 'GNOME Location Services'
    [[ "$status" -eq 0 && "$output" == *'value unavailable or unsupported; setting unassessed'* ]]
    [[ "$output" == *INCOMPLETE* && "$output" != *'PASS:'* && "$output" != *'WARN:'* ]]
  done
}
