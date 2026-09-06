#!/usr/bin/env bats

# Validate consumer control flow against presence, absence and unavailable data.
# The identity and NUL argument readers have separate fixture/native coverage.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  # shellcheck disable=SC1090
  source <(awk '/^_de_check_file_indexer\(\) \{/,/^}/ {print}' "$SCRIPT")
  # Extract narrow production blocks inside functions to preserve local scope.
  # shellcheck disable=SC1090
  source <(printf '_clip_block() {\n'; sed -n '/^  local clip_procs=/,/^  local core_pattern/p' "$SCRIPT" | sed '$d'; printf '}\n')
  # shellcheck disable=SC1090
  source <(printf '_portal_block() {\n'; awk '/^  if _process_running_exact xdg-desktop-portal; then/ {found=1} found && /^}/ {exit} found {print}' "$SCRIPT"; printf '}\n')
  # shellcheck disable=SC1090
  source <(printf '_wsdd_block() {\n'; awk '/^# (wsdd \(Web Services Discovery\) check|WS-Discovery: unit state)/ {found=1} /^# Failed Services/ {exit} found {print}' "$SCRIPT"; printf '}\n')
  declare -gA PROC_RCS=()
  DEFAULT_PROC_RC=1 WSDD_PIDS='' WSDD2_PIDS='' WSDD_PID_RC=1 WSDD2_PID_RC=1 ARG_RC=1
  WSDD_UNIT_STATE=absent OTHER_UNIT_STATE=active
  _DE_FAMILY=gnome
}
_process_running_exact() { return "${PROC_RCS[$1]:-$DEFAULT_PROC_RC}"; }
_process_pids_exact() {
  case "$1" in
    wsdd) printf '%s' "$WSDD_PIDS"; return "$WSDD_PID_RC" ;;
    wsdd2) printf '%s' "$WSDD2_PIDS"; return "$WSDD2_PID_RC" ;;
    *) return "$DEFAULT_PROC_RC" ;;
  esac
}
_process_has_any_arg() { return "$ARG_RC"; }
_service_group_state() { if [[ "$1" == wsdd.service ]]; then printf '%s\n' "$WSDD_UNIT_STATE"; else printf '%s\n' "$OTHER_UNIT_STATE"; fi; }
systemctl() { return 3; }
require_cmd() { return 1; }
_ufw_is_active() { return 0; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_fail() { printf 'FAIL:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }
_plural() { if [[ "$1" == 1 ]]; then printf '%s' "$2"; else printf '%s' "$3"; fi; }

@test "complete clipboard process absence retains PASS" {
  run _clip_block
  [[ "$output" == 'PASS:No clipboard manager daemon detected' ]]
}

@test "clipboard process read failure cannot become an absence PASS" {
  PROC_RCS[clipman]=2
  run _clip_block
  [[ "$output" == 'INFO:Clipboard manager process inventory incomplete (unassessed)' ]]
}

@test "Klipper query failure remains unassessed" {
  PROC_RCS[klipper]=2
  run _clip_block
  [[ "$output" == 'INFO:Clipboard manager process inventory incomplete (unassessed)' ]]
}

@test "portal query failure does not become a not-running assertion" {
  PROC_RCS[xdg-desktop-portal]=2
  run _portal_block
  [[ "$output" == 'INFO:xdg-desktop-portal process state unavailable (unassessed)' ]]
}

@test "known portal absence remains explicit" {
  run _portal_block
  [[ "$output" == 'INFO:xdg-desktop-portal not running' ]]
}

@test "KDE indexer absence needs both candidate queries" {
  _DE_FAMILY=kde PROC_RCS[baloo_file_extractor]=2
  run _de_check_file_indexer
  [[ "$status" -eq 2 && "$output" == 'KDE Baloo' ]]
}

@test "known KDE indexer presence remains evidence despite another failed query" {
  _DE_FAMILY=kde PROC_RCS[baloo_file]=2 PROC_RCS[baloo_file_extractor]=0
  run _de_check_file_indexer
  [[ "$status" -eq 0 && "$output" == 'KDE Baloo' ]]
}

@test "complete WS-Discovery absence retains a bounded PASS" {
  run _wsdd_block
  [[ "$output" == *'PASS:WS-Discovery: no wsdd/wsdd2 process or active service detected'* ]]
}

@test "failed WS-Discovery process query cannot establish absence" {
  WSDD_PID_RC=2
  run _wsdd_block
  [[ "$output" == *'INFO:WS-Discovery state incomplete'* && "$output" != *'PASS:'* ]]
}

@test "unknown WS-Discovery service state cannot establish absence" {
  WSDD_UNIT_STATE=unknown
  run _wsdd_block
  [[ "$output" == *'INFO:WS-Discovery state incomplete'* && "$output" != *'PASS:'* ]]
}

@test "no-host argument is option inventory without a parentage or traffic claim" {
  WSDD_PIDS=123 WSDD_PID_RC=0 ARG_RC=0
  run _wsdd_block
  [[ "$output" == *'INFO:wsdd: 1 process with an explicit --no-host/-o argument (option inventory; traffic and parentage not inferred)'* ]]
  [[ "$output" != *'PASS:'* && "$output" != *'spawned'* ]]
}

@test "WS-Discovery process without a confirmed client option receives a review warning" {
  WSDD_PIDS=123 WSDD_PID_RC=0
  run _wsdd_block
  [[ "$output" == *'WARN:WS-Discovery process detected without a confirmed client-only option'* ]]
  [[ "$output" != *'broadcasts hostname'* ]]
}

@test "GVFS presence never proves firewall protection or LAN exposure" {
  PROC_RCS[gvfsd-wsdd]=0
  run _wsdd_block
  [[ "$output" == *'INFO:gvfsd-wsdd running (GNOME network browsing; listener and firewall scope are evaluated in Section 8)'* ]]
  [[ "$output" != *'firewall-protected'* && "$output" != *'exposed on LAN'* ]]
}

@test "failed cross-section state query does not declare a package absent" {
  OTHER_UNIT_STATE=unknown
  run _wsdd_block
  [[ "$output" == *'INFO:Service state unavailable: firewalld'* ]]
  [[ "$output" != *'not installed'* ]]
}

@test "active WS-Discovery unit is visible without invented traffic observations" {
  WSDD_UNIT_STATE=active
  run _wsdd_block
  [[ "$output" == *'WARN:WS-Discovery service active'* && "$output" != *'PASS:'* ]]
  [[ "$output" != *'broadcasts hostname'* ]]
}

@test "unreadable WS-Discovery arguments remain unassessed" {
  WSDD_PIDS=123 WSDD_PID_RC=0 ARG_RC=2
  run _wsdd_block
  [[ "$output" == *'INFO:wsdd process options unreadable or process exited (mode unassessed)'* ]]
  [[ "$output" != *'PASS:'* ]]
}

@test "known wsdd observation does not complete a partial process inventory" {
  WSDD_PIDS=123 WSDD_PID_RC=2 ARG_RC=0
  run _wsdd_block
  [[ "$output" == *'INFO:wsdd: 1 process'* && "$output" == *'INFO:WS-Discovery state incomplete'* ]]
  [[ "$output" != *'PASS:'* ]]
}

@test "standalone wsdd2 is not omitted from process inventory" {
  WSDD2_PIDS=123 WSDD2_PID_RC=0
  run _wsdd_block
  [[ "$output" == *'WARN:WS-Discovery process detected'* && "$output" != *'PASS:'* ]]
}
