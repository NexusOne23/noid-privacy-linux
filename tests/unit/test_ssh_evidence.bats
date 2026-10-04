#!/usr/bin/env bats

# Production readers/section with controlled external responses; actual native
# parser and /proc counterexamples are recorded separately in the audit notes.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _ssh_config_dump sshd_cfg_val _ssh_access_list_state _ssh_weak_algorithms _ssh_activation_state _ssh_grade_config _ssh_key_inventory check_ssh; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  UNIT_STATE=absent UNIT_RC=0 PROCESS_RC=1 PROCESS_NAME=sshd
  G_RC=0 T_RC=0 G_OUT='' T_OUT='' PARSER_CALLS="$BATS_TEST_TMPDIR/parser-calls"
  GOOD=$'permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\npubkeyauthentication yes\nx11forwarding no\nmaxauthtries 3\nlogingracetime 60\nciphers aes256-ctr\nmacs hmac-sha2-256\nkexalgorithms curve25519-sha256'
}

_service_group_state() { printf '%s\n' "$UNIT_STATE"; return "$UNIT_RC"; }
_process_running_exact() { if [[ "$1" == "$PROCESS_NAME" ]]; then return "$PROCESS_RC"; else return 1; fi; }
timeout() {
  [[ "$1" == 10 && "$2" == sshd ]] || return 90
  printf '%s\n' "$3" >> "$PARSER_CALLS"
  case "$3" in
    -G) printf '%s' "$G_OUT"; return "$G_RC" ;;
    -T) printf '%s' "$T_OUT"; return "$T_RC" ;;
    *) return 91 ;;
  esac
}
should_skip() { return 1; }
header() { :; }
sub_header() { :; }
require_cmd() { return 1; }
_ssh_collect_key_files() { _SSH_KEY_PATHS=(); }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_fail() { printf 'FAIL:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }

@test "known inactive units and absent processes permit only scoped inventory PASS" {
  run check_ssh
  [[ "$status" -eq 0 && "$output" == 'PASS:SSH: no enabled OpenSSH unit or matching process detected (current inventory)' ]]
  [[ ! -e "$PARSER_CALLS" ]]
}

@test "unreadable unit state cannot prove SSH absence" {
  UNIT_RC=1 G_RC=1 T_RC=1
  run check_ssh
  [[ "$output" == *'activation unassessed'* && "$output" == *'INCOMPLETE'* && "$output" != *'PASS:'* ]]
}

@test "unreadable process state cannot prove SSH absence" {
  PROCESS_RC=2 G_RC=1 T_RC=1
  run check_ssh
  [[ "$output" == *'activation unassessed'* && "$output" != *'PASS:'* ]]
}

@test "runtime enablement prevents inactive shortcut" {
  UNIT_STATE=enabled-runtime G_OUT="$GOOD"
  run check_ssh
  [[ "$output" == *'PASS:SSH: PermitRootLogin no'* && "$output" != *'no enabled OpenSSH'* ]]
}

@test "active socket and transitioning or failed units reach configuration review" {
  for UNIT_STATE in active transitioning failed enabled; do
    G_OUT="$GOOD"
    run check_ssh
    [[ "$output" == *'PASS:SSH: PermitRootLogin no'* && "$output" != *'no enabled OpenSSH'* ]]
  done
}

@test "standalone daemon and split OpenSSH workers prevent inactive shortcut" {
  for PROCESS_NAME in sshd sshd-session sshd-auth; do
    PROCESS_RC=0 G_OUT="$GOOD"
    run check_ssh
    [[ "$output" == *'PASS:SSH: PermitRootLogin no'* && "$output" != *'no enabled OpenSSH'* ]]
  done
}

@test "known process presence survives a separate unit query failure" {
  UNIT_RC=1 PROCESS_RC=0
  run _ssh_activation_state
  [[ "$status" -eq 0 && "$output" == present ]]
}

@test "all scalar checks share one successful parser invocation" {
  UNIT_STATE=active G_OUT="$GOOD"
  run check_ssh
  [[ "$status" -eq 0 && "$output" == *'LoginGraceTime 60s'* ]]
  [[ "$(cat "$PARSER_CALLS")" == -G ]]
}

@test "legacy parser fallback requires its own successful response" {
  G_RC=1 T_OUT="$GOOD"
  run _ssh_config_dump
  [[ "$status" -eq 0 && "$output" == "$GOOD" ]]
  [[ "$(cat "$PARSER_CALLS")" == $'-G\n-T' ]]
}

@test "failed partial responses never become configuration evidence" {
  UNIT_STATE=active G_OUT="$GOOD" T_OUT="$GOOD" G_RC=1 T_RC=1
  run check_ssh
  [[ "$output" == *'global configuration unavailable'* && "$output" != *'PASS:'* ]]
}

@test "empty successful responses never invent OpenSSH defaults" {
  UNIT_STATE=active
  run check_ssh
  [[ "$output" == *'global configuration unavailable'* && "$output" != *'PASS:'* ]]
}

@test "successful partial response leaves missing controls unassessed" {
  UNIT_STATE=active G_OUT='permitrootlogin no'
  run check_ssh
  [[ "$output" == *'PASS:SSH: PermitRootLogin no'* ]]
  [[ "$output" == *'PermitEmptyPasswords unavailable'* && "$output" == *'PubkeyAuthentication unavailable'* ]]
  [[ "$output" != *'PASS:SSH: PermitEmptyPasswords'* && "$output" != *'PASS:SSH: PubkeyAuthentication'* ]]
}

@test "duplicate scalar fields are rejected instead of choosing first" {
  run sshd_cfg_val PermitRootLogin $'permitrootlogin no\npermitrootlogin yes'
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "empty or extra scalar tokens are rejected" {
  for raw in 'permitemptypasswords' 'permitemptypasswords no yes'; do
    run sshd_cfg_val PermitEmptyPasswords "$raw"
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "configuration scope explicitly excludes Match and runtime overrides" {
  _emit_info() {
    printf 'INFO:%s\n' "$1"
    if [[ "${2:-}" == evidence-limit ]]; then printf 'AI-EVIDENCE:%s\n' "$1"; fi
  }
  run _ssh_grade_config "$GOOD"
  [[ "$output" == *'connection-specific Match rules, daemon launch overrides and loaded runtime state are not verified'* ]]
  [[ "$output" == *'AI-EVIDENCE:SSH configuration scope:'* ]]
}

@test "LoginGraceTime zero is unlimited, never a short-timeout PASS" {
  run _ssh_grade_config "${GOOD/logingracetime 60/logingracetime 0}"
  [[ "$output" == *'WARN:SSH: LoginGraceTime 0 (no authentication time limit)'* ]]
  [[ "$output" != *'PASS:SSH: LoginGraceTime'* ]]
}

@test "positive grace-time boundaries are graded in native seconds" {
  for n in 1 60; do
    run _ssh_grade_config "${GOOD/logingracetime 60/logingracetime $n}"
    [[ "$output" == *"PASS:SSH: LoginGraceTime ${n}s"* ]]
  done
  run _ssh_grade_config "${GOOD/logingracetime 60/logingracetime 61}"
  [[ "$output" == *'WARN:SSH: LoginGraceTime 61s'* ]]
}

@test "invalid numeric responses cannot reach shell arithmetic or invented defaults" {
  for n in 1m 08 -1 2147483648 999999999999999999999999999 'x[1]'; do
    local raw="${GOOD/logingracetime 60/logingracetime $n}"
    raw="${raw/maxauthtries 3/maxauthtries $n}"
    run _ssh_grade_config "$raw"
    [[ "$status" -eq 0 && "$output" == *'LoginGraceTime unavailable or invalid'* && "$output" == *'MaxAuthTries unavailable or invalid'* ]]
    [[ "$output" != *'syntax error'* && "$output" != *'value too great'* ]]
  done
}

@test "MaxAuthTries zero is availability context rather than hardening PASS" {
  run _ssh_grade_config "${GOOD/maxauthtries 3/maxauthtries 0}"
  [[ "$output" == *'INFO:SSH: MaxAuthTries 0'* && "$output" != *'PASS:SSH: MaxAuthTries'* ]]
}

@test "repeated native AllowUsers patterns are inventory without exposing identities" {
  run _ssh_grade_config "$GOOD"$'\nallowusers fixture\nallowusers *\nallowgroups sample'
  [[ "$output" == *'global AllowUsers/AllowGroups patterns configured'* && "$output" != *'fixture'* && "$output" != *'sample'* ]]
  [[ "$output" != *'whitelist active'* ]]
}

@test "absent global access patterns do not claim connection-specific absence" {
  run _ssh_grade_config "$GOOD"
  [[ "$output" == *'no global AllowUsers/AllowGroups patterns (connection-specific restrictions unassessed)'* ]]
}

@test "malformed native access-list row is unassessed" {
  run _ssh_grade_config "$GOOD"$'\nallowusers'
  [[ "$output" == *'AllowUsers/AllowGroups response invalid'* && "$output" == *'INCOMPLETE'* ]]
}

@test "algorithm-list modifiers and empty elements cannot be treated as effective algorithms" {
  for list in '-aes256-cbc' '+aes256-cbc' '^aes256-ctr' 'aes256-ctr,' ',aes256-ctr' 'aes256-ctr,,aes128-ctr' $'aes256-ctr\nhmac-sha1'; do
    run _ssh_weak_algorithms "$list"
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "legacy algorithm families use the production classifier" {
  run _ssh_weak_algorithms 'aes256-cbc,hmac-md5-96,hmac-sha1-etm@openssh.com,umac-64@openssh.com,rsa1024-sha1,aes256-ctr'
  [[ "$status" -eq 0 && "$output" == 'aes256-cbc hmac-md5-96 hmac-sha1-etm@openssh.com umac-64@openssh.com rsa1024-sha1' ]]
}

@test "strong algorithm screen makes no universal cryptographic guarantee" {
  run _ssh_grade_config "$GOOD"
  [[ "$output" == *'no configured algorithms match the legacy-family screen'* ]]
  [[ "$output" != *'no weak algorithms'* ]]
}

@test "unknown boolean values cannot produce default PASS" {
  local raw="${GOOD/permitemptypasswords no/permitemptypasswords future}"
  raw="${raw/pubkeyauthentication yes/pubkeyauthentication future}"
  run _ssh_grade_config "$raw"
  [[ "$output" == *'PermitEmptyPasswords unavailable or invalid'* && "$output" == *'PubkeyAuthentication unavailable or invalid'* ]]
  [[ "$output" != *'PASS:SSH: PermitEmptyPasswords'* && "$output" != *'PASS:SSH: PubkeyAuthentication'* ]]
}

@test "complete positive configuration grades every scalar including X11Forwarding" {
  run _ssh_grade_config "$GOOD"
  [[ "$status" -eq 0 && "$output" == *'PASS:SSH: X11Forwarding no'* ]]
  [[ "$output" != *'INCOMPLETE'* && "$output" != *'unavailable'* && "$output" != *'WARN:'* && "$output" != *'FAIL:'* ]]
}

@test "explicit empty-password permission retains a failure without claiming authentication bypass" {
  run _ssh_grade_config "${GOOD/permitemptypasswords no/permitemptypasswords yes}"
  [[ "$output" == *'FAIL:SSH: PermitEmptyPasswords yes'*'other authentication requirements still apply'* ]]
  [[ "$output" != *'PASS:SSH: PermitEmptyPasswords'* ]]
}

@test "root authentication severity uses the native configured mode" {
  for mode in prohibit-password without-password forced-commands-only; do
    run _ssh_grade_config "${GOOD/permitrootlogin no/permitrootlogin $mode}"
    [[ "$output" == *"WARN:SSH: PermitRootLogin $mode"* && "$output" != *'FAIL:SSH: PermitRootLogin'* ]]
  done
  run _ssh_grade_config "${GOOD/permitrootlogin no/permitrootlogin yes}"
  [[ "$output" == *'FAIL:SSH: PermitRootLogin yes'* ]]
}
