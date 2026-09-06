#!/usr/bin/env bats

# Native-response consumer tests; commands are replaced, grading is not.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _chrony_nts_audit _bluetooth_rfkill_state check_bluetooth_privacy check_ntp _chrony_source_counts _chrony_source_quality_state; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  AUTH_HEADER='Name/IP address             Mode KeyID Type KLen Last Atmp  NAK Cook CLen'
  AUTH_OUT="$AUTH_HEADER"$'\n=========\n192.0.2.1 NTS 1 15 256 2h 0 0 8 100'
  AUTH_RC=0 BT_STATE=inactive BT_CTL=0 RF_OUT='bluetooth unblocked blocked' RF_RC=0
  TIME_OUT=yes TIME_RC=0 CHRONY_ACTIVE=0 NTP_STATE=active
}
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }
should_skip() { return 1; }
header() { :; }
require_cmd() { [[ "$1" == timedatectl || "$1" == chronyc ]]; }
_plural() { if [[ "$1" == 1 ]]; then printf '%s' "$2"; else printf '%ss' "$2"; fi; }
_service_unit_state() { printf '%s' "$BT_STATE"; }
_service_group_state() { printf '%s' "$NTP_STATE"; }
_active_chrony_unit() { [[ "$CHRONY_ACTIVE" == 1 ]] && printf 'chronyd.service'; }
timedatectl() { if [[ "$*" == *NTPSynchronized* ]]; then printf '%s' "$TIME_OUT"; return "$TIME_RC"; else printf UTC; fi; }
chronyc() { printf 'MS Name/IP address Stratum Poll Reach LastRx Last sample\n===\n'; }
command() {
  [[ "$1" == -v && "$2" == bluetoothctl ]] && return "$BT_CTL"
  [[ "$1" == -v && "$2" == rfkill ]] && return 0
  builtin command "$@"
}
rfkill() { printf '%s' "$RF_OUT"; return "$RF_RC"; }
timeout() { if [[ "$*" == '10 chronyc -n authdata' ]]; then printf '%s' "$AUTH_OUT"; return "$AUTH_RC"; fi; return 1; }

@test "native NTS records establish key material with bounded wording" {
  run _chrony_nts_audit
  [[ "$output" == *'PASS:NTS key material available for 1 of 1 associations'* ]]
  [[ "$output" == *'packet authentication not rechecked'* ]]
}

@test "NTS mode without keys or cookies does not prove usable authentication" {
  for row in '192.0.2.1 NTS 0 0 0 - 1 0 0 0' '192.0.2.1 NTS 1 15 256 2h 0 0 0 100'; do
    AUTH_OUT="$AUTH_HEADER"$'\n'"$row"
    run _chrony_nts_audit
    [[ "$output" == *'usable key material not established'* && "$output" != *PASS:* ]]
  done
}

@test "non-NTS and empty native inventories do not earn NTS credit" {
  for row in '' '192.0.2.1 SK 30 13 128 - 0 0 0 0' '192.0.2.1 - 0 0 0 - 0 0 0 0'; do
    AUTH_OUT="$AUTH_HEADER"$'\n'"$row"
    run _chrony_nts_audit
    [[ "$output" == 'INFO:No NTS associations reported by chrony' ]]
  done
}

@test "failed partial NTS queries do not fall back to configuration PASS" {
  for AUTH_RC in 1 124; do
    run _chrony_nts_audit
    [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
}

@test "malformed or diagnostic-bearing authdata is unassessed" {
  for AUTH_OUT in '' '192.0.2.1 NTS 1 15 256 2h 0 0 8 100' "$AUTH_OUT"$'\nerror'; do
    run _chrony_nts_audit
    [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
}

@test "native synchronized and unsynchronized values retain different grades" {
  run check_ntp
  [[ "$output" == *'PASS:NTP synchronized'* ]]
  TIME_OUT=no
  run check_ntp
  [[ "$output" == *'WARN:NTP not synchronized'* ]]
}

@test "time query failure and unknown service state cannot create an outage warning" {
  TIME_RC=1 NTP_STATE=unknown
  run check_ntp
  [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* && "$output" != *WARN:* ]]
  TIME_RC=0 TIME_OUT=unknown
  run check_ntp
  [[ "$output" == *'synchronization state unavailable'* && "$output" != *WARN:* ]]
}

@test "Bluetooth inactivity is assessed independently of the controller client" {
  BT_CTL=1
  run check_bluetooth_privacy
  [[ "$output" == *'PASS:Bluetooth service is not running'* && "$output" != *'cannot start'* ]]
}

@test "Bluetooth manager failures and transitions never imply inactive service" {
  for BT_STATE in unknown transitioning; do
    run check_bluetooth_privacy
    [[ "$output" == *INCOMPLETE* && "$output" != *PASS:* ]]
  done
}

@test "masked means inactive and masked while active service still requires radio evidence" {
  BT_STATE=masked
  run check_bluetooth_privacy
  [[ "$output" == 'PASS:Bluetooth service inactive and masked' ]]
  BT_STATE=active
  run check_bluetooth_privacy
  [[ "$output" == *'All reported Bluetooth radios blocked'* && "$output" != *'inactive and masked'* ]]
}

@test "rfkill blocks must cover all Bluetooth radios and ignore other radio types" {
  run _bluetooth_rfkill_state <<< $'wlan unblocked unblocked\nbluetooth blocked unblocked\nbluetooth unblocked blocked'
  [[ "$status" -eq 0 && "$output" == blocked ]]
  run _bluetooth_rfkill_state <<< $'bluetooth blocked unblocked\nbluetooth unblocked unblocked'
  [[ "$status" -eq 0 && "$output" == unblocked ]]
  run _bluetooth_rfkill_state <<< 'wlan unblocked unblocked'
  [[ "$status" -eq 0 && "$output" == none ]]
}

@test "incomplete or failed rfkill evidence cannot establish radio blocking" {
  for RF_OUT in 'bluetooth blocked' 'bluetooth unknown blocked'; do
    run _bluetooth_rfkill_state <<< "$RF_OUT"
    [[ "$status" -ne 0 ]]
  done
  BT_STATE=active RF_OUT='bluetooth blocked blocked' RF_RC=1
  run check_bluetooth_privacy
  [[ "$output" == *'radio block state unavailable'* && "$output" != *PASS:* ]]
}
