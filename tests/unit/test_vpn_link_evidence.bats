#!/usr/bin/env bats

# Extracted production blocks and Bats invoke fixture globals/functions.
# shellcheck disable=SC2317,SC2034
# shellcheck disable=SC1091
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # shellcheck disable=SC1090
  source <(awk '/^_iface_admin_state\(\) \{/,/^}/ {print}' "$SCRIPT")
  REPORT_SOURCE="$BATS_TEST_TMPDIR/vpn-report.sh"
  awk '/^# BEGIN NOID VPN INTERFACE EVIDENCE/ {printing=1}
       printing {print}
       /^# END NOID VPN INTERFACE EVIDENCE/ {printing=0}' "$SCRIPT" > "$REPORT_SOURCE"
  # Use the equivalent original reporting boundary for adverse-source runs.
  if [[ ! -s "$REPORT_SOURCE" ]]; then
    sed -n '/^# VPN Interface —/,/^VPN_FULL_TUNNEL=false/p' "$SCRIPT" > "$REPORT_SOURCE"
  fi
  UP_RECORD='7: wg-fixture: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000'
  LINK_RECORD="$UP_RECORD"
  LINK_RC=0
  INVENTORY="$UP_RECORD"
  INVENTORY_RC=0
  KIND=confirmed
  _VPN_IFACE_REGEX='^(tun|tap|wg|proton|pvpn)'
}

ip() {
  case "$*" in
    '-o link show up dev wg-fixture')
      [[ -z "$LINK_RECORD" ]] || printf '%s\n' "$LINK_RECORD"
      return "$LINK_RC" ;;
    '-o link show')
      [[ -z "$INVENTORY" ]] || printf '%s\n' "$INVENTORY"
      return "$INVENTORY_RC" ;;
    'link show wg-fixture') printf '%s\n' "$LINK_RECORD"; return "$LINK_RC" ;;
    *) return 127 ;;
  esac
}
_iface_vpn_kind() { printf '%s\n' "$KIND"; }
_emit_pass() { printf 'PASS %s\n' "$*"; }
_emit_info() { printf 'INFO %s\n' "$*"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }
report() {
  # shellcheck disable=SC1090
  source "$REPORT_SOURCE"
}

@test "administrative UP accepts UNKNOWN carrier state" {
  [[ "$(_iface_admin_state wg-fixture)" == up ]]
}

@test "successful empty filtered output means DOWN" {
  LINK_RECORD=''
  [[ "$(_iface_admin_state wg-fixture)" == down ]]
}

@test "failed link queries never establish UP or DOWN" {
  for LINK_RC in 1 2 124 127; do
    LINK_RECORD=''
    [[ "$(_iface_admin_state wg-fixture)" == unknown ]]
    LINK_RECORD="$UP_RECORD"
    [[ "$(_iface_admin_state wg-fixture)" == unknown ]]
  done
}

@test "partial or malformed link records remain unknown" {
  for LINK_RECORD in ' ' '7: wg-fixture: <LOWER_UP> mtu 1420' \
      '7: other: <UP> mtu 1420' '7: wg-fixture: <UP' \
      "$UP_RECORD"$'\n'"$UP_RECORD"; do
    [[ "$(_iface_admin_state wg-fixture)" == unknown ]]
  done
}

@test "an interface peer suffix preserves exact device matching" {
  LINK_RECORD='7: wg-fixture@if8: <UP,LOWER_UP> mtu 1420 state UNKNOWN'
  [[ "$(_iface_admin_state wg-fixture)" == up ]]
}

@test "UP report states the limits of link-state evidence" {
  run report
  [[ "$status" -eq 0 && "$output" == *'PASS VPN interface wg-fixture: administratively UP'* ]]
  [[ "$output" == *'peer authentication and tunnel traffic unassessed'* ]]
  [[ "$output" != *INCOMPLETE* ]]
}

@test "DOWN report never grants active VPN PASS" {
  LINK_RECORD=''
  run report
  [[ "$status" -eq 0 && "$output" == *'present but administratively down'* ]]
  [[ "$output" != *'PASS '* && "$output" != *INCOMPLETE* ]]
}

@test "failed per-device queries mark VPN evidence incomplete" {
  for LINK_RC in 1 124 127; do
    run report
    [[ "$status" -eq 0 && "$output" == *'administrative state unassessed'* ]]
    [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
    [[ "$output" != *'present but administratively down'* ]]
  done
}

@test "failed global link inventories discard partial records" {
  INVENTORY_RC=2
  run report
  [[ "$status" -eq 0 && "$output" == *'interface inventory unavailable'* ]]
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
}

@test "empty global link inventory is unavailable evidence" {
  INVENTORY=''
  run report
  [[ "$status" -eq 0 && "$output" == *'interface inventory unavailable'* ]]
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
}

@test "ambiguous UP and DOWN interfaces never grant VPN PASS" {
  KIND=ambiguous
  run report
  [[ "$status" -eq 0 && "$output" == *'VPN purpose is not independently proven'* ]]
  [[ "$output" != *'PASS '* ]]
  LINK_RECORD=''
  run report
  [[ "$status" -eq 0 && "$output" == *'present but administratively down'* ]]
  [[ "$output" != *'PASS '* ]]
}

@test "bridged TAP classification does not imply VPN activity" {
  KIND=virtual
  run report
  [[ "$status" -eq 0 && "$output" == *'not classified as VPN'* ]]
  [[ "$output" != *'PASS '* && "$output" != *INCOMPLETE* ]]
}

@test "dummy helpers are reported without a VPN activity PASS" {
  KIND=dummy
  run report
  [[ "$status" -eq 0 && "$output" == *'Dummy interface'* ]]
  [[ "$output" == *'routing helper, not a VPN tunnel'* && "$output" != *'PASS '* ]]
}
