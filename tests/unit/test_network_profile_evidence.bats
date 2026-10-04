#!/usr/bin/env bats

# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  local helper
  for helper in _nm_dhcp_profile_audit _resolved_llmnr_state_from_status _remote_listener_counts _extract_ip _extract_port; do
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  PROFILE_DATA=$'auto\n0\ndisabled\n0'
  PROFILE_RC=0
}
timeout() { shift; "$@"; }
nmcli() {
  if [[ "$*" == *GENERAL.CON-UUID* ]]; then
    printf '00000000-1111-2222-3333-444444444444\n'
  else
    printf '%s\n' "$PROFILE_DATA"
  fi
  return "$PROFILE_RC"
}
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }

@test "DHCP hostname opt-out is read from the selected active profile" {
  run _nm_dhcp_profile_audit wlan-test
  [[ "$output" == *'PASS:IPv4 DHCP hostname sending disabled in active profile'* ]]
}

@test "IPv6 DHCP policy cannot disappear behind static IPv4" {
  PROFILE_DATA=$'manual\n0\nauto\n1'
  run _nm_dhcp_profile_audit wlan-test
  [[ "$output" == *'WARN:IPv6 active profile'* && "$output" != *PASS:* ]]
}

@test "inherited defaults and failed profile queries never become hostname opt-out" {
  PROFILE_DATA=$'auto\n-1\ndisabled\n0'
  run _nm_dhcp_profile_audit wlan-test
  [[ "$output" == *'inherits defaults'* && "$output" != *PASS:* ]]
  PROFILE_RC=1 PROFILE_DATA=$'auto\n0\ndisabled\n0'
  run _nm_dhcp_profile_audit wlan-test
  [[ "$output" == *unassessed* && "$output" != *PASS:* ]]
}

@test "partial or diagnostic profile tables cannot be graded" {
  for PROFILE_DATA in '' $'auto\n0' $'auto\n0\ndisabled\n0\ndiagnostic'; do
    run _nm_dhcp_profile_audit wlan-test
    [[ "$output" == *unassessed* && "$output" != *PASS:* ]]
  done
}

@test "mDNS runtime state does not borrow a disabled LLMNR setting" {
  run _resolved_llmnr_state_from_status mDNS <<< $'Link 2 (eth0)\n  Current Scopes: DNS\n  Protocols: -LLMNR +mDNS'
  [[ "$output" == enabled ]]
  run _resolved_llmnr_state_from_status mDNS <<< $'Link 2 (eth0)\n  Current Scopes: DNS\n  Protocols: +LLMNR -mDNS'
  [[ "$output" == disabled ]]
}

@test "an unknown second mDNS link prevents a global disabled verdict" {
  run _resolved_llmnr_state_from_status mDNS <<< $'Link 2 (eth0)\n  Protocols: -mDNS\nLink 3 (wlan0)\n  Current Scopes: DNS'
  [[ "$output" == unknown ]]
}


@test "remote listener scope uses the local endpoint and exact standard port" {
  run _remote_listener_counts <<< $'LISTEN 0 5 127.0.0.1:5900 0.0.0.0:* users:(("test",pid=1,fd=1))\nLISTEN 0 5 [fe80::1]:3389 [::]:*\nLISTEN 0 5 0.0.0.0:33890 0.0.0.0:*'
  [[ "$status" -eq 0 && "$output" == '1 1' ]]
}

@test "malformed listener output cannot become absence evidence" {
  run _remote_listener_counts <<< 'ss: inventory failed'
  [[ "$status" -ne 0 ]]
  run _remote_listener_counts <<< ''
  [[ "$status" -eq 0 && "$output" == '0 0' ]]
}
