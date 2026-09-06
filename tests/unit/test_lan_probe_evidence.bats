#!/usr/bin/env bats

# Bats invokes the mocks and the extracted production block indirectly.
# shellcheck disable=SC2317
# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  LAN_SOURCE="$BATS_TEST_TMPDIR/lan.sh"
  sed -n '/BEGIN NOID LAN ISOLATION PROBES/,/END NOID LAN ISOLATION PROBES/p' "$SCRIPT" > "$LAN_SOURCE"
  [[ -s "$LAN_SOURCE" ]]
  LAN_GW_LIST='192.0.2.20'
  ACTUAL_GW='192.0.2.20'
  # The dynamically sourced LAN block consumes this fixture global.
  # shellcheck disable=SC2034
  TESTED_GWS=''
  VPN_FULL_TUNNEL=true
  SKIP_PROBES=false
  HAVE_PING=true
  ROUTE_VPN=false
  OWN_VPN=false
  PING_RC=1
  PING_LOG="$BATS_TEST_TMPDIR/ping.log"
  : > "$PING_LOG"
}

should_skip() { "$SKIP_PROBES"; }
require_cmd() { [[ "$1" != ping ]] || "$HAVE_PING"; }
ping() { printf '%s\n' "$*" >> "$PING_LOG"; return "$PING_RC"; }
_iface_is_vpn() { [[ "$1" == wg-fixture ]]; }
_iface_is_dummy() { return 1; }
ip() {
  if [[ "$*" == '-o addr show' ]]; then
    if "$OWN_VPN"; then
      printf '%s\n' '7: wg-fixture inet 192.0.2.20/32 scope global wg-fixture'
    fi
  elif [[ "$*" == 'route get '* ]]; then
    if "$ROUTE_VPN"; then printf '%s\n' 'fixture-route dev wg-fixture'
    else printf '%s\n' 'fixture-route dev eth-fixture'; fi
  else
    return 1
  fi
}
_emit_pass() { printf 'PASS %s\n' "$*"; }
_emit_info() { printf 'INFO %s\n' "$*"; }
probe() {
  # shellcheck disable=SC1090
  source "$LAN_SOURCE"
}

@test "unanswered ICMP never proves LAN isolation" {
  run probe
  [[ "$status" -eq 0 && "$output" == *'did not answer ICMP:'* ]]
  [[ "$output" == *'isolation not proven'* && "$output" != *'PASS '* ]]
  [[ "$(wc -l < "$PING_LOG")" -eq 1 ]]
}

@test "failed ping commands report missing evidence instead of blocked LAN" {
  for PING_RC in 2 124 127; do
    run probe
    [[ "$status" -eq 0 && "$output" == *"ping rc=$PING_RC; isolation unassessed"* ]]
    [[ "$output" != *'PASS '* ]]
  done
}

@test "successful gateway ICMP remains reachability information" {
  PING_RC=0
  run probe
  [[ "$status" -eq 0 && "$output" == *'INFO LAN gateway reachable:'* ]]
  [[ "$output" != *'PASS '* ]]
}

@test "successful non-gateway ICMP remains reachability information" {
  PING_RC=0
  # The dynamically sourced LAN block consumes this fixture global.
  # shellcheck disable=SC2034
  ACTUAL_GW='192.0.2.1'
  run probe
  [[ "$status" -eq 0 && "$output" == *'INFO LAN candidate reachable:'* ]]
  [[ "$output" != *'PASS '* ]]
}

@test "successful VPN-route ICMP cannot establish LAN isolation" {
  PING_RC=0
  ROUTE_VPN=true
  run probe
  [[ "$status" -eq 0 && "$output" == *'INFO LAN candidate reachable via a VPN-classified route:'* ]]
  [[ "$output" == *'isolation not proven'* && "$output" != *'PASS '* ]]
}

@test "duplicate LAN candidates are probed once" {
  # The dynamically sourced LAN block consumes this fixture global.
  # shellcheck disable=SC2034
  LAN_GW_LIST='192.0.2.20 192.0.2.20 192.0.2.21 192.0.2.21'
  run probe
  [[ "$status" -eq 0 && "$(wc -l < "$PING_LOG")" -eq 2 ]]
}

@test "offline mode performs no LAN probe" {
  SKIP_PROBES=true
  run probe
  [[ "$status" -eq 0 && "$output" == *'probes skipped'* && ! -s "$PING_LOG" ]]
}

@test "absent full-tunnel intent performs no LAN probe" {
  # The dynamically sourced LAN block consumes this fixture global.
  # shellcheck disable=SC2034
  VPN_FULL_TUNNEL=false
  run probe
  [[ "$status" -eq 0 && "$output" == *'no VPN full-tunnel default route inferred'* && ! -s "$PING_LOG" ]]
}

@test "missing ping reports an unavailable probe" {
  HAVE_PING=false
  run probe
  [[ "$status" -eq 0 && "$output" == *'ping is unavailable'* && ! -s "$PING_LOG" ]]
}

@test "an owned VPN address is excluded without sending a packet" {
  OWN_VPN=true
  run probe
  [[ "$status" -eq 0 && -z "$output" && ! -s "$PING_LOG" ]]
}
