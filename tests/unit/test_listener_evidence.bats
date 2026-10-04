#!/usr/bin/env bats

# Bats and the loaded production section invoke these fixture functions.
# shellcheck disable=SC2317
# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # The section defines nested helpers, so use its next section boundary.
  # shellcheck disable=SC1090
  source <(awk '/^check_ssh\(\)/ {exit} /^check_ports\(\)/ {found=1} found {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_plural\(\) \{/,/^}/ {print}' "$SCRIPT")
  local helper
  for helper in _extract_ip _extract_scope_iface _extract_port; do
    # Shared with the desktop section, so loaded outside check_ports.
    # shellcheck disable=SC1090
    source <(awk -v signature="$helper() {" '$0==signature {found=1} found {print} found && /^}/ {exit}' "$SCRIPT")
  done
  SS_FAILURE=""
  SS_POPULATED=false
  SS_PARTIAL=false
}

should_skip() { return 1; }
header() { :; }
sub_header() { :; }
ip() { return 0; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }
_emit_fail() { printf 'FAIL:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }

ss() {
  local failed=false args="$*"
  [[ "$args" == '-H '* ]] || args="-H $args"
  [[ "$SS_FAILURE" == all || "$args" == "$SS_FAILURE" ]] && failed=true
  if $failed && ! $SS_PARTIAL; then return 1; fi
  if $SS_POPULATED; then
    [[ "$*" == '-H '* ]] || printf '%s\n' 'State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process'
    case "$args" in
      '-H -tlnp'|'-H -tln') printf '%s\n' 'LISTEN 0 8 127.0.0.1:8443 0.0.0.0:* users:(("fixture",pid=42,fd=3))' ;;
      '-H -ulnp') printf '%s\n' 'UNCONN 0 0 127.0.0.1:5353 0.0.0.0:* users:(("fixture",pid=42,fd=4))' ;;
      '-H -tn state established') printf '%s\n' '0 0 192.0.2.10:45000 198.51.100.10:45678' ;;
      '-H -wnp') printf '%s\n' 'UNCONN 0 0 0.0.0.0:1 0.0.0.0:*' ;;
      *) return 2 ;;
    esac
  fi
  ! $failed
}

@test "successful empty socket queries retain four absence findings" {
  run check_ports
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'PASS:No TCP listeners'* ]]
  [[ "$output" == *'PASS:No UDP listeners'* ]]
  [[ "$output" == *'PASS:No likely outbound connections'* ]]
  [[ "$output" == *'PASS:No raw sockets'* ]]
  [[ "$output" != *unassessed* ]]
}

@test "failed socket queries never produce absence PASS findings" {
  SS_FAILURE=all
  run check_ports
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" == *'TCP listener inventory unavailable:'* ]]
  [[ "$output" == *'UDP listener inventory unavailable:'* ]]
  [[ "$output" == *'Outbound peer-port inventory unavailable:'* ]]
  [[ "$output" == *'Raw socket inventory unavailable:'* ]]
}

@test "partial socket output cannot establish listeners or peer ports" {
  SS_FAILURE=all
  SS_POPULATED=true
  SS_PARTIAL=true
  run check_ports
  [[ "$status" -eq 0 ]]
  [[ "$output" != *PASS:* ]]
  [[ "$output" != *fixture* && "$output" != *45678* ]]
  [[ "$output" != *'Raw sockets: 1'* ]]
  [[ "$output" == *'Raw socket inventory unavailable:'* ]]
}

@test "failed TCP inventory invalidates peer direction without hiding valid UDP or raw evidence" {
  SS_FAILURE='-H -tlnp'
  run check_ports
  [[ "$status" -eq 0 ]]
  [[ "$output" != *'PASS:No TCP listeners'* ]]
  [[ "$output" != *'PASS:No likely outbound connections'* ]]
  [[ "$output" == *'Outbound peer-port inventory unavailable:'* ]]
  [[ "$output" == *'PASS:No UDP listeners'* ]]
  [[ "$output" == *'PASS:No raw sockets'* ]]
}

@test "failed established-connection query is independent of successful listener queries" {
  SS_FAILURE='-H -tn state established'
  run check_ports
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'PASS:No TCP listeners'* ]]
  [[ "$output" == *'PASS:No UDP listeners'* ]]
  [[ "$output" != *'PASS:No likely outbound connections'* ]]
  [[ "$output" == *'Outbound peer-port inventory unavailable:'* ]]
}

@test "successful populated queries preserve first socket rows and peer evidence" {
  SS_POPULATED=true
  run check_ports
  [[ "$status" -eq 0 ]]
  [[ "$output" == *'PASS:TCP 127.0.0.1:8443 (fixture)'* ]]
  [[ "$output" == *'PASS:UDP 127.0.0.1:5353 (fixture)'* ]]
  [[ "$output" == *'INFO:Likely outbound connections to non-standard peer ports: 45678'* ]]
  [[ "$output" == *'INFO:Raw sockets: 1 '* ]]
  [[ "$output" != *unavailable* && "$output" != *'PASS:No '* ]]
}
