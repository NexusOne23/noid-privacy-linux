#!/usr/bin/env bats

# Bats invokes the extracted production block and per-test mocks indirectly.
# Test assignments intentionally belong to each isolated test case.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031

setup() {
  SCRIPT="${NOID_AUDIT_TEST_SOURCE:-${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh}"
  # shellcheck disable=SC1090
  source <(
    printf '_forwarding_probe() {\n'
    awk '/^# (ip_forward |IPv4 forwarding needs)/ {found=1}
         found {print} found && /^fi$/ {exit}' "$SCRIPT"
    printf '}\n'
  )
  FORWARD_VALUE=0
  FORWARD_RC=0
  VM_SERVICE_RC=3
  LINK_OUTPUT=''
  LINK_RC=0
  VPN_IFACES=''
  _VIRT_IFACE_REGEX='^(docker|virbr|veth)'
}

sysctl() {
  [[ "$*" == '-n net.ipv4.ip_forward' ]] || return 127
  printf '%s\n' "$FORWARD_VALUE"
  return "$FORWARD_RC"
}
systemctl() { return "$VM_SERVICE_RC"; }
ip() { printf '%s\n' "$LINK_OUTPUT"; return "$LINK_RC"; }
_emit_pass() { printf 'PASS:%s\n' "$1"; }
_emit_info() { printf 'INFO:%s\n' "$1"; }
_emit_warn() { printf 'WARN:%s\n' "$1"; }

@test "IPv4 forwarding disabled passes only on a successful exact zero" {
  run _forwarding_probe
  [[ "$status" -eq 0 && "$output" == 'PASS:ip_forward=0' ]]
}

@test "VPN presence cannot certify that IPv4 forwarding is required or safe" {
  FORWARD_VALUE=1 VPN_IFACES=wg0
  run _forwarding_probe
  [[ "$status" -eq 0 && "$output" == INFO:* ]]
  [[ "$output" == *'VPN presence alone does not establish a need for forwarding'* ]]
  [[ "$output" != *PASS:* && "$output" != *WARN:* ]]
}

@test "VM forwarding context is reported even alongside a VPN" {
  FORWARD_VALUE=1 VPN_IFACES=wg0 VM_SERVICE_RC=0
  run _forwarding_probe
  [[ "$status" -eq 0 && "$output" == 'INFO:ip_forward=1 (container/VM networking detected;'* ]]
  [[ "$output" != *PASS:* ]]
}

@test "virtual link inventory provides context without certifying forwarding policy" {
  FORWARD_VALUE=1 LINK_OUTPUT='virbr0 UP'
  run _forwarding_probe
  [[ "$status" -eq 0 && "$output" == 'INFO:ip_forward=1 (container/VM networking detected;'* ]]
}

@test "unexplained enabled forwarding retains an actionable warning" {
  FORWARD_VALUE=1
  run _forwarding_probe
  [[ "$status" -eq 0 && "$output" == WARN:ip_forward=1* ]]
}

@test "failed and partial forwarding queries cannot report disabled or enabled posture" {
  for FORWARD_RC in 1 2 124 127; do
    for FORWARD_VALUE in '' 0 1; do
      run _forwarding_probe
      [[ "$status" -eq 0 && "$output" == 'INFO:IPv4 forwarding: state query failed (unassessed)' ]]
    done
  done
}

@test "unexpected forwarding values remain unassessed without arithmetic coercion" {
  for FORWARD_VALUE in '' word 2 -1 00 01 0+1 $'0\n1'; do
    run _forwarding_probe
    [[ "$status" -eq 0 && "$output" == 'INFO:IPv4 forwarding: unexpected state value (unassessed)' ]]
  done
}

@test "failed partial link inventory cannot establish VM routing context" {
  FORWARD_VALUE=1 VPN_IFACES=wg0 LINK_OUTPUT='virbr0 UP' LINK_RC=1
  run _forwarding_probe
  [[ "$status" -eq 0 && "$output" == INFO:* ]]
  [[ "$output" == *'VPN presence alone'* && "$output" != *'container/VM networking detected'* ]]
}
