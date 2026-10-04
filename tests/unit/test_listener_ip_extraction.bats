#!/usr/bin/env bats
#
# Listener IP extraction — scoped IPv6 (link-local / VPN-tunnel) handling.
# Section 08 classifies every ss listener address via _extract_ip →
# _classify_listener. A scoped IPv6 listener (ss emits `[fe80::1%wg0]:3702`,
# and — depending on iproute2 version — `[fe80::1]%wg0:3702`) must yield the
# bare address so the bridge/VPN/loopback classifier can recognize it.
#
# Bug class: parsing order (regex CL13 + impl-vs-intent CL10). The pre-fix
# `_extract_ip` stripped `%scope` (and the port with it) BEFORE the bracket
# match, leaving `[fe80::1]` with no `:port`; the bracket-regex then missed it
# and the `${addr%:*}` fallback truncated the address to `[fe80:`, so a scoped
# link-local / VPN-tunnel listener was mis-classified as internet-facing
# "external" — a false FAIL on hosts without a physical-iface firewall block.
#
# The functions are sourced from the script so the tests exercise the real
# code, not a re-implementation.

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_extract_ip\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_extract_scope_iface\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_classify_listener\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_extract_port\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_listener_is_dhcp_client\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_listener_process_label\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_qemu_cmdline_uses_user_networking\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_qemu_cmdline_has_udp_hostfwd_port\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_qemu_dynamic_usernet_udp_socket\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_tcp_nonstandard_outbound_ports\(\) \{/,/^}/ {print}' "$SCRIPT")
}

# --- _extract_ip: every documented ss address form ---------------------------

@test "extract: plain IPv4 with port" {
  [[ "$(_extract_ip '192.168.122.1:53')" == '192.168.122.1' ]]
}

@test "extract: bracketed IPv6 loopback" {
  [[ "$(_extract_ip '[::1]:53')" == '::1' ]]
}

@test "extract: IPv4 with %iface scope (port trails the scope)" {
  [[ "$(_extract_ip '0.0.0.0%virbr0:67')" == '0.0.0.0' ]]
  [[ "$(_extract_ip '127.0.0.53%lo:53')" == '127.0.0.53' ]]
}

@test "extract: full bracketed IPv6 (no scope) preserves every group" {
  [[ "$(_extract_ip '[fe80::1234:5678:9abc:def0]:3702')" == 'fe80::1234:5678:9abc:def0' ]]
}

@test "extract: scoped IPv6 with scope INSIDE brackets (iproute2 form)" {
  [[ "$(_extract_ip '[fe80::1%wg0]:3702')" == 'fe80::1' ]]
}

@test "extract: scoped IPv6 with scope OUTSIDE brackets" {
  [[ "$(_extract_ip '[fe80::abcd]%wg0:3702')" == 'fe80::abcd' ]]
}

@test "extract: wildcard IPv6 any-address" {
  [[ "$(_extract_ip '[::]:443')" == '::' ]]
}

# --- _classify_listener: scoped IPv6 must not read as external ----------------

@test "classify: scoped IPv6 on a bridge link-local reads as bridge, not external" {
  _VM_BRIDGE_ADDRS='192.168.122.1|fe80::1234:5678:9abc:def0'
  _VPN_TUNNEL_ADDRS='10.2.0.1'
  [[ "$(_classify_listener '[fe80::1234:5678:9abc:def0%virbr0]:3702')" == 'bridge' ]]
}

@test "classify: scoped IPv6 on a VPN tunnel reads as vpn, not external" {
  _VM_BRIDGE_ADDRS='192.168.122.1'
  _VPN_TUNNEL_ADDRS='2001:db8::5'
  [[ "$(_classify_listener '[2001:db8::5%wg0]:443')" == 'vpn' ]]
}

@test "classify: scoped IPv4 loopback stub reads as loopback" {
  _VM_BRIDGE_ADDRS=''
  _VPN_TUNNEL_ADDRS=''
  [[ "$(_classify_listener '127.0.0.53%lo:53')" == 'loopback' ]]
}

@test "classify: wildcard UDP socket scoped to virbr remains intra-host" {
  _VM_BRIDGE_ADDRS='192.168.122.1'
  _VPN_TUNNEL_ADDRS=''
  _VIRT_IFACE_REGEX='^(virbr|vnet|docker|br-|veth|tap)'
  _iface_is_vpn() { return 1; }
  [[ "$(_extract_scope_iface '0.0.0.0%virbr0:67')" == 'virbr0' ]]
  [[ "$(_classify_listener '0.0.0.0%virbr0:67')" == 'bridge' ]]
}

@test "scope parser accepts both bracketed IPv6 forms" {
  [[ "$(_extract_scope_iface '[fe80::1%wg0]:3702')" == 'wg0' ]]
  [[ "$(_extract_scope_iface '[fe80::1]%wg0:3702')" == 'wg0' ]]
}

@test "classify: genuinely external IPv6 (no scope, not bridge/vpn) stays external" {
  _VM_BRIDGE_ADDRS='192.168.122.1'
  _VPN_TUNNEL_ADDRS='10.2.0.1'
  [[ "$(_classify_listener '[2606:4700::1111]:443')" == 'external' ]]
}

# --- anti-regression: bracket handling precedes the scope/port strip ---------

@test "regression: bracket case is matched before stripping scope/port" {
  block=$(awk '/^_extract_ip\(\) \{/,/^}/ {print}' "$SCRIPT")
  # Fixed form tests for a bracketed value (leading '[') first.
  # shellcheck disable=SC2016  # literal source-code pattern
  grep -qF '$addr" == \[*\]*' <<< "$block"
  # The old ':port'-requiring bracket regex must be gone.
  run grep -qF 'addr" =~ ^\[(.+)\]:[0-9]+$' <<< "$block"
  [[ "$status" -ne 0 ]]
}

@test "DHCP client listeners are network configuration traffic not servers" {
  _listener_is_dhcp_client 68 systemd-network
  _listener_is_dhcp_client 546 NetworkManager
  run _listener_is_dhcp_client 67 systemd-network
  [[ "$status" -ne 0 ]]
  run _listener_is_dhcp_client 68 dnsmasq
  [[ "$status" -ne 0 ]]
}

@test "listener label expands the known systemd-resolved comm truncation" {
  [[ "$(_listener_process_label systemd-resolve)" == 'systemd-resolved' ]]
  [[ "$(_listener_process_label NetworkManager)" == 'NetworkManager' ]]
  [[ "$(_listener_process_label arbitrary-name)" == 'arbitrary-name' ]]
}

@test "QEMU user-network parser preserves explicit UDP host forwards" {
  plain='qemu-system-x86_64 -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22'
  forwarded='qemu-system-x86_64 -netdev user,id=net0,hostfwd=udp::5353-:5353'
  libvirt='qemu-system-x86_64 -netdev {"type":"user","id":"hostnet0"}'
  _qemu_cmdline_uses_user_networking "$plain"
  _qemu_cmdline_uses_user_networking "$libvirt"
  run _qemu_cmdline_has_udp_hostfwd_port "$plain" 5353
  [[ "$status" -ne 0 ]]
  _qemu_cmdline_has_udp_hostfwd_port "$forwarded" 5353
}

@test "QEMU dynamic UDP classifier requires ephemeral unforwarded user networking" {
  proc_root="$BATS_TEST_TMPDIR/proc"
  mkdir -p "$proc_root/123" "$proc_root/sys/net/ipv4"
  printf '%s\0' qemu-system-x86_64 -netdev user,id=net0,hostfwd=tcp::2222-:22 > "$proc_root/123/cmdline"
  printf '%s\n' '32768 60999' > "$proc_root/sys/net/ipv4/ip_local_port_range"
  line='UNCONN 0 0 0.0.0.0:50000 0.0.0.0:* users:(("qemu-system-x86",pid=123,fd=7))'
  _qemu_dynamic_usernet_udp_socket "$line" 50000 qemu-system-x86 "$proc_root"
  run _qemu_dynamic_usernet_udp_socket "$line" 1900 qemu-system-x86 "$proc_root"
  [[ "$status" -ne 0 ]]

  printf '%s\0' qemu-system-x86_64 -netdev user,id=net0,hostfwd=udp::50000-:53 > "$proc_root/123/cmdline"
  run _qemu_dynamic_usernet_udp_socket "$line" 50000 qemu-system-x86 "$proc_root"
  [[ "$status" -ne 0 ]]
}

@test "inbound client ephemeral ports are not reported as destinations" {
  listeners=$'22\n631'
  pairs=$'10.0.2.15:22 10.0.2.2:53552\n10.0.2.15:49152 203.0.113.10:443\n10.0.2.15:49153 203.0.113.20:11434'
  [[ "$(_tcp_nonstandard_outbound_ports "$listeners" "$pairs")" == "11434" ]]
}
