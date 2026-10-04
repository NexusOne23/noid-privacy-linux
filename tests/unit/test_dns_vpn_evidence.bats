#!/usr/bin/env bats

# Bats invokes the command mocks indirectly from the extracted function.
# shellcheck disable=SC2317
# shellcheck disable=SC2034

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # shellcheck disable=SC1090
  source <(awk '
    /^(_is_ip_address|_iface_admin_state|_dns_address_via_vpn)\(\) \{/ { in_function=1 }
    in_function { print }
    in_function && /^}/ { in_function=0 }
  ' "$SCRIPT")
  RESOLVED_RC=0
  RESOLVED_FIXTURE=''
  ROUTE_IFACE=''
  LINK_UP=true
  require_cmd() { [[ "$1" == resolvectl ]]; }
  resolvectl() {
    printf '%s\n' "$RESOLVED_FIXTURE"
    return "$RESOLVED_RC"
  }
  ip() {
    case "$*" in
      'route get '*)
        [[ -n "$ROUTE_IFACE" ]] || return 1
        printf 'fixture-route dev %s\n' "$ROUTE_IFACE"
        ;;
      '-o link show up dev wg-fixture')
        if "$LINK_UP"; then printf '%s\n' '7: wg-fixture: <UP,LOWER_UP> mtu 1420 state UNKNOWN'; fi ;;
      *) return 1 ;;
    esac
  }
  _iface_is_vpn() { [[ "$1" == wg-fixture ]]; }
}

@test "DNS ownership matches exact addresses and optional DoT names" {
  RESOLVED_FIXTURE=$'Global\n  DNS Servers: 1.1.1.1\nLink 8 (wg-fixture)\n  DNS Servers: 9.9.9.9#dns.example 2001:db8::1'
  _dns_address_via_vpn 9.9.9.9
  _dns_address_via_vpn '9.9.9.9#dns.example'
  _dns_address_via_vpn 2001:db8::1
  run _dns_address_via_vpn 1.1.1.1
  [[ "$status" -eq 1 ]]
}

@test "DNS ownership rejects suffix matches and non-address fields" {
  RESOLVED_FIXTURE=$'Link 8 (wg-fixture)\n  DNS Servers: 19.9.9.9 2001:db8::11\n  DNS Domain: 9.9.9.9'
  run _dns_address_via_vpn 9.9.9.9
  [[ "$status" -eq 1 ]]
  run _dns_address_via_vpn 2001:db8::1
  [[ "$status" -eq 1 ]]
}

@test "failed resolver status cannot supply positive VPN evidence" {
  RESOLVED_FIXTURE=$'Link 8 (wg-fixture)\n  Current DNS Server: 9.9.9.9'
  _dns_address_via_vpn 9.9.9.9
  RESOLVED_RC=1
  run _dns_address_via_vpn 9.9.9.9
  [[ "$status" -eq 1 ]]
}

@test "DNS ownership still requires a confirmed active VPN interface" {
  RESOLVED_FIXTURE=$'Link 8 (eth-fixture)\n  Current DNS Server: 9.9.9.9'
  run _dns_address_via_vpn 9.9.9.9
  [[ "$status" -eq 1 ]]
  RESOLVED_FIXTURE=$'Link 8 (wg-fixture)\n  Current DNS Server: 9.9.9.9'
  LINK_UP=false
  run _dns_address_via_vpn 9.9.9.9
  [[ "$status" -eq 1 ]]
  LINK_UP=true
  _dns_address_via_vpn 9.9.9.9
}

@test "a confirmed active route works without resolver fallback" {
  ROUTE_IFACE=wg-fixture
  RESOLVED_RC=1
  _dns_address_via_vpn 9.9.9.9
  LINK_UP=false
  run _dns_address_via_vpn 9.9.9.9
  [[ "$status" -eq 1 ]]
}
