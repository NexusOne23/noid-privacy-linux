#!/usr/bin/env bats

# Bats invokes the extracted functions and fixture globals indirectly.
# Each test intentionally mutates its own isolated setup state.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # shellcheck disable=SC1090
  source <(awk '/^(_iface_link_kind|_iface_vpn_kind|_iface_is_dummy|_iface_is_vpn)\(\) \{/ {printing=1}
                printing {print} printing && /^}/ {printing=0}' "$SCRIPT")
  _VPN_IFACE_REGEX='^(tun|tap|wg|proton|pvpn|tailscale|zt|nebula|mullvad|nordlynx)'
  _NM_ACTIVE_VPN_DEVICES=''
  LINK_RC=0
  DETAIL='7: fixture: <UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN \    link/none \    wireguard'
}
ip() {
  case "$*" in
    '-d -o link show dev '*) printf '%s\n' "$DETAIL"; return "$LINK_RC" ;;
    'route show table all default') printf '%s\n' 'default dev proton-fake'; return 0 ;;
    *) return 127 ;;
  esac
}

@test "native WireGuard link type is independent of interface naming" {
  [[ "$(_iface_vpn_kind fixture)" == confirmed ]]
  _iface_is_vpn fixture
}

@test "dummy defaults remain routing helpers rather than VPN tunnels" {
  DETAIL='7: proton-fake: <UP> mtu 1500 qdisc noqueue \    link/ether \    dummy'
  [[ "$(_iface_vpn_kind proton-fake)" == dummy ]]
  _iface_is_dummy proton-fake
  run _iface_is_vpn proton-fake
  [[ "$status" -eq 1 ]]
}

@test "ethernet plus a VPN-like name and default cannot earn VPN confirmation" {
  DETAIL='7: proton-fake: <UP> mtu 1500 qdisc noqueue \    link/ether'
  [[ "$(_iface_vpn_kind proton-fake)" == ambiguous ]]
}

@test "bridge-attached TAP evidence comes from the same network namespace" {
  DETAIL='7: tap-fixture: <UP> mtu 1500 qdisc noqueue master bridge0 \    link/ether \    tun type tap pi off'
  [[ "$(_iface_vpn_kind tap-fixture)" == virtual ]]
}

@test "custom TUN needs a VPN manager binding to establish its purpose" {
  DETAIL='7: custom: <UP> mtu 1500 qdisc noqueue \    link/none \    tun type tun pi off'
  [[ "$(_iface_vpn_kind custom)" == ambiguous ]]
  _NM_ACTIVE_VPN_DEVICES=custom
  [[ "$(_iface_vpn_kind custom)" == confirmed ]]
}

@test "ordinary named TUN remains recognized with actual TUN type evidence" {
  DETAIL='7: tun0: <UP> mtu 1500 qdisc noqueue \    link/none \    tun type tun pi off'
  [[ "$(_iface_vpn_kind tun0)" == confirmed ]]
}

@test "failed partial or mismatched link reads cannot establish device type" {
  for LINK_RC in 1 2 124 127; do
    [[ "$(_iface_link_kind fixture)" == unknown ]]
  done
  LINK_RC=0
  [[ "$(_iface_link_kind another)" == unknown ]]
  DETAIL+=$'\n'"$DETAIL"
  [[ "$(_iface_link_kind fixture)" == unknown ]]
}

@test "missing link records cannot be replaced by a default-route heuristic" {
  DETAIL=''
  [[ "$(_iface_link_kind proton-fake)" == unknown ]]
  [[ "$(_iface_vpn_kind proton-fake)" == ambiguous ]]
}
