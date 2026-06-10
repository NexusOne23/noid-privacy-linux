#!/usr/bin/env bats
#
# F-387 (v3.7.0) — firewall zone-severity interface classification.
# A firewalld zone (e.g. 'trusted') whose interfaces are ALL non-internet-facing
# — VPN tunnels ($_VPN_IFACE_REGEX) OR VM/container virtual interfaces
# ($_VIRT_IFACE_REGEX: libvirt virbr/vnet, docker/br-/veth, podman/cni, lxc/lxd)
# — is not directly exposed, so an ACCEPT target there is INFO, not WARN.
# Regression guard: a libvirt VM host puts a guest TAP (vnet0) in the 'trusted'
# zone alongside the VPN iface; before F-387 the VPN-only check WARNed on it.
#
# Counter-increment style note: var=$((var+1)), never ((var++)) — bash
# post-increment returns rc=1 when the var was 0 (bombs under set -e / BATS).

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  VIRT_RE=$(grep -E "^_VIRT_IFACE_REGEX=" "$SCRIPT" | head -1 | sed -E "s/^_VIRT_IFACE_REGEX='([^']*)'.*/\1/")
  VPN_RE=$(grep -E "^_VPN_IFACE_REGEX=" "$SCRIPT" | head -1 | sed -E "s/^_VPN_IFACE_REGEX='([^']*)'.*/\1/")
}

@test "F-387: canonical _VIRT_IFACE_REGEX is defined" {
  [[ -n "$VIRT_RE" ]]
}

@test "F-387: _VIRT_IFACE_REGEX matches VM/container interface families" {
  for ifc in virbr0 virbr0-nic vnet0 vnet12 docker0 br-1a2b3c veth9f0e podman0 cni-podman0 lxcbr0 lxdbr0; do
    if ! [[ "$ifc" =~ $VIRT_RE ]]; then echo "should MATCH: $ifc"; return 1; fi
  done
}

@test "F-387: _VIRT_IFACE_REGEX does NOT match physical/VPN/generic-bridge interfaces" {
  # eth/enp/eno/wlan = physical; proton0 = VPN (other regex); br0 = manual bridge
  # (may be LAN-bridged → deliberately treated as exposed; only 'br-' matches)
  for ifc in eth0 enp3s0 eno1 wlan0 wlp2s0 lo br0 proton0; do
    if [[ "$ifc" =~ $VIRT_RE ]]; then echo "should NOT match: $ifc"; return 1; fi
  done
}

@test "F-387: combined non-internet-facing classifier (VPN OR virt) as the zone check uses it" {
  # proton0 = VPN-safe, vnet0 = virt-safe → both non-internet-facing
  [[ "proton0" =~ $VPN_RE || "proton0" =~ $VIRT_RE ]]
  [[ "vnet0"   =~ $VPN_RE || "vnet0"   =~ $VIRT_RE ]]
  # eth0 matches neither → internet-facing (exposed)
  if [[ "eth0" =~ $VPN_RE || "eth0" =~ $VIRT_RE ]]; then echo "eth0 wrongly classified safe"; return 1; fi
}

@test "F-387: firewall zone loop uses the combined VPN|VIRT classifier (no VPN-only regression)" {
  grep -qF '$_VPN_IFACE_REGEX|$_VIRT_IFACE_REGEX' "$SCRIPT"
}
