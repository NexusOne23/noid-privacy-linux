#!/usr/bin/env bats
#
# Test that all VPN-iface regex usages in the script reference the canonical
# global $_VPN_IFACE_REGEX, not hand-written subsets.
#
# Bug class: inconsistent regex globals (NoID Bug Pattern #5).
# Original bug: 5 places used reduced `^(tun|wg|proton|pvpn)` instead of
# the global covering Tailscale/ZeroTier/Mullvad/Nebula/Nordlynx.

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
}

@test "canonical _VPN_IFACE_REGEX is defined" {
  grep -qE '^_VPN_IFACE_REGEX=' "$SCRIPT"
}

@test "canonical regex covers all major VPN families" {
  line=$(grep -E '^_VPN_IFACE_REGEX=' "$SCRIPT" | head -1)
  [[ "$line" == *"tun"*       ]]
  [[ "$line" == *"tap"*       ]]
  [[ "$line" == *"wg"*        ]]
  [[ "$line" == *"proton"*    ]]
  [[ "$line" == *"pvpn"*      ]]
  [[ "$line" == *"tailscale"* ]]
  [[ "$line" == *"zt"*        ]]
  [[ "$line" == *"nebula"*    ]]
  [[ "$line" == *"mullvad"*   ]]
  [[ "$line" == *"nordlynx"*  ]]
}

@test "no hand-written reduced VPN regex subsets" {
  # The 18-bug audit found 5 places with reduced subsets. After fix they
  # should ALL use $_VPN_IFACE_REGEX. Catches regression where someone
  # adds a new check with a hand-written subset like ^(tun|wg|proton).
  ! grep -nE 'grep[^|]+-qE?[^|]+"\^\(tun\|wg\|proton[^"]*"' "$SCRIPT" \
    | grep -v '_VPN_IFACE_REGEX' \
    | grep -v '^\s*#' || {
    echo "Hand-written VPN regex subset found — should reference _VPN_IFACE_REGEX"
    return 1
  }
}
