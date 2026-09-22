#!/usr/bin/env bats

# Bats and the extracted production functions consume fixture globals.
# shellcheck disable=SC2317,SC2034
setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # shellcheck disable=SC1090
  source <(awk '
    /^(_ks_link_evidence|_ks_dummy_guard_routes|_ks_dummy_guard_evidence|_plural|_run_timed_capture|_nft_direct_output_drop_rules|_nft_table_has_direct_output_drop|_nft_table_name_is_vpn|has_nft_drop_on_phys|get_killswitch_tables|check_nftables)\(\) \{/ {printing=1}
    printing {print}
    printing && /^}/ {printing=0}
  ' "$SCRIPT")
  VPN_IFACES=wg-fixture
  PRIMARY_IFACE=eth-fixture
  HAVE_IP=true
  RULESET=''
  NFT_RC=0
  RULES4=$'0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default'
  RULES6="$RULES4"
  IP4_RC=0
  IP6_RC=0
  OUTPUT_HEAD=$'table inet vpnfixture {\n chain output {\n  type filter hook output priority filter; policy accept;'
  OUTPUT_TAIL=$'\n }\n}'
}
require_cmd() { [[ "$1" != ip ]] || "$HAVE_IP"; }
should_skip() { return 1; }
header() { :; }
systemctl() { return 1; }
# Keep the real capture helper but supply deterministic command completion.
# Native namespace checks exercise the actual timeout/nft/ip executables.
timeout() { shift; "$@"; }
nft() {
  case "$*" in
    'list ruleset'|'list table inet vpnfixture') printf '%s\n' "$RULESET"; return "$NFT_RC" ;;
    'list tables') [[ -z "$RULESET" ]] || printf '%s\n' 'table inet vpnfixture'; return "$NFT_RC" ;;
    *) return 2 ;;
  esac
}
ip() {
  case "$*" in
    '-4 rule show'|'rule show') printf '%s\n' "$RULES4"; return "$IP4_RC" ;;
    '-6 rule show') printf '%s\n' "$RULES6"; return "$IP6_RC" ;;
    *) return 2 ;;
  esac
}
_emit_pass() { printf 'PASS %s\n' "$*"; }
_emit_info() { printf 'INFO %s\n' "$*"; }
_emit_warn() { printf 'WARN %s\n' "$*"; }
_emit_fail() { printf 'FAIL %s\n' "$*"; }
_score_mark_incomplete() { printf 'INCOMPLETE\n'; }
_vpn_has_full_tunnel_route() { return 0; }

@test "ordinary WireGuard routing selectors cannot prove a kill-switch" {
  RULES4=$'32764: from all lookup main suppress_prefixlength 0\n32765: not from all fwmark 0xca6c lookup 51820\n32766: from all lookup main'
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'fallback paths not verified'* ]]
  [[ "$output" == *'protection not verified'* && "$output" == *INCOMPLETE* ]]
  [[ "$output" != *'PASS '* ]]
}

@test "a narrow output drop is inventory without a kill-switch PASS" {
  RULESET="$OUTPUT_HEAD"$'\n  oifname "eth-fixture" tcp dport 19082 drop'"$OUTPUT_TAIL"
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'1 direct output-drop rule candidate for'* ]]
  [[ "$output" == *'protection not verified'* && "$output" == *INCOMPLETE* ]]
  [[ "$output" != *'PASS '* ]]
}

@test "an earlier ACCEPT cannot be hidden by later DROP text" {
  RULESET="$OUTPUT_HEAD"$'\n  oifname "eth-fixture" accept\n  oifname "eth-fixture" drop'"$OUTPUT_TAIL"
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'protection not verified'* ]]
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
}

@test "a broad single-interface drop cannot attest all egress paths" {
  RULESET="$OUTPUT_HEAD"$'\n  oifname "eth-fixture" drop'"$OUTPUT_TAIL"
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'1 direct output-drop rule candidate for'* ]]
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
}

@test "failed nftables reads discard complete-looking partial rules" {
  RULESET="$OUTPUT_HEAD"$'\n  oifname "eth-fixture" drop'"$OUTPUT_TAIL"
  for NFT_RC in 1 2 124 127; do
    run check_nftables
    [[ "$status" -eq 0 && "$output" == *"ruleset query rc=$NFT_RC; partial output discarded"* ]]
    [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
    [[ "$output" != *'direct output-drop rule candidate'* ]]
  done
}

@test "failed routing reads cannot establish candidate evidence" {
  RULES4='32765: not from all fwmark 0xca6c lookup 51820'
  for IP4_RC in 1 2 124 127; do
    run check_nftables
    [[ "$status" -eq 0 && "$output" == *"-4 query rc=$IP4_RC; partial output discarded"* ]]
    [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
    [[ "$output" != *'selectors or blocking actions present (-4'* ]]
  done
}

@test "IPv6 routing evidence is reported independently" {
  RULES6='100: from 2001:db8::/32 prohibit'
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'selectors or blocking actions present (-6'* ]]
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
}

@test "absent recognized patterns do not prove that a kill-switch is missing" {
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'other rule structures may apply'* ]]
  [[ "$output" == *'protection not verified'* && "$output" == *INCOMPLETE* ]]
  [[ "$output" != *'WARN '* && "$output" != *'FAIL '* ]]
}

@test "no VPN keeps kill-switch applicability optional" {
  VPN_IFACES=''
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'no active VPN confirmed; optional policy'* ]]
  [[ "$output" != *INCOMPLETE* && "$output" != *'PASS '* ]]
}

@test "generic drops with no VPN do not create a VPN requirement" {
  VPN_IFACES=''
  RULESET="$OUTPUT_HEAD"$'\n  oifname "eth-fixture" ip daddr 192.0.2.0/24 drop'"$OUTPUT_TAIL"
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'direct output-drop rule candidate'* ]]
  [[ "$output" == *'optional policy'* && "$output" != *INCOMPLETE* ]]
}

@test "missing ip leaves routing evidence explicitly unavailable" {
  HAVE_IP=false
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'ip command missing'* ]]
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
}

@test "duplicate candidate rules do not earn a posture PASS" {
  RULESET="$OUTPUT_HEAD"$'\n  oifname "eth-fixture" drop\n  oifname "eth-fixture" drop'"$OUTPUT_TAIL"
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'2 direct output-drop rule candidate'* ]]
  [[ "$output" == *INCOMPLETE* && "$output" != *'PASS '* ]]
}

@test "active firewalld does not imply persistent boot enablement" {
  VPN_IFACES=''
  systemctl() {
    [[ "$*" == 'is-active firewalld' ]]
  }
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'PASS nftables: active via firewalld backend'* ]]
  [[ "$output" != *'PASS nftables: boot-persistent'* ]]
}

@test "persistent firewalld enablement is distinct from runtime and static states" {
  VPN_IFACES=''
  systemctl() {
    case "$*" in
      'is-active firewalld') return 0 ;;
      'is-enabled firewalld') printf '%s\n' "$ENABLE_STATE" ;;
      *) return 1 ;;
    esac
  }
  ENABLE_STATE=enabled
  run check_nftables
  [[ "$status" -eq 0 && "$output" == *'PASS nftables: boot-persistent via firewalld'* ]]
  for ENABLE_STATE in enabled-runtime static disabled; do
    run check_nftables
    [[ "$status" -eq 0 && "$output" != *'PASS nftables: boot-persistent'* ]]
  done
}
