#!/usr/bin/env bats

# Extracted production code and Bats consume the fixture state.
# Each Bats test intentionally gets an isolated copy of setup state.
# shellcheck disable=SC2317,SC2034,SC2030,SC2031
setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  # shellcheck disable=SC1090
  source <(awk '/^(_ks_link_evidence|_ks_dummy_guard_routes|_ks_dummy_guard_evidence|_run_timed_capture)\(\) \{/ {printing=1}
                printing {print} printing && /^}/ {printing=0}' "$SCRIPT")
  LINKS=$'1: lo: <LOOPBACK,UP,LOWER_UP> qdisc noqueue\n2: physical0: <UP,LOWER_UP> qdisc noqueue\n3: guard0: <UP,LOWER_UP> qdisc noqueue \\\n    dummy\n4: personal: <UP,LOWER_UP> qdisc noqueue \\\n    wireguard'
  LINKS="${LINKS//$'\\\n'/$'\\    '}"
  LINK_FIELDS=$(printf '%s\n' "$LINKS" | _ks_link_evidence)
  RULES4=$'0: from all lookup local\n32764: from all lookup main suppress_prefixlength 0\n32765: not from all fwmark 0xca6c lookup 51820\n32766: from all lookup main\n32767: from all lookup default'
  RULES6=$'0: from all lookup local\n32766: from all lookup main'
  ROUTES4=$'default dev personal table 51820 metric 50\ndefault dev guard0 metric 98\ndefault via 192.0.2.1 dev physical0 metric 600\n192.0.2.0/24 dev physical0 proto kernel scope link'
  ROUTES6=$'default dev guard0 metric 95 pref medium\ndefault via 2001:db8:1::1 dev physical0 metric 600 pref medium\n2001:db8:1::/64 dev physical0 proto kernel metric 256 pref medium'
  _NFT_KS_RULESET='' _NFT_KS_RC=0
  COMMAND_RC=0 TC_RC=0 FILTERS='' QDISC='qdisc noqueue 0: root refcnt 2'
  HAVE_TC=true
}
require_cmd() { [[ "$1" != tc ]] || "$HAVE_TC"; }
timeout() { shift; "$@"; }
ip() {
  case "$*" in
    '-d -o link show') printf '%s\n' "$LINKS" ;;
    '-4 rule show') printf '%s\n' "$RULES4" ;;
    '-6 rule show') printf '%s\n' "$RULES6" ;;
    '-o -4 route show table all') printf '%s\n' "$ROUTES4" ;;
    '-o -6 route show table all') printf '%s\n' "$ROUTES6" ;;
    *) return 127 ;;
  esac
  return "$COMMAND_RC"
}
tc() {
  case "$1" in
    filter) printf '%s' "$FILTERS" ;;
    qdisc) printf '%s\n' "$QDISC" ;;
    *) return 127 ;;
  esac
  return "$TC_RC"
}
family4() { _ks_dummy_guard_routes -4 "$LINK_FIELDS" "$RULES4" "$ROUTES4"; }

@test "dual-stack dummy fallback is verified with an arbitrarily named WireGuard link" {
  run _ks_dummy_guard_evidence
  [[ "$status" -eq 0 && "$output" == '0 2' ]]
}

@test "removing the tunnel leaves the independent guard verifiable" {
  ROUTES4=$(printf '%s\n' "$ROUTES4" | sed '/dev personal/d')
  LINKS=$(printf '%s\n' "$LINKS" | sed '/personal:/d')
  run _ks_dummy_guard_evidence
  [[ "$status" -eq 0 && "$output" == '0 2' ]]
}

@test "a guard losing or tying a physical default never passes" {
  for metric in 600 900; do
    ROUTES4="${ROUTES4/metric 98/metric $metric}"
    run family4
    [[ "$status" -ne 0 && -z "$output" ]]
    ROUTES4="${ROUTES4/metric $metric/metric 98}"
  done
}

@test "IPv6 requires its own winning guard" {
  ROUTES6=$(printf '%s\n' "$ROUTES6" | sed '/dev guard0/d')
  run _ks_dummy_guard_evidence
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "multiple candidate dummy defaults cannot hide an unchecked forwarding attachment" {
  LINK_FIELDS+=$'\n5: otherguard: <UP,LOWER_UP> qdisc noqueue dummy'
  ROUTES4+=$'\ndefault dev otherguard metric 98'
  run family4
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "a dummy name or default route on another link type is insufficient" {
  LINK_FIELDS="${LINK_FIELDS/ dummy/}"
  run family4
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "DOWN or enslaved dummy links cannot establish fallback protection" {
  for record in '3: guard0: <LOWER_UP> qdisc noqueue dummy' \
                '3: guard0: <UP,LOWER_UP> qdisc noqueue master br0 dummy' \
                '3: guard0: <UP,LOWER_UP> qdisc noqueue dummy xdp'; do
    LINK_FIELDS=$(printf '%s\n' "$LINK_FIELDS" | sed '/guard0:/d')$'\n'"$record"
    run family4
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "an unsupported RPDB selector cannot hide a bypass before the guard" {
  RULES4=$'0: from all lookup local\n100: from all uidrange 1000-1000 lookup 200\n32766: from all lookup main'
  run family4
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "a referenced alternate table with physical egress prevents verification" {
  RULES4=$'0: from all lookup local\n100: from all lookup 200\n32766: from all lookup main'
  ROUTES4+=$'\ndefault dev physical0 table 200 metric 1'
  run family4
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "broad more-specific non-tunnel routes prevent verification" {
  ROUTES4+=$'\n128.0.0.0/1 via 192.0.2.1 dev physical0'
  run family4
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "host-route exceptions are counted separately from connected networks" {
  ROUTES4+=$'\n198.51.100.20 via 192.0.2.1 dev physical0'
  ROUTES6+=$'\n2001:db8:2::20/128 via 2001:db8:1::1 dev physical0'
  run _ks_dummy_guard_evidence
  [[ "$status" -eq 0 && "$output" == '2 2' ]]
}

@test "multipath routes and unknown route fields remain unsupported" {
  ROUTES4+=$'\ndefault metric 1 nexthop via 192.0.2.1 dev physical0 weight 1'
  run family4
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "complete-looking partial command output never passes" {
  for COMMAND_RC in 1 2 124 127; do
    run _ks_dummy_guard_evidence
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "TC actions and shared blocks require separate verification" {
  FILTERS='filter protocol all pref 1 matchall action mirred egress redirect'
  run _ks_dummy_guard_evidence
  [[ "$status" -ne 0 && -z "$output" ]]
  FILTERS='' QDISC=$'qdisc noqueue 0: root\nqdisc clsact ffff: parent ffff:fff1 ingress_block 10'
  run _ks_dummy_guard_evidence
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "missing or failed TC evidence cannot establish a dummy sink" {
  for TC_RC in 1 124 127; do
    run _ks_dummy_guard_evidence
    [[ "$status" -ne 0 && -z "$output" ]]
  done
  TC_RC=0 HAVE_TC=false
  run _ks_dummy_guard_evidence
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "nft forwarding duplication and userspace queues remain unassessed" {
  for _NFT_KS_RULESET in 'fwd to physical0' 'dup to physical0' 'queue num 1'; do
    run _ks_dummy_guard_evidence
    [[ "$status" -ne 0 && -z "$output" ]]
  done
}

@test "ordinary netdev accept and drop rules do not bypass the dummy sink" {
  _NFT_KS_RULESET=$'table netdev fixture {\n chain out {\n type filter hook egress device guard0 priority 0; policy accept;\n drop\n }\n}'
  run _ks_dummy_guard_evidence
  [[ "$status" -eq 0 && "$output" == '0 2' ]]
}

@test "failed nft observation prevents verification" {
  _NFT_KS_RC=2
  run _ks_dummy_guard_evidence
  [[ "$status" -ne 0 && -z "$output" ]]
}

@test "bridge ageing timers do not change normalized link evidence" {
  before=$(printf '%s\n' '8: bridge0: <UP> qdisc noqueue \    bridge hello_timer 1.8 gc_timer 2.0' | _ks_link_evidence)
  after=$(printf '%s\n' '8: bridge0: <UP> qdisc noqueue \    bridge hello_timer 1.7 gc_timer 1.9' | _ks_link_evidence)
  [[ "$before" == "$after" ]]
}

@test "link changes between snapshots prevent a verified result" {
  marker="$BATS_TEST_TMPDIR/link-read"
  ip() {
    case "$*" in
      '-d -o link show')
        if [[ -e "$marker" ]]; then
          printf '%s\n' "${LINKS/guard0: <UP,LOWER_UP>/guard0: <LOWER_UP>}"
        else
          : > "$marker"
          printf '%s\n' "$LINKS"
        fi ;;
      '-4 rule show') printf '%s\n' "$RULES4" ;;
      '-6 rule show') printf '%s\n' "$RULES6" ;;
      '-o -4 route show table all') printf '%s\n' "$ROUTES4" ;;
      '-o -6 route show table all') printf '%s\n' "$ROUTES6" ;;
      *) return 127 ;;
    esac
  }
  run _ks_dummy_guard_evidence
  [[ "$status" -ne 0 && -z "$output" ]]
}
