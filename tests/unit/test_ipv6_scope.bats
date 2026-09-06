#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '
    /^(_ipv6_proc_scope|_ipv6_tempaddr_verdict)\(\) \{/ { in_function=1 }
    in_function { print }
    in_function && /^}/ { in_function=0 }
  ' "$SCRIPT")
}

@test "IPv6 proc classifier accepts only 2000::/3 as global unicast" {
  [[ "$(_ipv6_proc_scope 20010db8000000000000000000000001)" == "global" ]]
  [[ "$(_ipv6_proc_scope 3fff0000000000000000000000000001)" == "global" ]]
  [[ "$(_ipv6_proc_scope 40000000000000000000000000000001)" == "other" ]]
}

@test "IPv6 proc classifier separates non-global address classes" {
  [[ "$(_ipv6_proc_scope fe800000000000000000000000000001)" == "link-local" ]]
  [[ "$(_ipv6_proc_scope febf0000000000000000000000000001)" == "link-local" ]]
  [[ "$(_ipv6_proc_scope fec00000000000000000000000000001)" == "site-local" ]]
  [[ "$(_ipv6_proc_scope feff0000000000000000000000000001)" == "site-local" ]]
  [[ "$(_ipv6_proc_scope fc000000000000000000000000000001)" == "ula" ]]
  [[ "$(_ipv6_proc_scope fdff0000000000000000000000000001)" == "ula" ]]
  [[ "$(_ipv6_proc_scope ff020000000000000000000000000001)" == "multicast" ]]
  [[ "$(_ipv6_proc_scope 00000000000000000000000000000000)" == "unspecified" ]]
  [[ "$(_ipv6_proc_scope 00000000000000000000000000000001)" == "loopback" ]]
}

@test "IPv6 proc classifier rejects malformed input" {
  run _ipv6_proc_scope fe80::1
  [[ "$status" -ne 0 ]]
  [[ "$output" == "invalid" ]]
}

@test "runtime IPv6 inventory uses the shared prefix classifier" {
  ipv6_block=$(sed -n '/# IPv6: classify every raw/,/# LAN Isolation/p' "$SCRIPT")
  # shellcheck disable=SC2016  # literal production-source variable
  [[ "$ipv6_block" == *'_ipv6_proc_scope "$_v6addr"'* ]]
  [[ "$ipv6_block" == *'deprecated site-local'* ]]
}

@test "RFC 4941 state is unassessed without an active physical connection" {
  [[ "$(_ipv6_tempaddr_verdict 0 0)" == "unassessed" ]]
  [[ "$(_ipv6_tempaddr_verdict 0 2)" == "unassessed" ]]
}

@test "RFC 4941 state is graded only on an active physical connection" {
  [[ "$(_ipv6_tempaddr_verdict 1 2)" == "pass" ]]
  [[ "$(_ipv6_tempaddr_verdict 1 1)" == "info" ]]
  [[ "$(_ipv6_tempaddr_verdict 1 0)" == "warn" ]]
}
