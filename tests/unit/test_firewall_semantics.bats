#!/usr/bin/env bats

# Bats invokes setup/test bodies and their command mocks indirectly.
# shellcheck disable=SC2317

# shellcheck source=../test_helper.bash
# shellcheck disable=SC1091  # Bats sets BATS_TEST_DIRNAME at runtime.
source "${BATS_TEST_DIRNAME}/../test_helper.bash"

setup() {
  _noid_ensure_test_tmpdir
  SCRIPT="${BATS_TEST_DIRNAME}/../../noid-privacy-linux.sh"
  [[ -f "$SCRIPT" ]] || skip "main script not found"
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_target_is_default_deny\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_normalize_target\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_risky_services\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_word_list_contains\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_word_list_difference\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_view_field\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_named_view_names\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_named_view\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_runtime_zone_target\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_runtime_policy_target\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_effective_ifaces\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewall_port_specs_match\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_service_allows_port\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_firewalld_zone_port_state\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_ufw_status_is_active\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_ufw_is_active\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_iptables_listener_ingress_state_from_rules\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_nft_direct_output_drop_rules\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_nft_table_has_direct_output_drop\(\) \{/,/^}/ {print}' "$SCRIPT")
  # shellcheck disable=SC1090
  source <(awk '/^_nft_table_name_is_vpn\(\) \{/,/^}/ {print}' "$SCRIPT")
  _FIREWALLD_LISTENER_CACHE_READY=false
  _FIREWALLD_AUDIT_POLICY_CACHE_READY=false
  _FW_AUDIT_POLICY_VIEWS=""
}

@test "interface list comparison is exact rather than word-prefix based" {
  run _firewalld_word_list_contains 'eth0.2 veth0' 'eth0'
  [[ "$status" -ne 0 ]]
  _firewalld_word_list_contains 'eth0.2 eth0 veth0' 'eth0'
}

@test "word-list difference reports only permanent additions" {
  run _firewalld_word_list_difference 'ssh cockpit 8443/tcp' 'ssh'
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'cockpit\n8443/tcp' ]]
}

@test "firewalld view fields preserve IPv6 colons" {
  view=$'public\n  sources: 2001:db8::/64 192.0.2.0/24\n  services: ssh'
  [[ "$(_firewalld_view_field sources <<< "$view")" == \
    '2001:db8::/64 192.0.2.0/24' ]]
}

@test "batched firewalld views preserve exact names fields and active annotations" {
  views=$'public (active)\n  target: default\n  interfaces: eth0\n  sources: 2001:db8::/64\n  services: ssh\n\nwork\n  target: DROP\n  interfaces:\n  sources:\n  services:'
  [[ "$(_firewalld_named_view_names <<< "$views")" == $'public\nwork' ]]
  public_view=$(_firewalld_named_view public <<< "$views")
  [[ "$(_firewalld_view_field target <<< "$public_view")" == "default" ]]
  [[ "$(_firewalld_view_field sources <<< "$public_view")" == "2001:db8::/64" ]]
  work_view=$(_firewalld_named_view work <<< "$views")
  [[ "$(_firewalld_view_field target <<< "$work_view")" == "DROP" ]]
  [[ "$work_view" != *'eth0'* ]]
}

@test "firewall zone audit queries both runtime and permanent planes" {
  grep -q 'Runtime is the effective kernel policy' "$SCRIPT"
  grep -q -- 'firewall-cmd --list-all-zones' "$SCRIPT"
  grep -q -- 'firewall-cmd --permanent --list-all-zones' "$SCRIPT"
  # shellcheck disable=SC2016  # literal production source patterns
  grep -q '_SERVICES_RUN=$(_firewalld_view_field services <<< "$_ZONE_VIEW_RUN")' "$SCRIPT"
  # shellcheck disable=SC2016  # literal production source patterns
  grep -q '_SERVICES_PERM=$(_firewalld_view_field services <<< "$_ZONE_VIEW_PERM")' "$SCRIPT"
  grep -q 'post-reload adds allowed server service definitions' "$SCRIPT"
  grep -q 'post-reload adds allowed explicit ports' "$SCRIPT"
}

@test "runtime targets use firewalld runtime views instead of permanent-only get-target" {
  # shellcheck disable=SC2016  # literal production source pattern
  run grep -qF '_TARGET_RUN=$(firewall-cmd --zone="$ZONE" --get-target' "$SCRIPT"
  [[ "$status" -ne 0 ]]
  # shellcheck disable=SC2016  # literal production source patterns
  grep -q '_TARGET_RUN=$(_firewalld_view_field target <<< "$_ZONE_VIEW_RUN")' "$SCRIPT"
  # shellcheck disable=SC2016  # literal production source patterns
  grep -q '_firewalld_runtime_policy_target "$policy"' "$SCRIPT"
}

@test "batched policy snapshot eliminates one firewalld client per target" {
  _FIREWALLD_AUDIT_POLICY_CACHE_READY=true
  _FW_AUDIT_POLICY_VIEWS=$'block-lan-out (active)\n  target: DROP\n  ingress-zones: HOST\n  egress-zones: ANY'
  calls="$BATS_TEST_TMPDIR/firewall-policy.calls"
  firewall-cmd() {
    printf '%s\n' "$*" >> "$calls"
    return 1
  }
  [[ "$(_firewalld_runtime_policy_target block-lan-out)" == "DROP" ]]
  [[ ! -e "$calls" ]]
  grep -q -- 'firewall-cmd --list-all-policies' "$SCRIPT"
}

@test "client and discovery service aliases do not duplicate server exposure" {
  run _firewalld_risky_services 'dhcpv6-client mdns samba-client ssh cockpit'
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'ssh\ncockpit' ]]
}

@test "stale permanent bindings do not become current zone exposure" {
  _FIREWALL_SYS_CLASS_NET_ROOT="$BATS_TEST_TMPDIR/net"
  mkdir -p "$_FIREWALL_SYS_CLASS_NET_ROOT/eth-present"
  run _firewalld_effective_ifaces \
    'stale-bridge eth-present runtime-tap' \
    'runtime-tap'
  [[ "$status" -eq 0 ]]
  [[ "$output" == $'eth-present\nruntime-tap' ]]
  [[ "$output" != *'stale-bridge'* ]]
}

@test "firewalld default target is recognized as default-deny" {
  _firewalld_target_is_default_deny default
  _firewalld_target_is_default_deny DEFAULT
}

@test "explicit firewalld drop and reject targets are default-deny" {
  _firewalld_target_is_default_deny DROP
  _firewalld_target_is_default_deny REJECT
  _firewalld_target_is_default_deny '%%REJECT%%'
}

@test "runtime XML reject spelling and permanent CLI spelling compare equally" {
  [[ "$(_firewalld_normalize_target '%%REJECT%%')" == "REJECT" ]]
  [[ "$(_firewalld_normalize_target 'REJECT')" == "REJECT" ]]
}

@test "firewalld ACCEPT target is not default-deny" {
  run _firewalld_target_is_default_deny ACCEPT
  [[ "$status" -ne 0 ]]
}

@test "disabled firewall logging is a visible privacy trade-off, not a warning" {
  grep -q '_emit_info "Firewall logging: denied packets not logged' "$SCRIPT"
  grep -q '_emit_info "UFW logging disabled' "$SCRIPT"
  run grep -E '_emit_warn "(Firewall logging: denied packets NOT logged|UFW logging disabled)' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "UFW activity parser never mistakes inactive for active" {
  _ufw_status_is_active $'Status: active\nLogging: on (low)'
  run _ufw_status_is_active $'Status: inactive\n'
  [[ "$status" -ne 0 ]]
  run _ufw_status_is_active 'Status: active-ish'
  [[ "$status" -ne 0 ]]
}

@test "all UFW consumers share the exact effective status helper" {
  require_cmd() { [[ "$1" == "ufw" ]]; }
  ufw() { printf '%s\n' 'Status: inactive'; }
  run _ufw_is_active
  [[ "$status" -ne 0 ]]

  ufw() { printf '%s\n' 'Status: active'; }
  _ufw_is_active

  run grep -nE 'ufw status.*grep.*active|is-active ufw' "$SCRIPT"
  [[ "$status" -ne 0 ]]
}

@test "empty iptables ACCEPT policy is absence of filtering not an allowance" {
  [[ "$(_iptables_listener_ingress_state_from_rules '-P INPUT ACCEPT')" == "no_firewall" ]]
  [[ "$(_iptables_listener_ingress_state_from_rules '-P INPUT DROP')" == "blocked" ]]
}

@test "iptables chains with rules remain unassessed without packet evaluation" {
  rules=$'-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j DROP'
  [[ "$(_iptables_listener_ingress_state_from_rules "$rules")" == "unknown" ]]
  rules=$'-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT'
  [[ "$(_iptables_listener_ingress_state_from_rules "$rules")" == "unknown" ]]
}

@test "listener port specifications match exact ports and ranges" {
  _firewall_port_specs_match '22/tcp 8000-8100/tcp 5353/udp' 22 tcp
  _firewall_port_specs_match '22/tcp 8000-8100/tcp 5353/udp' 8050 tcp
  _firewall_port_specs_match '22/tcp 8000-8100/tcp 5353/udp' 5353 udp
  run _firewall_port_specs_match '22/tcp 8000-8100/tcp 5353/udp' 222 tcp
  [[ "$status" -ne 0 ]]
  run _firewall_port_specs_match '22/tcp 8000-8100/tcp 5353/udp' 5353 tcp
  [[ "$status" -ne 0 ]]
}

@test "firewalld service ports distinguish permitted and blocked listeners" {
  firewall-cmd() {
    case "$*" in
      '--zone=public --list-all') printf 'public\n  target: default\n' ;;
      '--zone=public --list-ports'|'--zone=public --list-protocols'|\
      '--zone=public --list-rich-rules'|'--zone=public --list-forward-ports') ;;
      '--zone=public --list-services') printf '%s\n' 'ssh mdns' ;;
      '--info-service=ssh') printf 'ssh\n  ports: 22/tcp\n  protocols:\n  includes:\n' ;;
      '--info-service=mdns') printf 'mdns\n  ports: 5353/udp\n  protocols:\n  includes:\n' ;;
      *) return 1 ;;
    esac
  }
  [[ "$(_firewalld_zone_port_state public 22 tcp)" == "allowed" ]]
  [[ "$(_firewalld_zone_port_state public 5353 udp)" == "allowed" ]]
  [[ "$(_firewalld_zone_port_state public 5355 tcp)" == "blocked" ]]
  [[ "$(_firewalld_zone_port_state public 27500 tcp)" == "blocked" ]]
}

@test "listener snapshot eliminates repeated firewalld CLI reads per port" {
  declare -gA _FW_ZONE_VIEW_OK=([public]=1)
  declare -gA _FW_ZONE_TARGET_CACHE=([public]=default)
  declare -gA _FW_ZONE_PORTS_CACHE=([public]='22/tcp')
  declare -gA _FW_ZONE_PROTOCOLS_CACHE=([public]='')
  declare -gA _FW_ZONE_SERVICES_CACHE=([public]='')
  declare -gA _FW_ZONE_RICH_CACHE=([public]='')
  declare -gA _FW_ZONE_FORWARD_CACHE=([public]='')
  declare -gA _FW_SERVICE_INFO_OK=()
  declare -gA _FW_SERVICE_INFO_CACHE=()
  _FIREWALLD_LISTENER_CACHE_READY=true
  calls="$BATS_TEST_TMPDIR/firewall-cmd.calls"
  firewall-cmd() {
    printf '%s\n' "$*" >> "$calls"
    return 1
  }

  [[ "$(_firewalld_zone_port_state public 22 tcp)" == "allowed" ]]
  [[ "$(_firewalld_zone_port_state public 443 tcp)" == "blocked" ]]
  [[ ! -e "$calls" ]]
  listener_body=$(awk '/^_listener_ingress_state\(\) \{/,/^}/ {print}' "$SCRIPT")
  grep -q '^[[:space:]]*_firewalld_prepare_listener_cache$' <<< "$listener_body"
}

@test "firewalld drop-chain jumps are not VPN kill-switch verdicts" {
  rules=$'table inet firewalld {\n chain filter_OUTPUT_POLICIES {\n  type filter hook output priority filter + 10; policy accept;\n  oifname "enp0s4" jump filter_OUT_drop\n }\n}'
  run _nft_table_has_direct_output_drop enp0s4 <<< "$rules"
  [[ "$status" -ne 0 ]]
}

@test "only a direct physical-interface drop in an output hook is candidate evidence" {
  output_rules=$'table inet protonvpn {\n chain output {\n  type filter hook output priority filter; policy accept;\n  oifname "enp0s4" counter drop\n }\n}'
  forward_rules=$'table inet filter {\n chain forward {\n  type filter hook forward priority filter; policy accept;\n  oifname "enp0s4" counter drop\n }\n}'
  _nft_table_has_direct_output_drop enp0s4 <<< "$output_rules"
  run _nft_table_has_direct_output_drop enp0s4 <<< "$forward_rules"
  [[ "$status" -ne 0 ]]
}

@test "disconnected-state kill-switch inference requires a VPN-specific table name" {
  _nft_table_name_is_vpn protonvpn
  _nft_table_name_is_vpn wg-quick-wg0
  _nft_table_name_is_vpn mullvad
  run _nft_table_name_is_vpn firewalld
  [[ "$status" -ne 0 ]]
  run _nft_table_name_is_vpn block-lan-out
  [[ "$status" -ne 0 ]]
}
